//go:build linux

package sealedtree

import (
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

var migrationStageFixture = ".migration-data-" + strings.Repeat("1", 32) + "-" + strings.Repeat("2", 64) + ".part"
var migrationBlobFixture = strings.Repeat("b", 64)

const migrationBlobContent = "opaque migration fixture"

func newMigrationBlobStage(t *testing.T) (*BlobPublisher, *os.File, os.FileInfo) {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err = root.WriteFile(migrationStageFixture, []byte(migrationBlobContent), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := root.Open(migrationStageFixture)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	proof, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	return p, file, proof
}

func TestInstallVerifiedMigrationBlobLinksOnceAndReplays(t *testing.T) {
	p, verified, proof := newMigrationBlobStage(t)
	dest, err := BlobPath(migrationBlobFixture)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for attempt := 0; attempt < 2; attempt++ {
		if err = p.InstallVerifiedMigrationBlob(ctx, migrationStageFixture, migrationBlobFixture, proof.Size(), verified, proof); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		linked, err := p.root.Lstat(dest)
		if err != nil || !os.SameFile(linked, proof) || !migrationBlobLinks(linked, 2) || linked.Mode() != 0600 {
			t.Fatalf("attempt %d installed another inode or link: %v", attempt, err)
		}
	}
	data, err := p.root.ReadFile(dest)
	if err != nil || string(data) != migrationBlobContent {
		t.Fatalf("linked bytes changed: %v", err)
	}
}

func TestInstallVerifiedMigrationBlobRejectsForeignExistingBlob(t *testing.T) {
	p, verified, proof := newMigrationBlobStage(t)
	dest, err := BlobPath(migrationBlobFixture)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.root.MkdirAll(path.Dir(dest), 0700); err != nil {
		t.Fatal(err)
	}
	if err = p.root.WriteFile(dest, []byte(migrationBlobContent), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := p.root.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.InstallVerifiedMigrationBlob(context.Background(), migrationStageFixture, migrationBlobFixture, proof.Size(), verified, proof); !errors.Is(err, ErrBlobIncomplete) {
		t.Fatalf("foreign inode with identical bytes accepted: %v", err)
	}
	after, err := p.root.Lstat(dest)
	if err != nil || !os.SameFile(before, after) || os.SameFile(proof, after) || !migrationBlobLinks(after, 1) {
		t.Fatalf("existing destination changed: %v", err)
	}
}

func TestInstallVerifiedMigrationBlobRejectsStageAndPathChanges(t *testing.T) {
	for _, attack := range []string{"path", "replace", "modify", "stage-symlink", "parent-symlink", "extra-link", "cancelled"} {
		t.Run(attack, func(t *testing.T) {
			p, verified, proof := newMigrationBlobStage(t)
			stage, ctx := migrationStageFixture, context.Background()
			dest, err := BlobPath(migrationBlobFixture)
			if err != nil {
				t.Fatal(err)
			}
			switch attack {
			case "path":
				stage = "other/../" + stage
			case "replace", "stage-symlink":
				if err = p.root.Rename(stage, "other.part"); err != nil {
					t.Fatal(err)
				}
				if attack == "replace" {
					err = p.root.WriteFile(stage, []byte(migrationBlobContent), 0600)
				} else {
					err = p.root.Symlink("other.part", stage)
				}
			case "modify":
				changed := proof.ModTime().Add(-time.Minute)
				err = p.root.Chtimes(stage, changed, changed)
			case "parent-symlink":
				if err = p.root.Mkdir("alternate", 0700); err != nil {
					t.Fatal(err)
				}
				err = p.root.Symlink("alternate", "objects")
			case "extra-link":
				err = p.root.Link(stage, "other.part")
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = p.InstallVerifiedMigrationBlob(ctx, stage, migrationBlobFixture, proof.Size(), verified, proof); err == nil {
				t.Fatal("invalid stage or path accepted")
			}
			if _, err = p.root.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected destination after refusal: %v", err)
			}
			if attack == "parent-symlink" {
				if _, err = p.root.Lstat("alternate/bb"); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("created a directory under a symlink: %v", err)
				}
			}
		})
	}
}
