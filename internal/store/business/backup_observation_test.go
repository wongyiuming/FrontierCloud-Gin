package business_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPeerBackupObservationColdReadDoesNotRepairLease(t *testing.T) {
	db, _, rel := backupFixture(t)
	configured, ok := db.(interface{ ConfigureFileBackups(string) error })
	if !ok {
		t.Skip("native storage uses embedded SQLite")
	}
	directory := t.TempDir()
	if err := configured.ConfigureFileBackups(directory); err != nil {
		t.Fatal(err)
	}
	ctx, repo := context.Background(), db.Backups()
	payload := []byte("immutable recovery artifact")
	if err := repo.BeginBackup(ctx, rel.ID, 100, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendBackup(ctx, rel.ID, 100, 0, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CommitBackup(ctx, rel.ID, 100, backupChecksum(payload), store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	read := func(ctx context.Context) error {
		_, err := repo.ReadReadyBackup(ctx, rel.PeerID, 100, func(_ store.BackupManifest, reader io.Reader) error {
			_, err := io.Copy(io.Discard, reader)
			return err
		})
		return err
	}
	lock := filepath.Join(directory, ".lock")
	if err := read(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := read(ctx); err == nil {
		t.Fatal("missing coordination inode accepted")
	}
	if _, err := os.Lstat(lock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only inspection created a lock", err)
	}
	if err := os.WriteFile(lock, []byte("unexpected retained data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := read(ctx); err == nil {
		t.Fatal("nonempty coordination file accepted")
	}
	if got, err := os.ReadFile(lock); err != nil || string(got) != "unexpected retained data" {
		t.Fatal("inspection rewrote unknown bytes", err)
	}
	if err := os.WriteFile(lock, nil, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(lock, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	release, err := filelease.Acquire(ctx, f, true)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	timeout, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := read(timeout); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("inspection bypassed active mutation lease", err)
	}
	release()
	if err := read(ctx); err != nil {
		t.Fatal("released artifact cannot be observed", err)
	}
}

func TestPeerBackupObservationManifestIdentityStateAndBounds(t *testing.T) {
	db, raw, rel := backupFixture(t)
	ctx := context.Background()
	identity, e := db.Nodes().ReadIdentity(ctx)
	if e != nil {
		t.Fatal(e)
	}
	repo := db.Backups()
	lookup := repo.(store.BackupObservationRepository)
	if e = repo.BeginBackup(ctx, rel.ID, 100, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = lookup.ReadyBackupManifest(ctx, rel.ID, identity.ID, rel.PeerID, 100); e == nil {
		t.Fatal("receiving is ready")
	}
	payload := []byte("actual backup")
	if e = repo.AppendBackup(ctx, rel.ID, 100, 0, payload); e != nil {
		t.Fatal(e)
	}
	ready, e := repo.CommitBackup(ctx, rel.ID, 100, backupChecksum(payload), store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	observed, e := lookup.ReadyBackupManifest(ctx, rel.ID, identity.ID, rel.PeerID, 100)
	if e != nil || observed != ready {
		t.Fatal(observed, e)
	}
	for _, ids := range [][3]string{{strings.Repeat("f", 32), identity.ID, rel.PeerID}, {rel.ID, strings.Repeat("f", 32), rel.PeerID}, {rel.ID, identity.ID, strings.Repeat("f", 32)}} {
		if _, e = lookup.ReadyBackupManifest(ctx, ids[0], ids[1], ids[2], 100); e == nil {
			t.Fatal("foreign identity", ids)
		}
	}
	for _, generation := range []int64{-1, 0, 101} {
		if _, e = lookup.ReadyBackupManifest(ctx, rel.ID, identity.ID, rel.PeerID, generation); e == nil {
			t.Fatal("invalid/missing generation", generation)
		}
	}
	if db.Backend() == "sqlite" {
		if _, e = raw.Exec("UPDATE cluster_business_backups SET checksum=? WHERE master_id=? AND generation=100", strings.Repeat("x", 1<<20), rel.PeerID); e != nil {
			t.Fatal(e)
		}
		if _, e = lookup.ReadyBackupManifest(ctx, rel.ID, identity.ID, rel.PeerID, 100); e == nil {
			t.Fatal("oversized checksum")
		}
	} else {
		if _, e = raw.Exec("UPDATE cluster_business_backups SET checksum=? WHERE master_id=? AND generation=100", strings.Repeat("x", 1<<20), rel.PeerID); e == nil {
			t.Fatal("MySQL accepted oversized checksum")
		}
		if observed, e = lookup.ReadyBackupManifest(ctx, rel.ID, identity.ID, rel.PeerID, 100); e != nil || observed != ready {
			t.Fatal("rejected mutation changed manifest", observed, e)
		}
	}
	if _, e = raw.Exec("UPDATE cluster_business_backups SET checksum=?,chunk_count=0 WHERE master_id=? AND generation=100", ready.Checksum, rel.PeerID); e != nil {
		t.Fatal(e)
	}
	if _, e = lookup.ReadyBackupManifest(ctx, rel.ID, identity.ID, rel.PeerID, 100); e == nil {
		t.Fatal("zero chunks")
	}
}
