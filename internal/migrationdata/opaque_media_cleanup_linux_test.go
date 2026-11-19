//go:build linux

package migrationdata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func opaqueCleanupFixture(t *testing.T, published bool) (*OpaqueMediaTransfer, *os.Root, string, string, []byte) {
	t.Helper()
	ctx := context.Background()
	meta, err := mediacrypto.NewMetadata(32)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0x7b}, int(meta.CiphertextSize))
	_, spec, root := fixture(t, data)
	binding := opaqueTestBinding(t, spec, data, &meta)
	guard := func(context.Context) error { return nil }
	transfer, err := OpenOpaqueMediaTransfer(root, binding.Target.OwnerID, binding, guard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transfer.Begin(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := transfer.Append(ctx, 0, data, sha(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := transfer.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	publisher, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	lost := errors.New("lost local publication result")
	progress, err := transfer.Publish(ctx, func() error { return nil }, func(stage string, file *os.File, proof os.FileInfo) error {
		if err := publisher.InstallVerifiedMigrationBlob(ctx, stage, binding.Target.Blob, binding.Target.Size, file, proof); err != nil {
			return err
		}
		if !published {
			return lost
		}
		return nil
	})
	if published && (err != nil || progress.State != "published") ||
		!published && (!errors.Is(err, lost) || progress.State != "publishing") {
		t.Fatal(progress, err)
	}
	transfer, err = OpenOpaqueMediaTransfer(root, binding.Target.OwnerID, binding, guard)
	if err != nil {
		t.Fatal(err)
	}
	stage, _, _ := names(transfer.spec)
	target, err := sealedtree.BlobPath(binding.Target.Blob)
	if err != nil {
		t.Fatal(err)
	}
	return transfer, root, stage, target, data
}

func TestOpaqueMediaRetiresAnchorAndRehashesSurvivingBlob(t *testing.T) {
	ctx := context.Background()
	admit := func() error { return nil }
	for _, crashAfterUnlink := range []bool{false, true} {
		name := "normal"
		if crashAfterUnlink {
			name = "after_durable_unlink_intent"
		}
		t.Run(name, func(t *testing.T) {
			transfer, root, stage, target, data := opaqueCleanupFixture(t, true)
			denied := errors.New("target commit proof revoked")
			calls := 0
			if _, err := transfer.RetireAnchor(ctx, func() error {
				calls++
				if calls == 2 {
					return denied
				}
				return nil
			}); !errors.Is(err, denied) {
				t.Fatalf("lost commit proof did not stop retirement: %v", err)
			}
			if _, err := root.Lstat(stage); err != nil {
				t.Fatal(err)
			}
			if crashAfterUnlink {
				c, err := transfer.receiver.load(transfer.spec)
				if err != nil {
					t.Fatal(err)
				}
				c.AnchorRetiring = true
				if err := transfer.receiver.save(c); err != nil {
					t.Fatal(err)
				}
				if err := root.Remove(stage); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if got, err := transfer.RetireAnchor(ctx, admit); err != nil || got.State != "published" || got.PrefixSHA != sha(data) {
					t.Fatal(got, err)
				}
			}
			if _, err := root.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("private link was not removed: %v", err)
			}
			got, err := root.ReadFile(target)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("published bytes changed: %v", err)
			}
			got[0]++
			if err := root.WriteFile(target, got, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := transfer.RetireAnchor(ctx, admit); !errors.Is(err, ErrState) {
				t.Fatalf("unverified surviving bytes passed replay: %v", err)
			}
		})
	}
}

func TestOpaqueMediaCleanupRejectsSubstitutedBlobAndSymlink(t *testing.T) {
	ctx := context.Background()
	admit := func() error { return nil }
	for _, published := range []bool{true, false} {
		for _, fault := range []string{"foreign_inode", "symlink_leaf", "symlink_parent"} {
			name := "cancel_" + fault
			if published {
				name = "retire_" + fault
			}
			t.Run(name, func(t *testing.T) {
				transfer, root, stage, target, data := opaqueCleanupFixture(t, published)
				switch fault {
				case "foreign_inode", "symlink_leaf":
					if err := root.Rename(target, "original.blob"); err != nil {
						t.Fatal(err)
					}
					var err error
					if fault == "foreign_inode" {
						err = root.WriteFile(target, data, 0600)
					} else {
						err = root.Symlink("../../../original.blob", target)
					}
					if err != nil {
						t.Fatal(err)
					}
				case "symlink_parent":
					parent := path.Dir(target)
					if err := root.Rename(parent, path.Join(path.Dir(parent), "old")); err != nil {
						t.Fatal(err)
					}
					if err := root.Symlink("old", parent); err != nil {
						t.Fatal(err)
					}
				}
				action := transfer.CancelPublication
				if published {
					action = transfer.RetireAnchor
				}
				if _, err := action(ctx, admit); err == nil {
					t.Fatal("unsafe cleanup succeeded")
				}
				for _, name := range []string{stage, target} {
					if _, err := root.Lstat(name); err != nil {
						t.Fatalf("cleanup removed %s: %v", name, err)
					}
				}
			})
		}
	}
}

func TestOpaqueMediaCancelsOnlyUncommittedInstallAndVerifiesReplay(t *testing.T) {
	ctx := context.Background()
	admit := func() error { return nil }
	published, _, _, _, _ := opaqueCleanupFixture(t, true)
	if _, err := published.CancelPublication(ctx, admit); !errors.Is(err, ErrState) {
		t.Fatalf("cancel accepted an already published transfer: %v", err)
	}
	for _, phase := range []string{"normal", "lost_target_unlink", "lost_stage_unlink"} {
		t.Run(phase, func(t *testing.T) {
			transfer, root, stage, target, data := opaqueCleanupFixture(t, false)
			denied := errors.New("target authority has already committed")
			if _, err := transfer.CancelPublication(ctx, func() error { return denied }); !errors.Is(err, denied) {
				t.Fatalf("cancel ignored committed target authority: %v", err)
			}
			for _, name := range []string{stage, target} {
				if _, err := root.Lstat(name); err != nil {
					t.Fatal(err)
				}
			}
			if phase != "normal" {
				c, err := transfer.receiver.load(transfer.spec)
				if err != nil {
					t.Fatal(err)
				}
				c.State, c.PublicationCancelling = "aborting", true
				c.PublicationUnlinked = phase == "lost_stage_unlink"
				if err := transfer.receiver.save(c); err != nil {
					t.Fatal(err)
				}
				if err := root.Remove(target); err != nil {
					t.Fatal(err)
				}
				if c.PublicationUnlinked {
					if err := root.Remove(stage); err != nil {
						t.Fatal(err)
					}
				}
			}
			for range 2 {
				if got, err := transfer.CancelPublication(ctx, admit); err != nil || got.State != "aborted" {
					t.Fatal(got, err)
				}
			}
			for _, name := range []string{stage, target} {
				if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unexpected retained link: %v", err)
				}
			}
			if err := root.WriteFile(target, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := transfer.CancelPublication(ctx, admit); !errors.Is(err, ErrState) {
				t.Fatalf("replay accepted a reappeared target: %v", err)
			}
			if got, err := root.ReadFile(target); err != nil || !bytes.Equal(got, data) {
				t.Fatalf("replay modified the unrelated target: %v", err)
			}
		})
	}
}
