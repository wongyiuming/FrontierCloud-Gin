package migrationdata

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestHistoricalPublishedAnchorRequiresCurrentExactDeletedObject(t *testing.T) {
	for _, fault := range []string{"none", "different_sha", "other_master", "corrupt", "crash_after_unlink"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			data := []byte("original historical managed copy")
			r, s, root := fixture(t, data)
			if e := root.MkdirAll("music/private", 0755); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Begin(ctx, s); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Append(ctx, s, 0, data, sha(data)); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Verify(ctx, s, nil); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Publish(ctx, s, func() error { return nil }, func(stage string) error { return root.Link(stage, s.TargetPath) }); e != nil {
				t.Fatal(e)
			}
			if e := root.Remove(s.TargetPath); e != nil {
				t.Fatal(e)
			}
			o := store.MigrationObject{ID: s.LogicalID, ObjectID: s.ObjectID, Resource: s.Resource, Path: s.TargetPath, Bytes: s.Bytes}
			master, hash := s.MasterID, s.SHA256
			name, _, _ := names(s)
			if fault == "different_sha" {
				hash = strings.Repeat("0", 64)
			}
			if fault == "other_master" {
				master = strings.Repeat("9", 32)
			}
			if fault == "corrupt" {
				f, e := root.OpenFile(name, os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.WriteAt([]byte("!"), 0)
				f.Close()
				if e != nil {
					t.Fatal(e)
				}
			}
			if fault == "crash_after_unlink" {
				c, e := r.load(s)
				if e != nil {
					t.Fatal(e)
				}
				c.AnchorRetiring = true
				if e = r.save(c); e != nil {
					t.Fatal(e)
				}
				if e = root.Remove(name); e != nil {
					t.Fatal(e)
				}
			}
			e := r.HistoricalAnchors(ctx, master, o, hash, func() error { return nil })
			if fault == "different_sha" || fault == "other_master" || fault == "corrupt" {
				if !errors.Is(e, ErrState) {
					t.Fatal("unbound historical anchor removed", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if finished, e := r.HistoricalAnchorsFinished(ctx, master, o, hash); e != nil || !finished {
				t.Fatal(finished, e)
			}
			if _, e = root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("historical physical copy remains", e)
			}
			if e = r.HistoricalAnchors(ctx, master, o, hash, func() error { return nil }); e != nil {
				t.Fatal("history replay", e)
			}
		})
	}
}

func TestDeletedPublishingAnchorRequiresActualBytesAndDeletionAdmission(t *testing.T) {
	for _, fault := range []string{"none", "denied", "corrupt", "missing", "verified"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			data := []byte("accounted publication retained private bytes")
			r, s, root := fixture(t, data)
			if e := root.MkdirAll("music/private", 0755); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Begin(ctx, s); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Append(ctx, s, 0, data, sha(data)); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Verify(ctx, s, nil); e != nil {
				t.Fatal(e)
			}
			if fault != "verified" {
				_, e := r.Publish(ctx, s, func() error { return nil }, func(stage string) error {
					if e := root.Link(stage, s.TargetPath); e != nil {
						return e
					}
					return errors.New("SQL committed; checkpoint acknowledgment lost")
				})
				if e == nil {
					t.Fatal("missing injected interruption")
				}
				if e = root.Remove(s.TargetPath); e != nil {
					t.Fatal(e)
				}
			}
			name, _, _ := names(s)
			if fault == "missing" {
				if e := root.Remove(name); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "corrupt" {
				f, e := root.OpenFile(name, os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.WriteAt([]byte("!"), 0)
				f.Close()
				if e != nil {
					t.Fatal(e)
				}
			}
			admission := func() error {
				if fault == "denied" {
					return ErrState
				}
				return nil
			}
			e := r.RetireDeletedAnchor(ctx, s, admission)
			if fault != "none" {
				if !errors.Is(e, ErrState) && !(fault == "missing" && errors.Is(e, os.ErrNotExist)) {
					t.Fatal("unproven publication consumed", e)
				}
				if fault != "missing" {
					if _, e = root.Lstat(name); e != nil {
						t.Fatal("private bytes removed", e)
					}
				}
				return
			}
			cp, e := r.Status(ctx, s)
			if e != nil || cp.State != "published" || !cp.AnchorRetired || cp.AnchorRetiring {
				t.Fatal(cp, e)
			}
			if _, e = root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("private bytes remain", e)
			}
			if e = r.RetireDeletedAnchor(ctx, s, admission); e != nil {
				t.Fatal("lost retirement receipt replay", e)
			}
		})
	}
}
