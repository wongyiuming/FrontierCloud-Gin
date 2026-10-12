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
