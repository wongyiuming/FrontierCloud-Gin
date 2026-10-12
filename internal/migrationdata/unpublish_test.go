package migrationdata

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"os"
	"testing"
)

func TestInterruptedPublicationCancellationPreservesForeignFilesAndResumes(t *testing.T) {
	for _, fault := range []string{"none", "foreign_inode", "corrupt", "lost_unlink", "lost_stage_unlink", "changed_retained_stage"} {
		t.Run(fault, func(t *testing.T) {
			data := []byte("original opaque bytes")
			r, s, root := fixture(t, data)
			ctx := context.Background()
			if _, e := r.Begin(ctx, s); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Append(ctx, s, 0, data, sha(data)); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Verify(ctx, s, nil); e != nil {
				t.Fatal(e)
			}
			if e := root.MkdirAll("music/private", 0700); e != nil {
				t.Fatal(e)
			}
			crash := errors.New("lost publication SQL acknowledgement")
			if _, e := r.Publish(ctx, s, func() error { return nil }, func(stage string) error {
				if e := root.Link(stage, s.TargetPath); e != nil {
					return e
				}
				return crash
			}); !errors.Is(e, crash) {
				t.Fatal(e)
			}
			calls := 0
			unpublish := func(stage string) error {
				calls++
				target, e := root.Lstat(s.TargetPath)
				if errors.Is(e, os.ErrNotExist) {
					return nil
				}
				if e != nil {
					return e
				}
				anchor, e := root.Lstat(stage)
				if e != nil {
					return e
				}
				if !target.Mode().IsRegular() || !anchor.Mode().IsRegular() || !os.SameFile(anchor, target) {
					return ErrState
				}
				if e = root.Remove(s.TargetPath); e != nil {
					return e
				}
				if e = fsutil.SyncDirectory(root, "music/private"); e != nil {
					return e
				}
				if fault == "lost_unlink" && calls == 1 {
					return crash
				}
				return nil
			}
			if fault == "foreign_inode" {
				if e := root.Rename(s.TargetPath, "music/private/original"); e != nil {
					t.Fatal(e)
				}
				if e := root.WriteFile(s.TargetPath, data, 0600); e != nil {
					t.Fatal(e)
				}
				if _, e := r.CancelPublication(ctx, s, func() error { return nil }, unpublish); !errors.Is(e, ErrState) {
					t.Fatal("foreign inode removed", e)
				}
				if got, e := root.ReadFile(s.TargetPath); e != nil || string(got) != string(data) {
					t.Fatal(got, e)
				}
				if e := root.Remove(s.TargetPath); e != nil {
					t.Fatal(e)
				}
				if e := root.Rename("music/private/original", s.TargetPath); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "corrupt" {
				if e := root.WriteFile(s.TargetPath, []byte("wrong bytes of length"), 0600); e != nil {
					t.Fatal(e)
				}
				if _, e := r.CancelPublication(ctx, s, func() error { return nil }, unpublish); !errors.Is(e, ErrState) {
					t.Fatal("unverified bytes cancelled", e)
				}
				if calls != 0 {
					t.Fatal("unlink called before hash", calls)
				}
				if e := root.WriteFile(s.TargetPath, data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "lost_unlink" {
				if _, e := r.CancelPublication(ctx, s, func() error { return nil }, unpublish); !errors.Is(e, crash) {
					t.Fatal(e)
				}
				if _, e := r.Abort(ctx, s, func() error { return nil }); !errors.Is(e, ErrState) {
					t.Fatal("ordinary staging abort ignored pending publication", e)
				}
				r, _ = New(root, s.TargetID, s.Resource)
			}
			if fault == "lost_stage_unlink" {
				cp, e := r.load(s)
				if e != nil {
					t.Fatal(e)
				}
				cp.State = "aborting"
				cp.PublicationCancelling = true
				cp.PublicationUnlinked = true
				if e = root.Remove(s.TargetPath); e != nil {
					t.Fatal(e)
				}
				if e = r.save(cp); e != nil {
					t.Fatal(e)
				}
				stage, _, _ := names(s)
				if e = root.Remove(stage); e != nil {
					t.Fatal(e)
				}
				r, _ = New(root, s.TargetID, s.Resource)
			}
			if fault == "changed_retained_stage" {
				cp, e := r.load(s)
				if e != nil {
					t.Fatal(e)
				}
				cp.State = "aborting"
				cp.PublicationCancelling = true
				cp.PublicationUnlinked = true
				if e = root.Remove(s.TargetPath); e != nil {
					t.Fatal(e)
				}
				if e = r.save(cp); e != nil {
					t.Fatal(e)
				}
				stage, _, _ := names(s)
				if e = root.WriteFile(stage, []byte("unproved replacement"), 0600); e != nil {
					t.Fatal(e)
				}
				if _, e = r.CancelPublication(ctx, s, func() error { return nil }, unpublish); !errors.Is(e, ErrState) {
					t.Fatal("retained unknown staging removed", e)
				}
				if _, e = root.Lstat(stage); e != nil {
					t.Fatal("unknown bytes not preserved", e)
				}
				if e = root.WriteFile(stage, data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			for range 2 {
				cp, e := r.CancelPublication(ctx, s, func() error { return nil }, unpublish)
				if e != nil || cp.State != "aborted" || !cp.PublicationUnlinked {
					t.Fatal(cp, e)
				}
			}
			stage, _, _ := names(s)
			for _, name := range []string{stage, s.TargetPath} {
				if _, e := root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("retained file", name, e)
				}
			}
			if _, e := r.Begin(ctx, s); !errors.Is(e, ErrState) {
				t.Fatal("cancelled publication reopened", e)
			}
		})
	}
}
