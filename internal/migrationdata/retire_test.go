package migrationdata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPublicationAnchorRetirementPreservesBusinessBytesAndRecoversUnlink(t *testing.T) {
	for _, fault := range []string{"none", "missing_without_intent", "crash_before_unlink", "crash_after_unlink", "replacement", "corrupt"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			data := []byte("actual original published bytes")
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
			name, _, _ := names(s)
			if fault == "missing_without_intent" {
				if e := root.Remove(name); e != nil {
					t.Fatal(e)
				}
			}
			if strings.HasPrefix(fault, "crash_") {
				cp, e := r.load(s)
				if e != nil {
					t.Fatal(e)
				}
				cp.AnchorRetiring = true
				if e = r.save(cp); e != nil {
					t.Fatal(e)
				}
				if fault == "crash_after_unlink" {
					if e = root.Remove(name); e != nil {
						t.Fatal(e)
					}
				}
				r, e = New(root, s.TargetID, s.Resource)
				if e != nil {
					t.Fatal(e)
				}
			}
			if fault == "replacement" {
				if e := root.Remove(s.TargetPath); e != nil {
					t.Fatal(e)
				}
				f, e := root.OpenFile(s.TargetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.Write(data)
				f.Close()
				if e != nil {
					t.Fatal(e)
				}
			}
			if fault == "corrupt" {
				f, e := root.OpenFile(s.TargetPath, os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.WriteAt([]byte("!"), 0)
				f.Close()
				if e != nil {
					t.Fatal(e)
				}
			}
			validate := func(stage string, exists bool) error {
				b, e := root.Lstat(s.TargetPath)
				if e != nil {
					return e
				}
				if !b.Mode().IsRegular() {
					return ErrState
				}
				if exists {
					a, e := root.Lstat(stage)
					if e != nil {
						return e
					}
					if !os.SameFile(a, b) {
						return ErrState
					}
				}
				return nil
			}
			cp, e := r.RetireAnchor(ctx, s, func() error { return nil }, validate)
			if fault == "missing_without_intent" || fault == "replacement" || fault == "corrupt" {
				if !errors.Is(e, ErrState) {
					t.Fatal("unsafe retirement accepted", cp, e)
				}
				return
			}
			if e != nil || !cp.AnchorRetired || cp.AnchorRetiring || cp.State != "published" {
				t.Fatal(cp, e)
			}
			if _, e = root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("anchor remains", e)
			}
			f, e := root.Open(s.TargetPath)
			if e != nil {
				t.Fatal(e)
			}
			got := make([]byte, len(data))
			_, e = f.Read(got)
			f.Close()
			if e != nil || !bytes.Equal(got, data) {
				t.Fatal("business bytes changed", e)
			}
			if _, e = r.RetireAnchor(ctx, s, func() error { return nil }, validate); e != nil {
				t.Fatal("retirement replay", e)
			}
			if _, e = r.Recheck(ctx, s, strings.Repeat("9", 32), func() error { return nil }, func(stage string) error {
				if stage != s.TargetPath {
					return ErrState
				}
				return validate(stage, false)
			}); e != nil {
				t.Fatal("fresh recheck after retirement", e)
			}
		})
	}
}
