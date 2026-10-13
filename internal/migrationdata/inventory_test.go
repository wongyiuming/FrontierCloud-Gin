package migrationdata

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"os"
	"testing"
)

func TestTerminalMigrationInventoryRequiresIdleBoundCompleteHistory(t *testing.T) {
	for _, outcome := range []string{"aborted", "published"} {
		t.Run(outcome, func(t *testing.T) {
			data := []byte("real opaque migration data")
			r, s, root := fixture(t, data)
			ctx := context.Background()
			if _, e := r.Begin(ctx, s); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Append(ctx, s, 0, data, sha(data)); e != nil {
				t.Fatal(e)
			}
			if outcome == "aborted" {
				if _, e := r.Abort(ctx, s, func() error { return nil }); e != nil {
					t.Fatal(e)
				}
			} else {
				if _, e := r.Verify(ctx, s, nil); e != nil {
					t.Fatal(e)
				}
				if e := root.MkdirAll("music/private", 0700); e != nil {
					t.Fatal(e)
				}
				if _, e := r.Publish(ctx, s, func() error { return nil }, func(stage string) error { return root.Link(stage, s.TargetPath) }); e != nil {
					t.Fatal(e)
				}
				if _, e := r.RetireAnchor(ctx, s, func() error { return nil }, func(stage string, exists bool) error {
					a, e := root.Lstat(stage)
					if e != nil {
						return e
					}
					b, e := root.Lstat(s.TargetPath)
					if e != nil {
						return e
					}
					if !os.SameFile(a, b) {
						return ErrState
					}
					return nil
				}); e != nil {
					t.Fatal(e)
				}
			}
			stage, journal, lock := names(s)
			entry := func(name string) resourceinventory.Entry {
				info, e := root.Lstat(name)
				if e != nil {
					t.Fatal(e)
				}
				return resourceinventory.Entry{Path: name, Kind: "regular", LogicalBytes: info.Size(), ModifiedNS: info.ModTime().UnixNano()}
			}
			calls := 0
			admit := func(actual Spec, state string) error {
				calls++
				if !bindingEqual(actual, s) || state != outcome {
					return ErrState
				}
				return nil
			}
			for _, name := range []string{journal, lock} {
				fact, handled := r.InventoryTerminal(ctx, entry(name), admit)
				if !handled || fact.Blocking || fact.Category != "retained_native_state" || fact.ObjectID != s.LogicalID {
					t.Fatal(fact, handled)
				}
			}
			if calls != 4 {
				t.Fatal("missing repeated binding validation", calls)
			}
			expectBlocked := func(admission func(Spec, string) error) {
				t.Helper()
				fact, handled := r.InventoryTerminal(ctx, entry(journal), admission)
				if !handled || !fact.Blocking || fact.Category != "migration_material" {
					t.Fatal("unsafe history accepted", fact, handled)
				}
			}
			calls = 0
			expectBlocked(func(Spec, string) error {
				calls++
				if calls == 2 {
					return errors.New("binding revoked during observation")
				}
				return nil
			})
			if calls != 2 {
				t.Fatal(calls)
			}
			f, e := root.OpenFile(lock, os.O_RDONLY, 0)
			if e != nil {
				t.Fatal(e)
			}
			release, e := filelease.Try(f, true)
			if e != nil {
				t.Fatal(e)
			}
			expectBlocked(admit)
			release()
			write := func(name string) {
				f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = f.Write([]byte("unknown bytes")); e != nil {
					t.Fatal(e)
				}
				f.Close()
			}
			for _, name := range []string{stage, journal + ".tmp"} {
				write(name)
				expectBlocked(admit)
				if e = root.Remove(name); e != nil {
					t.Fatal(e)
				}
			}
			original, e := root.ReadFile(journal)
			if e != nil {
				t.Fatal(e)
			}
			f, e = root.OpenFile(journal, os.O_WRONLY|os.O_APPEND, 0)
			if e != nil {
				t.Fatal(e)
			}
			f.Write([]byte("{}"))
			f.Close()
			expectBlocked(admit)
			f, e = root.OpenFile(journal, os.O_WRONLY|os.O_TRUNC, 0)
			if e != nil {
				t.Fatal(e)
			}
			f.Write(original)
			f.Close()
			if e = root.Remove(lock); e != nil {
				t.Fatal(e)
			}
			expectBlocked(admit)
			if _, e = root.Lstat(lock); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("read-only observation created lock", e)
			}
			if outcome == "published" {
				actual, e := root.ReadFile(s.TargetPath)
				if e != nil || string(actual) != string(data) {
					t.Fatal("business bytes changed", e)
				}
			}
		})
	}
}
