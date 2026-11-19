package migrationdata

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestRetainedGuardedReceiverRefusesMutationAndPreservesState(t *testing.T) {
	_, spec, root := fixture(t, []byte("private"))
	blocked := false
	r, err := NewGuarded(root, spec.TargetID, spec.Resource, func(context.Context) error {
		if blocked {
			return store.ErrNodeState
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = r.Begin(ctx, spec); err != nil {
		t.Fatal(err)
	}
	stage, journal, _ := names(spec)
	read := func(name string) []byte {
		t.Helper()
		f, e := root.Open(name)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		b, e := io.ReadAll(f)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	beforeStage, beforeJournal := string(read(stage)), string(read(journal))
	blocked = true
	admit := func() error { return nil }
	checks := []func() error{
		func() error { _, e := r.Begin(ctx, spec); return e },
		func() error { _, e := r.Append(ctx, spec, 0, []byte("private"), sha([]byte("private"))); return e },
		func() error { _, e := r.Verify(ctx, spec, admit); return e },
		func() error {
			_, e := r.Publish(ctx, spec, admit, func(string) error { t.Error("commit called"); return nil })
			return e
		},
		func() error { _, e := r.Abort(ctx, spec, admit); return e },
		func() error {
			_, e := r.RetireAnchor(ctx, spec, admit, func(string, bool) error { t.Error("validation called"); return nil })
			return e
		},
		func() error {
			_, e := r.CancelPublication(ctx, spec, admit, func(string) error { t.Error("unpublish called"); return nil })
			return e
		},
	}
	for i, check := range checks {
		if err := check(); !errors.Is(err, store.ErrNodeState) {
			t.Errorf("operation %d: %v", i, err)
		}
	}
	if string(read(stage)) != beforeStage || string(read(journal)) != beforeJournal {
		t.Fatal("private state changed")
	}
}
