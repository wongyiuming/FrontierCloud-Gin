package migrationdata

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestPublicationRetryRetainsAnchorAndRefusesAbort(t *testing.T) {
	ctx := context.Background()
	data := []byte("actual durable publication bytes")
	r, s, root := fixture(t, data)
	if _, e := r.Begin(ctx, s); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Append(ctx, s, 0, data, sha(data)); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Verify(ctx, s, nil); e != nil {
		t.Fatal(e)
	}
	injected := errors.New("database commit unavailable")
	fail := true
	calls := 0
	commit := func(stage string) error {
		calls++
		a, e := root.Stat(stage)
		if e != nil {
			return e
		}
		b, e := root.Stat("published.bin")
		if errors.Is(e, os.ErrNotExist) {
			if e = root.Link(stage, "published.bin"); e != nil {
				return e
			}
		} else if e != nil {
			return e
		} else if !os.SameFile(a, b) {
			return ErrState
		}
		if fail {
			return injected
		}
		return nil
	}
	c, e := r.Publish(ctx, s, func() error { return nil }, commit)
	if !errors.Is(e, injected) || c.State != "publishing" {
		t.Fatal(c, e)
	}
	if _, e = r.Abort(ctx, s, func() error { return nil }); !errors.Is(e, ErrState) {
		t.Fatal("aborted a publication intent", e)
	}
	r, e = New(root, s.TargetID, s.Resource)
	if e != nil {
		t.Fatal(e)
	}
	fail = false
	for range 2 {
		c, e = r.Publish(ctx, s, func() error { return nil }, commit)
		if e != nil || c.State != "published" {
			t.Fatal(c, e)
		}
	}
	if calls != 3 {
		t.Fatal(calls)
	}
	got, e := root.ReadFile("published.bin")
	if e != nil || string(got) != string(data) {
		t.Fatal(string(got), e)
	}
	name, _, _ := names(s)
	f, e := root.OpenFile(name, os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteAt([]byte("!"), 0)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Publish(ctx, s, func() error { return nil }, commit); !errors.Is(e, ErrState) {
		t.Fatal("trusted stale disk verification", e)
	}
	if calls != 3 {
		t.Fatal("corruption reached commit")
	}
}
