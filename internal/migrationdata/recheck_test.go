package migrationdata

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFreshRecheckPersistsRequestIdentityAndRejectsChangedDisk(t *testing.T) {
	ctx := context.Background()
	data := []byte("actual published bytes for cleanup proof")
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
	if _, e := r.Publish(ctx, s, func() error { return nil }, func(stage string) error { return root.Link(stage, "published.bin") }); e != nil {
		t.Fatal(e)
	}
	check := func(stage string) error {
		a, e := root.Stat(stage)
		if e != nil {
			return e
		}
		b, e := root.Stat("published.bin")
		if e != nil {
			return e
		}
		if !os.SameFile(a, b) {
			return ErrState
		}
		return nil
	}
	id := strings.Repeat("a", 32)
	cp, e := r.Recheck(ctx, s, id, func() error { return nil }, check)
	if e != nil || cp.RecheckID != id || cp.RecheckedAt < time.Now().Unix()-1 || cp.RecheckError != "" {
		t.Fatal(cp, e)
	}
	r, e = New(root, s.TargetID, s.Resource)
	if e != nil {
		t.Fatal(e)
	}
	cp, e = r.Status(ctx, s)
	if e != nil || cp.RecheckID != id {
		t.Fatal("request proof lost on restart", cp, e)
	}
	file, e := root.OpenFile("published.bin", os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = file.WriteAt([]byte("!"), 0)
	file.Close()
	if e != nil {
		t.Fatal(e)
	}
	failedID := strings.Repeat("b", 32)
	cp, e = r.Recheck(ctx, s, failedID, func() error { return nil }, check)
	if !errors.Is(e, ErrState) {
		t.Fatal("stale disk hash accepted", cp, e)
	}
	cp, e = r.Status(ctx, s)
	if e != nil || cp.RecheckID != failedID || cp.RecheckedAt != 0 || cp.RecheckError == "" || cp.State != "published" {
		t.Fatal("failure confused with old success/authority", cp, e)
	}
	name, _, _ := names(s)
	file, e = root.OpenFile(name, os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = file.WriteAt(data, 0)
	file.Close()
	if e != nil {
		t.Fatal(e)
	}
	if e = root.Remove("published.bin"); e != nil {
		t.Fatal(e)
	}
	if e = root.WriteFile("published.bin", data, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Recheck(ctx, s, strings.Repeat("c", 32), func() error { return nil }, check); !errors.Is(e, ErrState) {
		t.Fatal("different published inode accepted", e)
	}
}
