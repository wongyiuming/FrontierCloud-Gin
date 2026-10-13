package node

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSafeRetirementRequestGatePinsInodeAndJoinsIndependentRuntimes(t *testing.T) {
	dir := t.TempDir()
	a, b, other := &Service{}, &Service{}, &Service{}
	for _, v := range []struct {
		s    *Service
		root string
	}{{a, dir}, {b, dir}, {other, t.TempDir()}} {
		close, e := v.s.OpenRetirementRequestGate(v.root)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { close() })
	}
	ctx := context.Background()
	_, release, e := a.RetirementRequestLease(ctx, false)
	if e != nil {
		t.Fatal(e)
	}
	deadline, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	if _, unlock, e := b.RetirementRequestLease(deadline, true); e == nil {
		unlock()
		t.Fatal("shared handler did not fence another runtime")
	}
	cancel()
	_, unlock, e := other.RetirementRequestLease(ctx, true)
	if e != nil {
		t.Fatal("independent node was blocked", e)
	}
	unlock()
	release()
	_, unlock, e = b.RetirementRequestLease(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	unlock()
	// Never acquire a new lock inode after replacement: another process could
	// still be holding the old one, which would split the exclusion domain.
	path := filepath.Join(dir, RetirementAdmissionFile)
	if e = os.Rename(path, path+".old"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if _, release, e = a.RetirementRequestLease(ctx, false); e == nil {
		release()
		t.Fatal("replaced admission inode adopted")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if _, release, e = b.RetirementRequestLease(ctx, false); e == nil {
		release()
		t.Fatal("missing admission inode recreated")
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("read admission recreated lock", e)
	}
}
