//go:build linux

package media

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoveryOpaqueCensusExactOwnerSetAndExclusion(t *testing.T) {
	ctx := context.Background()
	root, db, svc := masterFixture(t)
	owner := db.Nodes().(recoveryOwnerFixtureRepo)
	recoveryProofOwnerFence(t, root, svc, owner)
	lease, err := owner.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	expected, file := recoveryProofPlacement(t, root, svc.identity.ID)
	ids := []string{expected.BlobID}
	var got RecoveryOpaqueCensus
	run := func(ids []string) error {
		return svc.VisitRecoveryOpaqueCensus(ctx, lease, svc.identity.ID, ids, func(proof RecoveryOpaqueCensus) error {
			got = proof
			wait, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
			defer cancel()
			unlock, e := svc.acquire(wait, true)
			if e == nil {
				unlock()
				return errors.New("census allowed writer")
			}
			if !errors.Is(e, context.DeadlineExceeded) {
				return e
			}
			return nil
		})
	}
	if err = run(ids); err != nil || got.Count != 1 || got.Version != 1 || len(got.SetCommitment) != 64 {
		t.Fatal("valid census", err, got)
	}
	if run(nil) == nil || run([]string{ids[0], ids[0]}) == nil || run([]string{strings.Repeat("f", 64)}) == nil {
		t.Fatal("missing or duplicate accepted")
	}
	other := strings.Repeat("b", 64)
	otherPath := filepath.Join(root, "objects", other[:2], other[2:4], other+".blob")
	if err = os.MkdirAll(filepath.Dir(otherPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(otherPath, []byte("extra"), 0600); err != nil {
		t.Fatal(err)
	}
	if run(ids) == nil {
		t.Fatal("unexpected blob accepted")
	}
	if err = os.Remove(otherPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(file, otherPath); err != nil {
		t.Fatal(err)
	}
	if run([]string{ids[0], other}) == nil {
		t.Fatal("hardlink accepted")
	}
	if err = os.Remove(otherPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(file, otherPath); err != nil {
		t.Fatal(err)
	}
	if run([]string{ids[0], other}) == nil {
		t.Fatal("symlink accepted")
	}
	if err = os.Remove(otherPath); err != nil {
		t.Fatal(err)
	}
	if err = svc.VisitRecoveryOpaqueCensus(ctx, lease, svc.identity.ID, ids, func(RecoveryOpaqueCensus) error { lease.Release(); return nil }); err == nil {
		t.Fatal("lost authority accepted")
	}
}
