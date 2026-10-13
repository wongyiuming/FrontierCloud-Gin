package sitecontrol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

func TestBusinessMaintenancePreservesOfflineFence(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	value, err := s.Status(ctx)
	if err != nil || value["maintenance"] != false || value["source"] != "open" || value["release"] != nil {
		t.Fatal(value, err)
	}
	// A recognized legacy override may not bypass a manual or native fence.
	if err = os.WriteFile(filepath.Join(root, ForceOpen), []byte("release-failure-override\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, Manual), []byte("manual\n"), 0600); err != nil {
		t.Fatal(err)
	}
	value, err = s.Status(ctx)
	if err != nil || value["maintenance"] != true || value["force_open"] != false || value["source"] != "manual" {
		t.Fatal(value, err)
	}
	value, err = s.Set(ctx, false)
	if err != nil || value["maintenance"] != false || value["force_open"] != false || value["release"] != nil {
		t.Fatal(value, err)
	}
	for _, change := range []bool{true, false, true, false} {
		value, err = s.Set(ctx, change)
		if err != nil || value["maintenance"] != change {
			t.Fatal(value, err)
		}
	}
	gate, err := maintenance.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	value, err = s.Status(ctx)
	if err != nil || value["maintenance"] != true || value["source"] != "native-offline" {
		t.Fatal(value, err)
	}
	if _, err = s.Set(ctx, false); err == nil {
		t.Fatal("Admin reopened native migration fence")
	}
}

func TestSiteUnknownFlagsAreNotReopeningAuthority(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	v, err := s.Set(ctx, true)
	if err != nil || v["maintenance"] != true {
		t.Fatal(v, err)
	}
	if err = os.WriteFile(filepath.Join(root, ForceOpen), []byte("unknown\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Set(ctx, true); !errors.Is(err, ErrState) {
		t.Fatal("unknown flag silently erased", err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, ForceOpen))
	if string(raw) != "unknown\n" {
		t.Fatal("changed unknown flag")
	}
	os.Remove(filepath.Join(root, ForceOpen))
	foreign := filepath.Join(t.TempDir(), "foreign")
	os.WriteFile(foreign, []byte("untouched"), 0600)
	if err = os.Symlink(foreign, filepath.Join(root, ForceOpen)); err != nil {
		t.Skip("symlink unavailable")
	}
	if _, err = s.Set(ctx, false); !errors.Is(err, ErrState) {
		t.Fatal("followed flag symlink", err)
	}
	raw, _ = os.ReadFile(foreign)
	if string(raw) != "untouched" {
		t.Fatal("foreign bytes changed")
	}
}
func TestSiteSharedOperatorLeaseHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	held, err := Lease(context.Background(), s.root, true)
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err = s.Status(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("query bypassed operator lease", err)
	}
}
