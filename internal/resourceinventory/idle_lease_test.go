package resourceinventory

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"os"
	"testing"
)

func TestIdleNativeLeaseObservationNeverCreatesOrBypassesHeldLease(t *testing.T) {
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	file, e := root.Create(".native.lock")
	if e != nil {
		t.Fatal(e)
	}
	file.Close()
	info, e := root.Lstat(".native.lock")
	if e != nil {
		t.Fatal(e)
	}
	entry := Entry{Path: ".native.lock", Kind: "regular", ModifiedNS: info.ModTime().UnixNano()}
	if e = IdleLeaseAt(context.Background(), root, entry); e != nil {
		t.Fatal(e)
	}
	file, e = root.Open(".native.lock")
	if e != nil {
		t.Fatal(e)
	}
	release, e := filelease.Try(file, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = IdleLeaseAt(context.Background(), root, entry); !errors.Is(e, filelease.ErrBusy) {
		t.Fatal("live reader admitted", e)
	}
	release()
	entry.Path = "missing.lock"
	if e = IdleLeaseAt(context.Background(), root, entry); e == nil {
		t.Fatal("missing created")
	}
	if _, e = root.Lstat(entry.Path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("probe wrote", e)
	}
	entry.Path = "../outside"
	if e = IdleLeaseAt(context.Background(), root, entry); !errors.Is(e, ErrChanged) {
		t.Fatal("traversal", e)
	}
	entry.Path = ".native.lock"
	entry.ModifiedNS++
	if e = IdleLeaseAt(context.Background(), root, entry); !errors.Is(e, ErrChanged) {
		t.Fatal("stale page", e)
	}
}
