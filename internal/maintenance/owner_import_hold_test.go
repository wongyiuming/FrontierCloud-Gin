//go:build linux

package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnerImportHoldPreventsResumeAndRestart(t *testing.T) {
	ctx := context.Background()
	gate, dir := fixture(t)
	db := filepath.Join(dir, "data.db")
	if err := os.WriteFile(db, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	authorize := func(held context.Context, check func() error) (func(), error) { return func() {}, check() }
	work := func(held context.Context, check func() error) error { return check() }
	if err := gate.InspectSQLiteOwnerImport(ctx, dir, db, authorize, work); !errors.Is(err, ErrState) {
		t.Fatal("armed outside maintenance", err)
	}
	if err := gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	released := false
	denied := errors.New("denied")
	if err := gate.InspectSQLiteOwnerImport(ctx, dir, db, func(context.Context, func() error) (func(), error) { return func() { released = true }, denied }, work); !errors.Is(err, denied) || !released {
		t.Fatal("failed authorization or lease release", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, OwnerImportHold)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed authorization armed a hold", err)
	}
	if err := gate.InspectSQLiteOwnerImport(ctx, dir, db, authorize, work); err != nil {
		t.Fatal(err)
	}
	if err := gate.InspectSQLiteOwnerImport(ctx, dir, db, authorize, work); err != nil {
		t.Fatal("hold retry", err)
	}
	if err := gate.Resume(ctx, func(context.Context) error { return nil }); !errors.Is(err, ErrState) {
		t.Fatal("resume bypassed Owner hold", err)
	}
	// A separate Gate instance models a restarted native process.
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = os.Remove(filepath.Join(dir, Marker)); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Runtime(ctx); !errors.Is(err, ErrState) {
		t.Fatal("restart bypassed Owner hold", err)
	}
}
