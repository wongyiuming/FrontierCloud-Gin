//go:build linux

package sealedtree

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestNewMediaReservationRequiresFenceAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	db, tree, _ := sqliteFixture(t)
	tree.unsafePrototype = false
	old, err := mediacrypto.NewMetadata(123)
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.ReserveNewMediaPreparation(ctx, old, "admin:test"); !errors.Is(err, ErrFenceRequired) {
		t.Fatalf("unfenced reservation: %v", err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = InitializeFence(ctx, tree, root, dir); err != nil {
		t.Fatal(err)
	}
	fresh, err := mediacrypto.NewMetadata(123)
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.ReserveNewMediaPreparation(ctx, fresh, "admin:test"); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLite(ctx, db, tree.tree, tree.rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFence(ctx, reopened, root, dir); err != nil {
		t.Fatal(err)
	}
	if err = reopened.ReserveNewMediaPreparation(ctx, fresh, "admin:other"); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused new ID: %v", err)
	}
	var raw int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, fresh.FileID).Scan(&raw); err != nil || raw != 0 {
		t.Fatalf("raw ID persisted: %d %v", raw, err)
	}
	if err = reopened.ReserveNewMediaPreparation(ctx, fresh, strings.Repeat("x", 513)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid binding: %v", err)
	}
}
