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

func TestMediaPreparationReservationRequiresRealFenceAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	db, tree, _ := sqliteFixture(t)
	tree.unsafePrototype = false
	metadata, err := mediacrypto.NewMetadata(123)
	if err != nil {
		t.Fatal(err)
	}
	history := HistoricalMediaIDScope{Manifest: strings.Repeat("e", 64), Empty: true, FinalDigest: strings.Repeat("d", 64)}
	if err = tree.ReserveMediaPreparation(ctx, metadata, "admin:synthetic", history); !errors.Is(err, ErrFenceRequired) {
		t.Fatalf("unfenced key reservation accepted: %v", err)
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
	if err = tree.ReserveMediaPreparation(ctx, metadata, "admin:synthetic", history); !errors.Is(err, ErrConflict) {
		t.Fatalf("preparation before history completion accepted: %v", err)
	}
	if err = tree.ApplyHistoricalMediaIDBatch(ctx, history.Manifest, 0, true, history.FinalDigest, nil, func([]string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = tree.ReserveMediaPreparation(ctx, metadata, "admin:synthetic", history); !errors.Is(err, ErrConflict) {
		t.Fatalf("final batch without completion proof accepted: %v", err)
	}
	if err = tree.CompleteHistoricalMediaIDs(ctx, history.Manifest, history.Batches, history.Empty, history.FinalDigest, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = tree.ReserveMediaPreparation(ctx, metadata, "admin:synthetic", history); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLite(ctx, db, tree.tree, tree.rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFence(ctx, reopened, root, dir); err != nil {
		t.Fatal(err)
	}
	if err = reopened.ReserveMediaPreparation(ctx, metadata, "admin:other", history); !errors.Is(err, ErrConflict) {
		t.Fatalf("file ID reused after restart: %v", err)
	}
	var raw int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, metadata.FileID).Scan(&raw); err != nil || raw != 0 {
		t.Fatalf("raw file ID persisted: %d %v", raw, err)
	}
	if _, err = reopened.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err = reopened.ReserveMediaPreparation(ctx, metadata, strings.Repeat("x", 513), history); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded binding accepted: %v", err)
	}
}
