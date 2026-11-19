//go:build linux

package sealedtree

import (
	"context"
	"strings"
	"testing"
)

// This exercises the transaction seam only. It does not prove publication,
// authorize a source, or make the helper a product entry point.
func TestPendingFinalizationUsesExistingImmediateTransaction(t *testing.T) {
	ctx := context.Background()
	db, tree, _ := sqliteFixture(t)
	entry := Entry{ParentID: tree.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "synthetic"}
	placement := fixturePlacement(t, entry.ObjectID)
	op, err := tree.PrepareFileWithFacts(ctx, entry, placement, Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TABLE pending_atomic_fixture(value INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, commit := range []bool{false, true} {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		before, savedEntry, savedPlacement, err := tree.pending(ctx, conn, op)
		if err == nil {
			err = tree.finalizePendingTx(ctx, conn, op, before, savedEntry, savedPlacement)
		}
		if err == nil {
			_, err = conn.ExecContext(ctx, `INSERT INTO pending_atomic_fixture(value) VALUES(1)`)
		}
		if err != nil {
			_, _ = conn.ExecContext(ctx, `ROLLBACK`)
			conn.Close()
			t.Fatal(err)
		}
		statement := `ROLLBACK`
		if commit {
			statement = `COMMIT`
		}
		_, err = conn.ExecContext(ctx, statement)
		conn.Close()
		if err != nil {
			t.Fatal(err)
		}
		var count int
		if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pending_atomic_fixture`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		_, _, lookupErr := tree.Get(ctx, entry.ObjectID)
		if !commit && (count != 0 || lookupErr == nil) || commit && (count != 1 || lookupErr != nil) {
			t.Fatalf("tree and auxiliary update diverged: commit=%v count=%d tree=%v", commit, count, lookupErr)
		}
	}
}
