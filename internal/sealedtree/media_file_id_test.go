package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestMediaPreparationReservationsAndClaims(t *testing.T) {
	ctx := context.Background()
	db, tree, _ := sqliteFixture(t)
	meta, err := mediacrypto.NewMetadata(23)
	if err != nil {
		t.Fatal(err)
	}
	binding := "admin:synthetic-session"
	op, other := strings.Repeat("1", 64), strings.Repeat("2", 64)
	transact := func(commit bool, f func(treeQuery) error) error {
		t.Helper()
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if e = tree.lockIndexedWriter(ctx, tx); e != nil {
			return e
		}
		if e = tree.verifyRoot(ctx, tx); e != nil {
			return e
		}
		if e = f(tx); e != nil || !commit {
			return e
		}
		return tx.Commit()
	}
	reserve := func() error {
		return transact(true, func(tx treeQuery) error { return tree.reserveMediaPreparationTx(ctx, tx, meta, binding) })
	}
	claim := func(commit bool, m mediacrypto.Metadata, b, operation string) error {
		return transact(commit, func(tx treeQuery) error { return tree.claimMediaPreparationTx(ctx, tx, m, b, operation) })
	}
	if err = claim(true, meta, binding, op); !errors.Is(err, ErrConflict) {
		t.Fatalf("unreserved claim: %v", err)
	}
	if err = reserve(); err != nil {
		t.Fatal(err)
	}
	if err = reserve(); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate file ID: %v", err)
	}
	changed := meta
	changed.NoncePrefix = "AAAAAAAAAAA="
	if changed.NoncePrefix == meta.NoncePrefix {
		changed.NoncePrefix = "AQAAAAAAAAA="
	}
	if err = claim(true, changed, binding, op); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed descriptor: %v", err)
	}
	if err = claim(true, meta, "admin:other", op); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed admin: %v", err)
	}
	if err = claim(false, meta, binding, op); err != nil {
		t.Fatalf("rolled-back claim: %v", err)
	}
	if err = claim(true, meta, binding, other); err != nil {
		t.Fatalf("claim after rollback: %v", err)
	}
	if err = claim(true, meta, binding, other); err != nil {
		t.Fatalf("same-operation retry: %v", err)
	}
	if err = claim(true, meta, binding, op); !errors.Is(err, ErrConflict) {
		t.Fatalf("second operation: %v", err)
	}
	// Reopening preserves the permanent claim; ordinary check tolerates tags.
	reopened, err := OpenSQLite(ctx, db, tree.tree, tree.rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.Check(ctx); err != nil {
		t.Fatalf("reopen check: %v", err)
	}
	tree = reopened
	if err = claim(true, meta, binding, op); !errors.Is(err, ErrConflict) {
		t.Fatalf("claim after reopen: %v", err)
	}
	var leaks int
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id IN (?,?)`, meta.FileID, binding).Scan(&leaks); err != nil || leaks != 0 {
		t.Fatalf("raw identifier persisted: %d %v", leaks, err)
	}
	// A trusted historical backfill would insert the exact same domain tag for
	// recording or media IDs. Such a tombstone prevents future preparations.
	retired, err := mediacrypto.NewMetadata(24)
	if err != nil {
		t.Fatal(err)
	}
	if err = transact(false, func(tx treeQuery) error { return tree.reserveHistoricalMediaFileIDTx(ctx, tx, retired.FileID) }); err != nil {
		t.Fatal(err)
	}
	if err = transact(true, func(tx treeQuery) error { return tree.reserveHistoricalMediaFileIDTx(ctx, tx, retired.FileID) }); err != nil {
		t.Fatal(err)
	}
	if err = transact(true, func(tx treeQuery) error { return tree.reserveHistoricalMediaFileIDTx(ctx, tx, retired.FileID) }); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate source ID accepted: %v", err)
	}
	if err = transact(true, func(tx treeQuery) error { return tree.reserveHistoricalMediaFileIDTx(ctx, tx, strings.Repeat("A", 32)) }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("noncanonical source ID accepted: %v", err)
	}
	if err = transact(true, func(tx treeQuery) error { return tree.reserveMediaPreparationTx(ctx, tx, retired, binding) }); !errors.Is(err, ErrConflict) {
		t.Fatalf("retired recording/media ID reused: %v", err)
	}

	concurrent, err := mediacrypto.NewMetadata(25)
	if err != nil {
		t.Fatal(err)
	}
	if err = transact(true, func(tx treeQuery) error { return tree.reserveMediaPreparationTx(ctx, tx, concurrent, binding) }); err != nil {
		t.Fatal(err)
	}
	type result struct {
		op  string
		err error
	}
	results := make(chan result, 8)
	var group sync.WaitGroup
	for i := 0; i < cap(results); i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			operation := fmt.Sprintf("%064x", i+1)
			results <- result{operation, claim(true, concurrent, binding, operation)}
		}(i)
	}
	group.Wait()
	close(results)
	winner := ""
	for result := range results {
		if result.err == nil {
			if winner != "" {
				t.Fatal("multiple concurrent operations claimed the same file ID")
			}
			winner = result.op
		} else if !errors.Is(result.err, ErrConflict) {
			t.Fatalf("concurrent claim failed unexpectedly: %v", result.err)
		}
	}
	if winner == "" {
		t.Fatal("no concurrent claimant succeeded")
	}
	if err = claim(true, concurrent, binding, winner); err != nil {
		t.Fatalf("winning operation retry: %v", err)
	}
}

// The transaction must be supplied by the coordinating writer; it may be a
// database/sql transaction, and its changes remain subject to caller rollback.
var _ treeQuery = (*sql.Tx)(nil)

func TestHistoricalMediaBatchCheckpointRequiresExactContents(t *testing.T) {
	ctx := context.Background()
	db, tree, _ := sqliteFixture(t)
	manifest := strings.Repeat("d", 64)
	proofDigest := strings.Repeat("c", 64)
	ids := []string{strings.Repeat("1", 32), strings.Repeat("2", 32)}
	batch := func(commit bool, manifest string, index uint64, final bool, values []string) error {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err = tree.lockIndexedWriter(ctx, tx); err == nil {
			err = tree.verifyRoot(ctx, tx)
		}
		if err == nil {
			err = tree.reserveHistoricalMediaBatchTx(ctx, tx, manifest, index, final, proofDigest, values)
		}
		if err != nil || !commit {
			return err
		}
		return tx.Commit()
	}
	complete := func(source string) bool {
		t.Helper()
		tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		ok, e := tree.historicalSourceCompleteTx(ctx, tx, source, 2, false, proofDigest)
		if e != nil {
			t.Fatal(e)
		}
		return ok
	}
	if err := batch(false, manifest, 0, false, ids); err != nil {
		t.Fatal(err)
	}
	if complete(manifest) {
		t.Fatal("rolled-back batch marked complete")
	}
	if err := batch(true, manifest, 0, false, ids); err != nil {
		t.Fatal(err)
	}
	if complete(manifest) {
		t.Fatal("nonfinal batch marked complete")
	}
	if err := tree.CompleteHistoricalMediaIDs(ctx, manifest, 2, false, proofDigest, func() error { return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("incomplete source accepted: %v", err)
	}
	if err := batch(true, manifest, 0, false, ids); err != nil {
		t.Fatalf("identical checkpoint retry: %v", err)
	}
	if err := batch(true, manifest, 0, true, ids); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed final flag: %v", err)
	}
	if err := batch(true, manifest, 0, false, []string{strings.Repeat("3", 32)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed batch at same slot: %v", err)
	}
	if err := batch(true, manifest, 1, false, []string{ids[0]}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate file ID across batches: %v", err)
	}
	if err := batch(true, strings.Repeat("e", 64), 0, false, ids); !errors.Is(err, ErrConflict) {
		t.Fatalf("another source may not silently adopt IDs: %v", err)
	}
	if err := batch(true, manifest, 1, true, []string{ids[1], ids[0]}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unordered source: %v", err)
	}
	if err := batch(true, manifest, 2, true, []string{strings.Repeat("4", 32)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("skipped batch accepted: %v", err)
	}
	last := []string{strings.Repeat("5", 32)}
	if err := batch(true, manifest, 1, true, last); err != nil {
		t.Fatalf("final batch: %v", err)
	}
	if complete(manifest) {
		t.Fatal("final batch alone marked complete")
	}
	proofFailure := errors.New("synthetic completion proof failure")
	if err := tree.CompleteHistoricalMediaIDs(ctx, manifest, 2, false, proofDigest, func() error { return proofFailure }); !errors.Is(err, proofFailure) || complete(manifest) {
		t.Fatalf("completion proof failure did not roll back: %v", err)
	}
	if err := tree.CompleteHistoricalMediaIDs(ctx, manifest, 2, false, strings.Repeat("9", 64), func() error { return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong final digest accepted: %v", err)
	}
	if err := tree.CompleteHistoricalMediaIDs(ctx, manifest, 1, false, proofDigest, func() error { return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong batch count accepted: %v", err)
	}
	if err := tree.CompleteHistoricalMediaIDs(ctx, manifest, 2, false, proofDigest, func() error { return nil }); err != nil {
		t.Fatal("authenticated completion", err)
	}
	if !complete(manifest) || complete(strings.Repeat("e", 64)) {
		t.Fatal("completion not bound to exact source")
	}
	if err := batch(true, manifest, 1, true, last); err != nil {
		t.Fatalf("final batch retry: %v", err)
	}
	if err := batch(true, manifest, 2, false, []string{strings.Repeat("6", 32)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("post-final batch accepted: %v", err)
	}
	empty := func(source string) error {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if e = tree.lockIndexedWriter(ctx, tx); e == nil {
			e = tree.verifyRoot(ctx, tx)
		}
		if e == nil {
			e = tree.completeEmptyHistoricalMediaTx(ctx, tx, source, proofDigest)
		}
		if e != nil {
			return e
		}
		return tx.Commit()
	}
	if err := empty(manifest); !errors.Is(err, ErrConflict) {
		t.Fatalf("nonempty source accepted as empty: %v", err)
	}
	if err := empty(strings.Repeat("f", 64)); !errors.Is(err, ErrConflict) {
		t.Fatalf("different source rebound existing history: %v", err)
	}
	tag, err := tree.mediaFileTag("id", ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM sealed_tree_encryption_ids WHERE encryption_id=?`, tag); err != nil {
		t.Fatal(err)
	}
	if err = batch(true, manifest, 0, false, ids); !errors.Is(err, ErrInvalid) {
		t.Fatalf("checkpoint with missing tombstone: %v", err)
	}
}

func TestEmptyHistoricalSourceCompletion(t *testing.T) {
	ctx := context.Background()
	db, tree, _ := sqliteFixture(t)
	manifest := strings.Repeat("f", 64)
	proofDigest := strings.Repeat("c", 64)
	empty := func() error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err = tree.lockIndexedWriter(ctx, tx); err == nil {
			err = tree.verifyRoot(ctx, tx)
		}
		if err == nil {
			err = tree.completeEmptyHistoricalMediaTx(ctx, tx, manifest, proofDigest)
		}
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := empty(); err != nil {
		t.Fatal(err)
	}
	if err := empty(); err != nil {
		t.Fatalf("empty retry: %v", err)
	}
	if err := tree.CompleteHistoricalMediaIDs(ctx, manifest, 0, true, proofDigest, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if ok, e := tree.historicalSourceCompleteTx(ctx, tx, manifest, 0, true, proofDigest); e != nil || !ok {
		t.Fatal("empty source completion", ok, e)
	}
}

func TestHistoricalBatchGuardFailureRollsBackSameTransaction(t *testing.T) {
	ctx := context.Background()
	db, tree, _ := sqliteFixture(t)
	manifest, digest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	ids := []string{strings.Repeat("c", 32)}
	guardCalls := 0
	guard := func(context.Context, *sql.Tx) error {
		guardCalls++
		if guardCalls == 2 {
			return errors.New("target fence changed")
		}
		return nil
	}
	if err := tree.ApplyHistoricalMediaIDBatchGuarded(ctx, manifest, 0, true, digest, ids, guard, func([]string) error { return nil }); err == nil || guardCalls != 2 {
		t.Fatal("changed target guard accepted", err, guardCalls)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&count); err != nil || count != 1 {
		t.Fatal("guard failure did not roll back source binding/tombstones", count, err)
	}
	if err := tree.ApplyHistoricalMediaIDBatchGuarded(ctx, manifest, 0, true, digest, ids, nil, func([]string) error { return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing target guard accepted", err)
	}
}
