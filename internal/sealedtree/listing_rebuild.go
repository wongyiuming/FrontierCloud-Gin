package sealedtree

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
)

func (s *SQLStore) listingBuildState(ctx context.Context, tx treeQuery) (int, string, error) {
	var state int
	var cursor, mac string
	err := tx.QueryRowContext(ctx, `SELECT state,build_cursor,mac FROM sealed_tree_listing_meta WHERE singleton=1`).Scan(&state, &cursor, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return -1, "", nil
	}
	if err != nil || (state != 0 && state != 1) || (cursor != "" && !hexID(cursor)) || state == 1 && cursor != "" || !hmac.Equal([]byte(mac), []byte(s.listingMetaMAC(state, cursor))) {
		return -1, "", ErrInvalid
	}
	return state, cursor, nil
}
func (s *SQLStore) ensureListingGroupDuringBuild(ctx context.Context, tx treeQuery, parent string, class int) error {
	group := s.listingClassGroup(parent, class)
	key := s.listingKey(group, listingSentinel)
	var exists int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM sealed_tree_listing WHERE index_key=?`, key).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return s.createListingGroup(ctx, tx, parent, class)
	}
	if err != nil {
		return ErrInvalid
	}
	_, _, err = s.listingSummary(ctx, tx, group)
	return err
}

// BeginListingRebuild explicitly begins construction for an older encrypted
// tree after its new empty schema has been provisioned. No existing index is
// overwritten. While state is building, ordinary indexed writers/readers fail
// closed. The caller must hold the deployment gate and reconcile pending
// publication/revocation intents first; it does not migrate plaintext data.
func (s *SQLStore) BeginListingRebuild(ctx context.Context) error {
	if !s.valid() || ctx == nil {
		return ErrInvalid
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	state, _, err := s.listingBuildState(ctx, tx)
	if err != nil || state != -1 {
		return ErrConflict
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_listing`).Scan(&count) != nil || count != 0 {
		return ErrConflict
	}
	present, err := hasSelectedCancellationTable(ctx, tx)
	if err != nil {
		return err
	}
	operationCount := `SELECT COUNT(*) FROM sealed_tree_operation_ids WHERE completed=0`
	if present {
		if err = s.verifySelectedCancellationRows(ctx, tx); err != nil {
			return err
		}
		operationCount = `SELECT COUNT(*) FROM sealed_tree_operation_ids o LEFT JOIN selected_upload_cancellations c ON c.operation_id=o.operation_id WHERE o.completed=0 AND c.operation_id IS NULL`
	}
	if tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM sealed_tree_pending_files)+(SELECT COUNT(*) FROM sealed_tree_pending_facts)+(SELECT COUNT(*) FROM sealed_tree_revocations)+(`+operationCount+`)`).Scan(&count) != nil || count != 0 {
		return ErrConflict
	}
	if err = s.createListingGroup(ctx, tx, s.rootID, listingVisibleGroup); err != nil {
		return err
	}
	if err = s.createListingGroup(ctx, tx, s.rootID, listingHidden); err != nil {
		return err
	}
	if err = s.createListingGroup(ctx, tx, s.rootID, listingInternal); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_listing_meta(singleton,state,build_cursor,mac) VALUES(1,0,'',?)`, s.listingMetaMAC(0, "")); err != nil {
		return ErrConflict
	}
	return tx.Commit()
}

// ContinueListingRebuild commits at most limit authenticated entries and an
// authenticated opaque object-index checkpoint. Every batch takes and releases
// the same exclusive tree fence; other writers fail while state is building.
// A crash rolls back the current batch and the next call resumes exactly.
// Finishing does a bounded SQL count check but not a malicious-writer or
// whole-database rollback proof. No runtime installs this builder yet.
func (s *SQLStore) ContinueListingRebuild(ctx context.Context, limit int) (bool, error) {
	if !s.valid() || ctx == nil || limit < 1 || limit > 256 {
		return false, ErrInvalid
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = lockWriter(ctx, tx); err != nil {
		return false, err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return false, err
	}
	state, cursor, err := s.listingBuildState(ctx, tx)
	if err != nil {
		return false, err
	}
	if state == 1 {
		return true, nil
	}
	if state != 0 {
		return false, ErrInvalid
	}
	rows, err := tx.QueryContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE object_index>? ORDER BY object_index LIMIT ?`, cursor, limit)
	if err != nil {
		return false, err
	}
	records := make([]Record, 0, limit)
	last := cursor
	for rows.Next() {
		r, e := scanRecord(rows)
		if e != nil || r.ObjectIndex <= last {
			rows.Close()
			return false, ErrInvalid
		}
		last = r.ObjectIndex
		records = append(records, r)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil || closeErr != nil {
		return false, ErrInvalid
	}
	if err = verifyNameReservations(ctx, tx, records); err != nil {
		return false, err
	}
	for _, r := range records {
		entry, e := s.tree.OpenRecord(r)
		if e != nil || s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID) != nil {
			return false, ErrInvalid
		}
		facts, _, e := s.factsFor(ctx, tx, entry, r.ObjectIndex)
		if e != nil || facts.Revocation != nil || facts.S3Deletion != nil {
			return false, ErrInvalid
		}
		for _, v := range []int{listingHidden, listingVisibleGroup, listingInternal} {
			if e = s.ensureListingGroupDuringBuild(ctx, tx, entry.ParentID, v); e != nil {
				return false, e
			}
			if entry.Kind == "directory" {
				if e = s.ensureListingGroupDuringBuild(ctx, tx, entry.ObjectID, v); e != nil {
					return false, e
				}
			}
		}
		if e = s.listingAdd(ctx, tx, entry, r, listingClass(&facts)); e != nil {
			return false, e
		}
	}
	done := len(records) < limit
	newState, newCursor := 0, last
	if done {
		var objects, indexed int64
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_records`).Scan(&objects) != nil || tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_listing WHERE entry_count=-1`).Scan(&indexed) != nil || objects != indexed {
			return false, ErrInvalid
		}
		newState, newCursor = 1, ""
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_listing_meta SET state=?,build_cursor=?,mac=? WHERE singleton=1 AND state=0 AND build_cursor=?`, newState, newCursor, s.listingMetaMAC(newState, newCursor), cursor)
	if err != nil {
		return false, ErrConflict
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return false, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return done, nil
}
