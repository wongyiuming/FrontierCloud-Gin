package sealedtree

import (
	"context"
	"database/sql"
)

// PendingRecovery is sensitive Master-only memory. It is not a node message,
// user authorization, source-snapshot proof or permission to publish bytes.
type PendingRecovery struct {
	OperationID string
	Entry       Entry
	Placement   Placement
	Facts       Facts
}

// RecoverPendingWithLease lists a bounded page of authenticated durable file
// intents after a restart, including the opaque physical mapping and encrypted
// facts. A caller-owned shared lease must remain held until the page is used;
// no write may be attempted while holding it. Release it before publishing,
// then reauthenticate the intent via PublishPending. Pages obtained under
// separate leases are not a single snapshot: concurrent earlier insertions
// require another full pass. Source identity, bytes, ownership, authorization,
// quotas, multi-node receipts and global rollback protection remain separate
// hard gates; this helper must not itself activate a migration.
func (s *SQLStore) RecoverPendingWithLease(ctx context.Context, lease *TreeLease, after string, limit int) ([]PendingRecovery, bool, error) {
	if !s.valid() || ctx == nil || lease == nil || (after != "" && !hexID(after)) || limit < 1 || limit > 64 {
		return nil, false, ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return nil, false, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return nil, false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT operation_id FROM sealed_tree_pending_files WHERE operation_id>? ORDER BY operation_id LIMIT ?`, after, limit+1)
	if err != nil {
		return nil, false, err
	}
	ids := make([]string, 0, limit+1)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil || !hexID(id) || id <= after || (len(ids) > 0 && id <= ids[len(ids)-1]) {
			rows.Close()
			return nil, false, ErrInvalid
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, false, err
	}
	if err = rows.Close(); err != nil {
		return nil, false, err
	}
	more := len(ids) > limit
	if more {
		ids = ids[:limit]
	}
	result := make([]PendingRecovery, 0, len(ids))
	for _, id := range ids {
		item, readErr := s.recoveryFor(ctx, tx, id)
		if readErr != nil {
			return nil, false, readErr
		}
		result = append(result, item)
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return nil, false, err
	}
	return result, more, nil
}

func (s *SQLStore) recoveryFor(ctx context.Context, tx treeQuery, id string) (PendingRecovery, error) {
	pending, entry, placement, readErr := s.pending(ctx, tx, id)
	if readErr != nil || pending.facts == nil || s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID) != nil {
		return PendingRecovery{}, ErrInvalid
	}
	facts, factErr := s.tree.OpenFacts(*pending.facts)
	if factErr != nil || !factsCompatiblePending(entry, facts) {
		return PendingRecovery{}, ErrInvalid
	}
	return PendingRecovery{OperationID: id, Entry: entry, Placement: placement, Facts: facts}, nil
}

// FindPendingObjectWithLease recovers the original operation after a response
// was lost before the caller could record its operation ID. The keyed lookup
// never places the business ID into SQL. The caller must independently verify
// that every recovered field matches its authenticated source and destination;
// found=false does not prove an object was never committed or a DB not rolled
// back. The same lease and release-before-publication rules as the paged
// recovery function apply.
func (s *SQLStore) FindPendingObjectWithLease(ctx context.Context, lease *TreeLease, objectID string) (PendingRecovery, bool, error) {
	if !s.valid() || ctx == nil || lease == nil || !hexID(objectID) || objectID == s.rootID {
		return PendingRecovery{}, false, ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return PendingRecovery{}, false, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return PendingRecovery{}, false, err
	}
	index, err := s.tree.ObjectIndex(objectID)
	if err != nil {
		return PendingRecovery{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return PendingRecovery{}, false, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return PendingRecovery{}, false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT operation_id FROM sealed_tree_pending_files WHERE object_index=? LIMIT 2`, index)
	if err != nil {
		return PendingRecovery{}, false, err
	}
	var op string
	found := rows.Next()
	if found {
		if err = rows.Scan(&op); err != nil || rows.Next() {
			rows.Close()
			return PendingRecovery{}, false, ErrInvalid
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return PendingRecovery{}, false, err
	}
	if err = rows.Close(); err != nil {
		return PendingRecovery{}, false, err
	}
	var result PendingRecovery
	if found {
		result, err = s.recoveryFor(ctx, tx, op)
		if err != nil || result.Entry.ObjectID != objectID {
			return PendingRecovery{}, false, ErrInvalid
		}
	}
	if err = tx.Commit(); err != nil {
		return PendingRecovery{}, false, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return PendingRecovery{}, false, err
	}
	return result, found, nil
}
