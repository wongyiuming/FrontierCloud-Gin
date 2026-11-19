package sealedtree

import (
	"context"
	"database/sql"
	"math"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

// FinishOpaqueHide completes one remote file's previously persisted hide
// intent only after its current paired owner durably acknowledged revocation.
// The encrypted facts retain the signed owner proof and the old alias remains
// permanently reserved. Retrying the exact operation after a lost response is
// idempotent. Unhide/new-alias registration, directory subtree hides, quota,
// audit, legacy writer fencing and actual user authorization are NOT provided;
// no production route may invoke this until those lifecycle gates exist.
func (s *SQLStore) FinishOpaqueHide(ctx context.Context, objectID, operationID, updatedAt string) error {
	return s.finishOpaqueHide(ctx, objectID, operationID, updatedAt, nil)
}

func (s *SQLStore) finishOpaqueHide(ctx context.Context, objectID, operationID, updatedAt string, afterFacts func()) error {
	if !s.valid() || ctx == nil || !hexID(objectID) || objectID == s.rootID || !lowerHex(operationID, 32) || !factText(updatedAt, 128, false) {
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
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	record, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil || entry.Kind == "directory" || s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID) != nil {
		return ErrInvalid
	}
	placement, err := s.placementFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return ErrInvalid
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return ErrInvalid
	}
	if facts.HiddenProof != nil {
		proof := facts.HiddenProof
		if proof.OperationID != operationID || facts.Visibility == nil || facts.Visibility.Hidden != 1 || facts.Visibility.UpdatedAt != updatedAt || proof.OwnerID != placement.OwnerID || proof.Alias != placement.ReadAlias || proof.BlobID != placement.BlobID {
			return ErrConflict
		}
		current, e := protocol.OpaquePlacementRevision(placement.ReadAlias, placement.BlobID, placement.SHA256, placement.Bytes, placement.Encryption)
		if e != nil || current != proof.Revision {
			return ErrInvalid
		}
		index, e := s.revocationReservation(operationID)
		if e != nil {
			return ErrInvalid
		}
		var present int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, index).Scan(&present) != nil || present != 1 {
			return ErrInvalid
		}
		return nil // exact committed retry; roll back transient writer generation
	}
	if revision == math.MaxInt64 || facts.Revocation == nil || facts.Revocation.Action != "hide" || facts.Revocation.OperationID != operationID || facts.Revocation.OwnerSignature == "" || s.verifyRevocation(ctx, tx, facts.Revocation, placement) != nil {
		return ErrConflict
	}
	proof := *facts.Revocation
	facts.Revocation = nil
	facts.HiddenProof = &proof
	facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: updatedAt}
	sealed, err := s.tree.SealFacts(facts, revision+1)
	if err != nil {
		return err
	}
	id, err := FactsEncryptionID(sealed)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, id, sealed.Sealed, sealed.ObjectIndex, revision)
	if err != nil {
		return ErrConflict
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrConflict
	}
	if afterFacts != nil {
		afterFacts()
	}
	index, err := s.revocationReservation(operationID)
	if err != nil {
		return ErrInvalid
	}
	result, err = tx.ExecContext(ctx, `DELETE FROM sealed_tree_revocations WHERE operation_index=? AND object_index=?`, index, record.ObjectIndex)
	if err != nil {
		return ErrConflict
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrConflict
	}
	// The all-items catalog can observe a pending hidden row becoming a
	// completed hidden row. Invalidate only that scope's continuation.
	if err = s.listingAdjust(ctx, tx, s.listingGroup(entry.ParentID, false), 0); err != nil {
		return err
	}
	return tx.Commit()
}

// RecoverOpaqueHideWithLease observes the pending or committed result using
// the caller's tree read fence. It does not authenticate a user or authorize
// retrying owner operations and does not return bytes or an owner token.
func (s *SQLStore) RecoverOpaqueHideWithLease(ctx context.Context, lease *TreeLease, objectID, operationID string) (state, updatedAt string, err error) {
	if !s.valid() || ctx == nil || lease == nil || !hexID(objectID) || !lowerHex(operationID, 32) {
		return "", "", ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return "", "", ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return "", "", err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return "", "", err
	}
	record, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil || entry.Kind == "directory" {
		return "", "", ErrInvalid
	}
	placement, err := s.placementFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return "", "", ErrInvalid
	}
	facts, _, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return "", "", ErrInvalid
	}
	if facts.Revocation != nil && facts.Revocation.OperationID == operationID && facts.Revocation.Action == "hide" {
		if s.verifyRevocation(ctx, tx, facts.Revocation, placement) != nil {
			return "", "", ErrInvalid
		}
		state = "pending"
	} else if facts.HiddenProof != nil && facts.HiddenProof.OperationID == operationID {
		proof := facts.HiddenProof
		revision, e := protocol.OpaquePlacementRevision(placement.ReadAlias, placement.BlobID, placement.SHA256, placement.Bytes, placement.Encryption)
		if e != nil || proof.Revision != revision || proof.OwnerID != placement.OwnerID || proof.Alias != placement.ReadAlias || proof.BlobID != placement.BlobID {
			return "", "", ErrInvalid
		}
		index, e := s.revocationReservation(operationID)
		if e != nil {
			return "", "", ErrInvalid
		}
		var n int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, index).Scan(&n) != nil || n != 1 {
			return "", "", ErrInvalid
		}
		state = "hidden"
		updatedAt = facts.Visibility.UpdatedAt
	} else {
		return "", "", ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return "", "", err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return "", "", err
	}
	return state, updatedAt, nil
}
