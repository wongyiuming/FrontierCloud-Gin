package sealedtree

import (
	"context"
	"math"
)

// UpgradeFactsToV2 explicitly upgrades one authenticated v1 encrypted facts
// row under the tree's mutation fence. It allocates a fresh permanent nonce
// identity and advances the revision in the same transaction. A row already
// at v2 is reported only when expectedRevision matches; after a lost response
// the caller must re-read and reconcile, not assume an unrelated write was
// this upgrade. This does not migrate legacy plaintext tables, WAL or backups,
// nor does it install a product route or make a MySQL tree runtime available.
func (s *SQLStore) UpgradeFactsToV2(ctx context.Context, objectID string, expectedRevision int64) (int64, bool, error) {
	if !s.valid() || ctx == nil || !hexID(objectID) || objectID == s.rootID || expectedRevision < 1 {
		return 0, false, ErrInvalid
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return 0, false, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return 0, false, err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return 0, false, err
	}
	record, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil {
		return 0, false, err
	}
	row, err := scanFacts(tx.QueryRowContext(ctx, `SELECT object_index,revision,encryption_id,sealed FROM sealed_tree_facts WHERE object_index=?`, record.ObjectIndex))
	if err != nil {
		return 0, false, err
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return 0, false, err
	}
	if revision != row.Revision || revision != expectedRevision {
		return 0, false, ErrConflict
	}
	if row.Sealed[0] == factsRecordVersion {
		return revision, true, nil
	}
	if row.Sealed[0] != recordVersion || revision == math.MaxInt64 {
		return 0, false, ErrInvalid
	}
	sealed, err := s.tree.SealFacts(facts, revision+1)
	if err != nil {
		return 0, false, err
	}
	id, err := FactsEncryptionID(sealed)
	if err != nil {
		return 0, false, err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return 0, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, id, sealed.Sealed, sealed.ObjectIndex, revision)
	if err != nil {
		return 0, false, ErrConflict
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return 0, false, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return 0, false, err
	}
	return sealed.Revision, false, nil
}
