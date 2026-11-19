package sealedtree

import (
	"context"
	"crypto/hmac"
)

// s3Slot is a keyed, domain-separated SQL reservation for a placement. It is
// neither the provider key nor a native blob identifier and never leaves the
// Master. A unique reservation prevents collision with any native locator.
func (s *SQLStore) s3Slot(objectID string) (string, error) {
	if !hexID(objectID) {
		return "", ErrInvalid
	}
	return s.tree.BlobIndex(s.listingMAC("s3-placement-slot", objectID))
}

// checkIndexedS3 returns handled only for the S3 envelope length. All other
// records must still pass the native placement checks; changing the length or
// type never converts an invalid S3 envelope into a valid native placement.
func (s *SQLStore) checkIndexedS3(ctx context.Context, tx treeQuery, entry Entry, index string) (bool, error) {
	var slot, id string
	var revision int64
	var sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT blob_index,revision,encryption_id,sealed FROM sealed_tree_placements WHERE object_index=?`, index).Scan(&slot, &revision, &id, &sealed); err != nil {
		return false, err
	}
	if len(sealed) != 1+recordSaltBytes+nonceBytes+s3PlacementPayloadBytes+16 {
		return false, nil
	}
	r := S3PlacementRecord{ObjectIndex: index, Revision: revision, Sealed: sealed}
	actual, err := S3PlacementEncryptionID(r)
	if err != nil || !hmac.Equal([]byte(actual), []byte(id)) {
		return true, ErrInvalid
	}
	if _, err = s.openIndexedS3Placement(ctx, tx, entry.ObjectID, slot, index, revision, sealed); err != nil {
		return true, err
	}
	var reserved, blob, aliases int
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?),(SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?),(SELECT COUNT(*) FROM sealed_tree_aliases WHERE object_index=?)`, id, slot, index).Scan(&reserved, &blob, &aliases); err != nil || reserved != 1 || blob != 1 || aliases != 0 {
		return true, ErrInvalid
	}
	return true, nil
}

// createImportedS3Fixture is intentionally package-private: callers have not
// yet wired source authentication, provider/member authorization, audit,
// recovery, S3 upload, or deletion. It stores metadata only, never moves a
// provider object, and must not be made a product import gate by itself.
func (s *SQLStore) createImportedS3Fixture(ctx context.Context, entry Entry, facts Facts, placement S3Placement) error {
	if !s.valid() || ctx == nil || entry.ObjectID == s.rootID || entry.Kind == "directory" || entry.ObjectID != placement.ObjectID || !factsCompatible(entry, facts) || facts.Revocation != nil || facts.HiddenProof != nil {
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
	if err = s.insertS3PlacementTx(ctx, tx, entry, facts, placement); err != nil {
		return err
	}
	return tx.Commit()
}

// insertS3PlacementTx requires the caller to hold the tree writer and to
// authenticate the source and destination facts in this transaction.
func (s *SQLStore) insertS3PlacementTx(ctx context.Context, tx treeQuery, entry Entry, facts Facts, placement S3Placement) error {
	if entry.ObjectID == s.rootID || entry.Kind != "audio" && entry.Kind != "video" || entry.ObjectID != placement.ObjectID || !factsCompatible(entry, facts) || facts.Revocation != nil || facts.HiddenProof != nil {
		return ErrInvalid
	}
	name, err := s.tree.Seal(entry.ParentID, entry.ObjectID, entry.Kind, entry.Name, 1)
	if err != nil {
		return err
	}
	sealedFacts, err := s.tree.SealFacts(facts, 1)
	if err != nil || sealedFacts.ObjectIndex != name.ObjectIndex {
		return ErrInvalid
	}
	sealedS3, err := s.tree.SealS3Placement(placement, 1)
	if err != nil || sealedS3.ObjectIndex != name.ObjectIndex {
		return ErrInvalid
	}
	slot, err := s.s3Slot(entry.ObjectID)
	if err != nil {
		return err
	}
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_pending_files WHERE object_index=? OR (parent_index=? AND lookup_tag=?)`, name.ObjectIndex, name.ParentIndex, name.Lookup).Scan(&pending); err != nil || pending != 0 {
		return ErrConflict
	}
	if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
		return err
	}
	if err = s.checkChildPathBounds(ctx, tx, entry.ParentID, entry.Name); err != nil {
		return err
	}
	if _, err = s.listingAncestorAnchor(ctx, tx, entry.ParentID, true); err != nil {
		return err
	}
	nameID, err := reserveEncryptionID(ctx, tx, name)
	if err != nil {
		return err
	}
	factsID, err := FactsEncryptionID(sealedFacts)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, factsID); err != nil {
		return err
	}
	placementID, err := S3PlacementEncryptionID(sealedS3)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, placementID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, slot); err != nil {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_records(object_index,parent_index,lookup_tag,revision,encryption_id,sealed) VALUES(?,?,?,?,?,?)`, name.ObjectIndex, name.ParentIndex, name.Lookup, name.Revision, nameID, name.Sealed); err != nil {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_facts(object_index,revision,encryption_id,sealed) VALUES(?,?,?,?)`, sealedFacts.ObjectIndex, sealedFacts.Revision, factsID, sealedFacts.Sealed); err != nil {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_placements(object_index,blob_index,revision,encryption_id,sealed) VALUES(?,?,?,?,?)`, sealedS3.ObjectIndex, slot, sealedS3.Revision, placementID, sealedS3.Sealed); err != nil {
		return ErrConflict
	}
	if err = s.listingAdd(ctx, tx, entry, name, listingClass(&facts)); err != nil {
		return err
	}
	return nil
}

func (s *SQLStore) openIndexedS3Placement(_ context.Context, _ treeQuery, objectID, slot, objectIndex string, revision int64, sealed []byte) (S3Placement, error) {
	expected, err := s.s3Slot(objectID)
	if err != nil || expected != slot {
		return S3Placement{}, ErrInvalid
	}
	p, err := s.tree.OpenS3Placement(S3PlacementRecord{ObjectIndex: objectIndex, Revision: revision, Sealed: sealed})
	if err != nil || p.ObjectID != objectID {
		return S3Placement{}, ErrInvalid
	}
	return p, nil
}
