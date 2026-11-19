package sealedtree

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"time"
)

// pendingFile contains ciphertext and independent random operation identity
// only; decoded names, owner IDs, object IDs and payload digests stay in RAM.
type pendingFile struct {
	op, mac, nameID, placementID, factsID string
	name                                  Record
	placement                             PlacementRecord
	facts                                 *FactsRecord
}

func (s *SQLStore) pendingMAC(p pendingFile) string {
	h := hmac.New(sha256.New, s.tree.indexKey[:])
	for _, value := range []string{"frontiercloud:sealed-tree:pending:v2\x00", p.op, p.name.ObjectIndex, p.name.ParentIndex, p.name.Lookup, p.nameID, p.placement.BlobIndex, p.placementID} {
		_, _ = h.Write([]byte(value))
	}
	_, _ = h.Write(p.name.Sealed)
	_, _ = h.Write(p.placement.Sealed)
	if p.facts == nil {
		_, _ = h.Write([]byte{0})
	} else {
		_, _ = h.Write([]byte{1})
		_, _ = h.Write([]byte(p.factsID))
		_, _ = h.Write(p.facts.Sealed)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *SQLStore) completionMAC(op, objectIndex, blobIndex string) string {
	h := hmac.New(sha256.New, s.tree.indexKey[:])
	_, _ = h.Write([]byte("frontiercloud:sealed-tree:completion:v1\x00" + op + objectIndex + blobIndex))
	return hex.EncodeToString(h.Sum(nil))
}

// completed reports a historical, authenticated commit receipt. It is not a
// claim that the object remains accessible after later legitimate changes.
func (s *SQLStore) completed(ctx context.Context, tx treeQuery, op string) (bool, error) {
	if !hexID(op) {
		return false, ErrInvalid
	}
	var objectIndex, blobIndex, mac string
	err := tx.QueryRowContext(ctx, `SELECT object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`, op).Scan(&objectIndex, &blobIndex, &mac)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil || !hexID(objectIndex) || !hexID(blobIndex) || !hmac.Equal([]byte(mac), []byte(s.completionMAC(op, objectIndex, blobIndex))) {
		return false, ErrInvalid
	}
	var pendingCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_pending_files WHERE operation_id=?`, op).Scan(&pendingCount); err != nil || pendingCount != 0 {
		return false, ErrInvalid
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_pending_facts WHERE operation_id=?`, op).Scan(&pendingCount); err != nil || pendingCount != 0 {
		return false, ErrInvalid
	}
	return true, nil
}

// PrepareFile reserves an opaque operation ID, blob ID, name and encryption
// identities in one SQLite transaction. It is a local prototype and does not
// expose a product write path or establish cross-node durability.
func (s *SQLStore) PrepareFile(ctx context.Context, entry Entry, placement Placement) (string, error) {
	if !s.prototypeOnly() {
		return "", ErrFactsRequired
	}
	return s.prepareFile(ctx, entry, placement, nil)
}

// PrepareFileWithFacts binds encrypted visibility, playback and lyric facts to
// the same operation as name and placement. Because it accepts caller-supplied
// locators, it is a synthetic compatibility primitive and must not be used by
// a real import. Runtime and authorization remain disabled.
func (s *SQLStore) PrepareFileWithFacts(ctx context.Context, entry Entry, placement Placement, facts Facts) (string, error) {
	if !s.prototypeOnly() {
		return "", ErrExternalLocators
	}
	if facts.Revocation != nil || !factsCompatible(entry, facts) {
		return "", ErrInvalid
	}
	return s.prepareFile(ctx, entry, placement, &facts)
}

// PreparedFile identifies a durable pending intent. BlobID and ReadAlias are
// independent opaque values, not historic media IDs or names. This return is
// trusted-Master state, not an authorization to use either value.
type PreparedFile struct {
	OperationID string
	BlobID      string
	ReadAlias   string
}

// PrepareFileWithFreshLocators creates both physical and public identifiers
// inside the trusted Master. A caller cannot supply or influence either value.
// A lost response is recovered by FindPendingObjectWithLease and compared to
// a separately authenticated source manifest; absence does not prove an
// object was never committed. This does not enable the import route.
func (s *SQLStore) PrepareFileWithFreshLocators(ctx context.Context, entry Entry, placement Placement, facts Facts) (PreparedFile, error) {
	if placement.BlobID != "" || placement.ReadAlias != "" || facts.Revocation != nil || !factsCompatible(entry, facts) {
		return PreparedFile{}, ErrInvalid
	}
	blob, err := NewBlobID()
	if err != nil {
		return PreparedFile{}, err
	}
	alias, err := NewBlobID()
	if err != nil {
		return PreparedFile{}, err
	}
	placement.BlobID, placement.ReadAlias = blob, alias
	op, err := s.prepareFile(ctx, entry, placement, &facts)
	if err != nil {
		return PreparedFile{}, err
	}
	return PreparedFile{OperationID: op, BlobID: blob, ReadAlias: alias}, nil
}

func (s *SQLStore) prepareFile(ctx context.Context, entry Entry, placement Placement, facts *Facts) (string, error) {
	if !s.valid() || entry.ObjectID == s.rootID || entry.Kind == "directory" || entry.ObjectID != placement.ObjectID {
		return "", ErrInvalid
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	name, err := s.tree.Seal(entry.ParentID, entry.ObjectID, entry.Kind, entry.Name, 1)
	if err != nil {
		return "", err
	}
	loc, err := s.tree.SealPlacement(placement, 1)
	if err != nil || name.ObjectIndex != loc.ObjectIndex {
		return "", ErrInvalid
	}
	var sealedFacts *FactsRecord
	if facts != nil {
		value, sealErr := s.tree.SealFacts(*facts, 1)
		if sealErr != nil || value.ObjectIndex != name.ObjectIndex {
			return "", ErrInvalid
		}
		sealedFacts = &value
	}
	op, err := NewBlobID()
	if err != nil || op == placement.BlobID || op == placement.ReadAlias || op == placement.ObjectID || op == placement.NativeObjectID {
		return "", ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err = s.prepareFileTx(ctx, tx, entry, placement, facts, name, loc, sealedFacts, op); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return op, nil
}

// prepareFileTx performs only the pending-tree mutation on the transaction
// created and fenced by its caller. It neither commits nor authorizes a request.
// Keeping it private prevents callers from injecting an unrelated transaction.
func (s *SQLStore) prepareFileTx(ctx context.Context, tx treeQuery, entry Entry, placement Placement, facts *Facts, name Record, loc PlacementRecord, sealedFacts *FactsRecord, op string) error {
	var err error
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
		return err
	}
	if err = s.checkChildPathBounds(ctx, tx, entry.ParentID, entry.Name); err != nil {
		return err
	}
	if !s.prototypeOnly() {
		if _, err = s.listingAncestorAnchor(ctx, tx, entry.ParentID, true); err != nil {
			return err
		}
	}
	if facts != nil && facts.PendingPlaceholder != nil {
		if _, _, err = s.validatePendingPlaceholder(ctx, tx, entry, *facts); err != nil {
			return err
		}
	}
	nameID, err := reserveEncryptionID(ctx, tx, name)
	if err != nil {
		return err
	}
	locID, err := PlacementEncryptionID(loc)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, locID); err != nil {
		return err
	}
	factsID := ""
	if sealedFacts != nil {
		factsID, err = FactsEncryptionID(*sealedFacts)
		if err != nil {
			return err
		}
		if _, err = reserveID(ctx, tx, factsID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_operation_ids(operation_id) VALUES(?)`, op); err != nil {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, loc.BlobIndex); err != nil {
		return ErrConflict
	}
	aliasIndex, err := s.tree.BlobIndex(placement.ReadAlias)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, aliasIndex); err != nil {
		return ErrConflict
	}
	mac := s.pendingMAC(pendingFile{op: op, nameID: nameID, placementID: locID, factsID: factsID, name: name, placement: loc, facts: sealedFacts})
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_pending_files(operation_id,operation_mac,object_index,parent_index,lookup_tag,name_encryption_id,name_sealed,blob_index,placement_encryption_id,placement_sealed) VALUES(?,?,?,?,?,?,?,?,?,?)`, op, mac, name.ObjectIndex, name.ParentIndex, name.Lookup, nameID, name.Sealed, loc.BlobIndex, locID, loc.Sealed); err != nil {
		return ErrConflict
	}
	if sealedFacts != nil {
		if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_pending_facts(operation_id,object_index,revision,encryption_id,sealed) VALUES(?,?,?,?,?)`, op, sealedFacts.ObjectIndex, sealedFacts.Revision, factsID, sealedFacts.Sealed); err != nil {
			return ErrConflict
		}
	}
	return nil
}

func (s *SQLStore) pending(ctx context.Context, tx treeQuery, op string) (pendingFile, Entry, Placement, error) {
	var p pendingFile
	if !hexID(op) {
		return p, Entry{}, Placement{}, ErrInvalid
	}
	p.op = op
	p.name.Revision = 1
	p.placement.Revision = 1
	err := tx.QueryRowContext(ctx, `SELECT operation_mac,object_index,parent_index,lookup_tag,name_encryption_id,name_sealed,blob_index,placement_encryption_id,placement_sealed FROM sealed_tree_pending_files WHERE operation_id=?`, op).Scan(&p.mac, &p.name.ObjectIndex, &p.name.ParentIndex, &p.name.Lookup, &p.nameID, &p.name.Sealed, &p.placement.BlobIndex, &p.placementID, &p.placement.Sealed)
	if err != nil {
		return pendingFile{}, Entry{}, Placement{}, ErrInvalid
	}
	p.placement.ObjectIndex = p.name.ObjectIndex
	var factRecord FactsRecord
	var factID string
	factErr := tx.QueryRowContext(ctx, `SELECT object_index,revision,encryption_id,sealed FROM sealed_tree_pending_facts WHERE operation_id=?`, op).Scan(&factRecord.ObjectIndex, &factRecord.Revision, &factID, &factRecord.Sealed)
	if factErr == nil {
		p.facts = &factRecord
		p.factsID = factID
	} else if factErr != sql.ErrNoRows {
		return pendingFile{}, Entry{}, Placement{}, ErrInvalid
	}
	if !hmac.Equal([]byte(p.mac), []byte(s.pendingMAC(p))) {
		return pendingFile{}, Entry{}, Placement{}, ErrInvalid
	}
	nameID, nerr := EncryptionID(p.name)
	locID, lerr := PlacementEncryptionID(p.placement)
	entry, eerr := s.tree.OpenRecord(p.name)
	loc, perr := s.tree.OpenPlacement(p.placement)
	if nerr != nil || lerr != nil || eerr != nil || perr != nil || nameID != p.nameID || locID != p.placementID || entry.ObjectID != loc.ObjectID || entry.Kind == "directory" || op == loc.BlobID || op == loc.ReadAlias {
		return pendingFile{}, Entry{}, Placement{}, ErrInvalid
	}
	aliasIndex, aliasErr := s.tree.BlobIndex(loc.ReadAlias)
	if aliasErr != nil || aliasIndex == p.placement.BlobIndex {
		return pendingFile{}, Entry{}, Placement{}, ErrInvalid
	}
	if p.facts != nil {
		id, idErr := FactsEncryptionID(*p.facts)
		value, valueErr := s.tree.OpenFacts(*p.facts)
		if idErr != nil || valueErr != nil || id != p.factsID || p.facts.ObjectIndex != p.name.ObjectIndex || p.facts.Revision != 1 || !factsCompatiblePending(entry, value) {
			return pendingFile{}, Entry{}, Placement{}, ErrInvalid
		}
		if value.PendingPlaceholder != nil {
			if _, _, err = s.validatePendingPlaceholder(ctx, tx, entry, value); err != nil {
				return pendingFile{}, Entry{}, Placement{}, err
			}
		}
		var reserved int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, id).Scan(&reserved); err != nil || reserved != 1 {
			return pendingFile{}, Entry{}, Placement{}, ErrInvalid
		}
	}
	var n int
	for _, q := range []struct{ statement, value string }{
		{`SELECT COUNT(*) FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=0`, op},
		{`SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, nameID},
		{`SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, locID},
		{`SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, p.placement.BlobIndex},
		{`SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, aliasIndex},
	} {
		if err = tx.QueryRowContext(ctx, q.statement, q.value).Scan(&n); err != nil || n != 1 {
			return pendingFile{}, Entry{}, Placement{}, ErrInvalid
		}
	}
	return p, entry, loc, nil
}

func samePending(a, b pendingFile) bool {
	if (a.facts == nil) != (b.facts == nil) {
		return false
	}
	if a.facts != nil && (a.factsID != b.factsID || a.facts.ObjectIndex != b.facts.ObjectIndex || a.facts.Revision != b.facts.Revision || !bytes.Equal(a.facts.Sealed, b.facts.Sealed)) {
		return false
	}
	return a.op == b.op && a.mac == b.mac && a.nameID == b.nameID && a.placementID == b.placementID && a.name.ObjectIndex == b.name.ObjectIndex && a.name.ParentIndex == b.name.ParentIndex && a.name.Lookup == b.name.Lookup && a.placement.BlobIndex == b.placement.BlobIndex && bytes.Equal(a.name.Sealed, b.name.Sealed) && bytes.Equal(a.placement.Sealed, b.placement.Sealed)
}

// PublishPending is an isolated single-filesystem proof of recovery, not a
// remote-node protocol. Root ownership must be exclusive for its entire call;
// callers must not use it for live untrusted nodes. A crash after linking but
// before SQL commit leaves a pending operation which may be retried safely.
// All ownership, authorization, quota and remote availability remain external.
func (s *SQLStore) PublishPending(ctx context.Context, op string, pub *BlobPublisher, src io.Reader) error {
	if !s.valid() || pub == nil || src == nil {
		return ErrInvalid
	}
	// Refuse an unattached/invalid fence before publishing any physical bytes.
	// Do not hold the exclusive lock during a potentially large stream; the
	// durable intent is reauthenticated after reacquiring it for SQL commit.
	ready, readyErr := s.acquireMutation(ctx)
	if readyErr != nil {
		return readyErr
	}
	ready()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		tx.Rollback()
		return err
	}
	before, entry, loc, err := s.pending(ctx, tx, op)
	if err != nil {
		done, checkErr := s.completed(ctx, tx, op)
		tx.Rollback()
		if checkErr != nil {
			return checkErr
		}
		if done {
			return nil
		}
		return err
	}
	// Prototype intents without encrypted facts cannot be activated by a
	// fenced store after restart or after a mode transition.
	if !s.prototypeOnly() && before.facts == nil {
		tx.Rollback()
		return ErrFactsRequired
	}
	if before.facts != nil {
		facts, e := s.tree.OpenFacts(*before.facts)
		if e != nil || facts.PendingSelectedUpload != nil {
			tx.Rollback()
			return ErrInvalid
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if err = pub.Publish(ctx, op, loc.BlobID, loc.Bytes, loc.SHA256, src); err != nil {
		return err
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.finalizePendingTx(ctx, tx, op, before, entry, loc); err != nil {
		return err
	}
	return tx.Commit()
}

// finalizePendingTx performs only authenticated tree mutations on the
// caller's existing transaction. It never opens, commits, or rolls back a
// transaction and does not prove remote publication or authorize an import.
func (s *SQLStore) finalizePendingTx(ctx context.Context, tx treeQuery, op string, before pendingFile, entry Entry, loc Placement) error {
	return s.finalizePendingTxSelected(ctx, tx, op, before, entry, loc, false)
}

// finalizePendingTxSelected may remove the selected marker only after its
// private caller has verified Owner publication and selected admission in the
// same transaction. Generic publication always calls the wrapper above.
func (s *SQLStore) finalizePendingTxSelected(ctx context.Context, tx treeQuery, op string, before pendingFile, entry Entry, loc Placement, selected bool) error {
	var err error
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	after, entry2, loc2, err := s.pending(ctx, tx, op)
	if err != nil || !samePending(before, after) || entry != entry2 || loc.ObjectID != loc2.ObjectID || loc.BlobID != loc2.BlobID {
		return ErrConflict
	}
	if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
		return err
	}
	if err = s.checkChildPathBounds(ctx, tx, entry.ParentID, entry.Name); err != nil {
		return err
	}
	finalFacts, finalFactsID := before.facts, before.factsID
	var listingFacts *Facts
	if before.facts != nil {
		f, e := s.tree.OpenFacts(*before.facts)
		if e != nil || !factsCompatiblePending(entry, f) {
			return ErrInvalid
		}
		needsSeal := false
		if f.PendingSelectedUpload != nil {
			if !selected {
				return ErrInvalid
			}
			f.PendingSelectedUpload = nil
			if entry.Kind == "audio" {
				if f.LyricResolution != nil || f.Lyric != nil || f.InternalDefaultLyric != nil {
					return ErrInvalid
				}
				now := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
				f.LyricResolution = &LyricResolutionFact{State: "none", Origin: "native", OperationID: op, PreviousRevision: 1, RelationCreatedAt: now, RelationUpdatedAt: now}
				evidence, err := s.nativeLyricEvidence(f)
				if err != nil {
					return err
				}
				f.LyricResolution.Evidence = evidence
			}
			needsSeal = true
		} else if selected {
			return ErrInvalid
		}
		if f.PendingPlaceholder != nil {
			if e = s.removePendingPlaceholder(ctx, tx, entry, f); e != nil {
				return e
			}
			f.PendingPlaceholder = nil
			needsSeal = true
		}
		if needsSeal {
			sealed, e := s.tree.SealFacts(f, 1)
			if e != nil {
				return e
			}
			id, e := FactsEncryptionID(sealed)
			if e != nil {
				return e
			}
			if _, e = reserveID(ctx, tx, id); e != nil {
				return e
			}
			finalFacts, finalFactsID = &sealed, id
		}
		if !factsCompatible(entry, f) {
			return ErrInvalid
		}
		listingFacts = &f
	} else if selected {
		return ErrInvalid
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_records(object_index,parent_index,lookup_tag,revision,encryption_id,sealed) VALUES(?,?,?,1,?,?)`, before.name.ObjectIndex, before.name.ParentIndex, before.name.Lookup, before.nameID, before.name.Sealed); err != nil {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_placements(object_index,blob_index,revision,encryption_id,sealed) VALUES(?,?,1,?,?)`, before.placement.ObjectIndex, before.placement.BlobIndex, before.placementID, before.placement.Sealed); err != nil {
		return ErrConflict
	}
	aliasIndex, err := s.tree.BlobIndex(loc.ReadAlias)
	if err != nil {
		return ErrInvalid
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_aliases(alias_index,object_index) VALUES(?,?)`, aliasIndex, before.placement.ObjectIndex); err != nil {
		return ErrConflict
	}
	if finalFacts != nil {
		if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_facts(object_index,revision,encryption_id,sealed) VALUES(?,?,?,?)`, finalFacts.ObjectIndex, finalFacts.Revision, finalFactsID, finalFacts.Sealed); err != nil {
			return ErrConflict
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM sealed_tree_pending_facts WHERE operation_id=?`, op); err != nil {
			return err
		}
	}
	if err = s.listingAdd(ctx, tx, entry, before.name, listingClass(listingFacts)); err != nil {
		return err
	}
	receipt := s.completionMAC(op, before.name.ObjectIndex, before.placement.BlobIndex)
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_operation_ids SET completed=1,object_index=?,blob_index=?,receipt_mac=? WHERE operation_id=? AND completed=0`, before.name.ObjectIndex, before.placement.BlobIndex, receipt, op)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sealed_tree_pending_files WHERE operation_id=?`, op); err != nil {
		return err
	}
	return nil
}
