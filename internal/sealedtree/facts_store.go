package sealedtree

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"math"
	"reflect"
)

func scanFacts(row interface{ Scan(...any) error }) (FactsRecord, error) {
	var record FactsRecord
	var storedID string
	if err := row.Scan(&record.ObjectIndex, &record.Revision, &storedID, &record.Sealed); err != nil {
		return FactsRecord{}, err
	}
	actual, err := FactsEncryptionID(record)
	if err != nil || !hmac.Equal([]byte(storedID), []byte(actual)) {
		return FactsRecord{}, ErrInvalid
	}
	return record, nil
}

func (s *SQLStore) factsFor(ctx context.Context, tx treeQuery, entry Entry, index string) (Facts, int64, error) {
	r, err := scanFacts(tx.QueryRowContext(ctx, `SELECT object_index,revision,encryption_id,sealed FROM sealed_tree_facts WHERE object_index=?`, index))
	if err != nil {
		return Facts{}, 0, err
	}
	facts, err := s.tree.OpenFacts(r)
	if err != nil || !factsCompatible(entry, facts) {
		return Facts{}, 0, ErrInvalid
	}
	id, err := FactsEncryptionID(r)
	if err != nil {
		return Facts{}, 0, err
	}
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, id).Scan(&n); err != nil || n != 1 {
		return Facts{}, 0, ErrInvalid
	}
	return facts, r.Revision, nil
}

// GetFacts authenticates metadata and its tree ancestry. It holds no lease and
// does not enforce visibility or authorize a user; missing facts are not public.
// A future public read must use ReadVisibleObjectWithLease and its other gates.
func (s *SQLStore) GetFacts(ctx context.Context, objectID string) (Facts, int64, error) {
	if !s.valid() || objectID == s.rootID {
		return Facts{}, 0, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Facts{}, 0, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return Facts{}, 0, err
	}
	r, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil {
		return Facts{}, 0, err
	}
	if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
		return Facts{}, 0, err
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, r.ObjectIndex)
	if err != nil {
		return Facts{}, 0, err
	}
	if err = tx.Commit(); err != nil {
		return Facts{}, 0, err
	}
	return facts, revision, nil
}

// SetFacts atomically inserts/replaces a fact row with CAS revision and a new
// permanently reserved encryption identity. It does not itself authorize the
// mutation or update product audit/quota; never use it to bypass those checks.
func (s *SQLStore) SetFacts(ctx context.Context, facts Facts, expectedRevision int64) (int64, error) {
	if !s.valid() || facts.ObjectID == s.rootID || facts.Revocation != nil || facts.S3Deletion != nil || facts.DirectoryDeletion != nil || expectedRevision < 0 || expectedRevision == math.MaxInt64 {
		return 0, ErrInvalid
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return 0, err
	}
	defer release()
	next := expectedRevision + 1
	sealed, err := s.tree.SealFacts(facts, next)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return 0, err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return 0, err
	}
	r, entry, err := s.recordByID(ctx, tx, facts.ObjectID)
	if err != nil {
		return 0, err
	}
	if !factsCompatible(entry, facts) {
		return 0, ErrInvalid
	}
	if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
		return 0, err
	}
	oldFacts, oldRevision, oldErr := s.factsFor(ctx, tx, entry, r.ObjectIndex)
	if facts.InternalPlaceholder || oldErr == nil && oldFacts.InternalPlaceholder {
		return 0, ErrInvalid
	}
	if oldErr == nil && oldFacts.InternalPromotedPlaceholder != facts.InternalPromotedPlaceholder || errors.Is(oldErr, sql.ErrNoRows) && facts.InternalPromotedPlaceholder {
		return 0, ErrConflict
	}
	// A generic facts update cannot manufacture or reuse a previously attested
	// lyric decision after a bind/unbind. Such changes need their own verified
	// operation evidence and atomic mutation path, not yet installed.
	if oldErr == nil && (oldFacts.LyricResolution != nil || facts.LyricResolution != nil) && (!reflect.DeepEqual(oldFacts.LyricResolution, facts.LyricResolution) || !reflect.DeepEqual(oldFacts.Lyric, facts.Lyric) || !reflect.DeepEqual(oldFacts.InternalDefaultLyric, facts.InternalDefaultLyric)) || errors.Is(oldErr, sql.ErrNoRows) && facts.LyricResolution != nil {
		return 0, ErrConflict
	}
	if oldErr == nil && (oldFacts.Revocation != nil || oldFacts.S3Deletion != nil || oldFacts.DirectoryDeletion != nil) {
		return 0, ErrConflict
	}
	// A signed owner tombstone cannot be manufactured, discarded, or used to
	// unhide via the generic facts setter. Re-activation needs a separately
	// authenticated new owner locator and is intentionally not implemented.
	if oldErr == nil && !reflect.DeepEqual(oldFacts.HiddenProof, facts.HiddenProof) || errors.Is(oldErr, sql.ErrNoRows) && facts.HiddenProof != nil {
		return 0, ErrConflict
	}
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?`, r.ObjectIndex).Scan(&pending); err != nil || pending != 0 {
		return 0, ErrInvalid
	}
	if expectedRevision == 0 {
		if !errors.Is(oldErr, sql.ErrNoRows) {
			if oldErr != nil {
				return 0, oldErr
			}
			return 0, ErrConflict
		}
	} else if oldErr != nil || oldRevision != expectedRevision {
		return 0, ErrConflict
	}
	id, err := FactsEncryptionID(sealed)
	if err != nil {
		return 0, err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return 0, err
	}
	if expectedRevision == 0 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_facts(object_index,revision,encryption_id,sealed) VALUES(?,?,?,?)`, sealed.ObjectIndex, sealed.Revision, id, sealed.Sealed); err != nil {
			return 0, ErrConflict
		}
	} else {
		result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, id, sealed.Sealed, sealed.ObjectIndex, expectedRevision)
		if err != nil {
			return 0, err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return 0, ErrConflict
		}
	}
	oldClass := listingHidden
	if oldErr == nil {
		oldClass = listingClass(&oldFacts)
	}
	newClass := listingClass(&facts)
	if oldClass != newClass {
		if err = s.listingRemove(ctx, tx, entry, r, oldClass); err != nil {
			return 0, err
		}
		if err = s.listingAdd(ctx, tx, entry, r, newClass); err != nil {
			return 0, err
		}
	} else {
		// Facts changes invalidate only scopes containing this child; hidden
		// changes must not invalidate the public visible-only continuation.
		if err = s.listingAdjust(ctx, tx, s.listingClassGroup(entry.ParentID, newClass), 0); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}
