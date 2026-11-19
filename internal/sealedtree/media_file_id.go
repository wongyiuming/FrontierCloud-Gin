package sealedtree

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

// These transaction primitives are deliberately not connected to key issuance.
// Activation requires trusted backfill of all historical file IDs (including
// retired recording IDs), recovery that invalidates old preparations and
// reconciles Owner/pending state, and an atomic claim with the actual upload
// intent. A reservation alone cannot provide those.
func (s *SQLStore) mediaFileTag(label string, parts ...string) (string, error) {
	if !s.valid() || label == "" {
		return "", ErrInvalid
	}
	h := hmac.New(sha256.New, s.tree.indexKey[:])
	_, _ = h.Write([]byte("frontiercloud:sealed-tree:media-file-id:v1\x00" + label + "\x00"))
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *SQLStore) mediaPreparationTags(meta mediacrypto.Metadata, binding string) (string, string, error) {
	if meta.Validate() != nil || binding == "" || len(binding) > 512 {
		return "", "", ErrInvalid
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return "", "", ErrInvalid
	}
	id, err := s.mediaFileTag("id", meta.FileID)
	if err != nil {
		return "", "", err
	}
	prepared, err := s.mediaFileTag("prepared", meta.FileID, binding, string(raw))
	return id, prepared, err
}

// reserveHistoricalMediaFileIDTx only reserves one validated source ID. It is
// not evidence that a source snapshot was complete and is not idempotent: the
// coordinating importer must authenticate its full snapshot, preserve the writer
// fence and roll back/reconcile its checkpoint together with these insertions.
// Recording and media use the same global ID domain as the legacy schema.
func (s *SQLStore) reserveHistoricalMediaFileIDTx(ctx context.Context, tx treeQuery, fileID string) error {
	raw, err := hex.DecodeString(fileID)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != fileID {
		return ErrInvalid
	}
	tag, err := s.mediaFileTag("id", fileID)
	if err != nil {
		return err
	}
	_, err = reserveID(ctx, tx, tag)
	return err
}

// bindHistoricalSourceTx pins this tree to one authenticated source manifest.
// Both tags are inserted atomically; a different source cannot append even if
// its file IDs do not collide. The caller must authenticate that manifest.
func (s *SQLStore) bindHistoricalSourceTx(ctx context.Context, tx treeQuery, manifest string) error {
	if !hexID(manifest) {
		return ErrInvalid
	}
	singleton, err := s.mediaFileTag("historical-source-bound")
	if err != nil {
		return err
	}
	owner, err := s.mediaFileTag("historical-source-owner", manifest)
	if err != nil {
		return err
	}
	bound, err := mediaTagPresent(ctx, tx, singleton)
	if err != nil {
		return err
	}
	if bound {
		matches, e := mediaTagPresent(ctx, tx, owner)
		if e != nil {
			return e
		}
		if !matches {
			return ErrConflict
		}
		return nil
	}
	if _, err = reserveID(ctx, tx, singleton); err != nil {
		return err
	}
	_, err = reserveID(ctx, tx, owner)
	return err
}

// markHistoricalSourceCompleteTx is called only with a separately verified
// complete-replay proof, never merely because a final batch was submitted.
func (s *SQLStore) markHistoricalSourceCompleteTx(ctx context.Context, tx treeQuery, manifest string, batches uint64, empty bool, finalDigest string) error {
	if !hexID(manifest) || !hexID(finalDigest) || empty && batches != 0 || !empty && batches == 0 {
		return ErrInvalid
	}
	ownerIndex, slotIndex := "empty", "0"
	if !empty {
		ownerIndex = strconv.FormatUint(batches-1, 10)
		slotIndex = ownerIndex
	}
	for _, entry := range []struct {
		label string
		parts []string
	}{
		{"historical-source-bound", nil}, {"historical-source-owner", []string{manifest}},
		{"historical-batch-end", []string{manifest}}, {"historical-batch-end-owner", []string{manifest, ownerIndex, finalDigest}},
	} {
		tag, err := s.mediaFileTag(entry.label, entry.parts...)
		if err != nil {
			return err
		}
		present, err := mediaTagPresent(ctx, tx, tag)
		if err != nil {
			return err
		}
		if !present {
			return ErrConflict
		}
	}
	lastSlot, err := s.mediaFileTag("historical-batch-slot", manifest, slotIndex)
	if err != nil {
		return err
	}
	present, err := mediaTagPresent(ctx, tx, lastSlot)
	if err != nil {
		return err
	}
	if present == empty {
		return ErrConflict
	}
	complete, err := s.mediaFileTag("historical-source-complete")
	if err != nil {
		return err
	}
	owner, err := s.mediaFileTag("historical-source-complete-owner", manifest, strconv.FormatUint(batches, 10), strconv.FormatBool(empty), finalDigest)
	if err != nil {
		return err
	}
	exists, err := mediaTagPresent(ctx, tx, complete)
	if err != nil {
		return err
	}
	if exists {
		matches, e := mediaTagPresent(ctx, tx, owner)
		if e != nil {
			return e
		}
		if !matches {
			return ErrConflict
		}
		return nil
	}
	if _, err = reserveID(ctx, tx, complete); err != nil {
		return err
	}
	_, err = reserveID(ctx, tx, owner)
	return err
}

// historicalSourceCompleteTx checks a trusted expected manifest under the
// caller's read fence. It cannot stand in for pending/Owner recovery checks.
func (s *SQLStore) historicalSourceCompleteTx(ctx context.Context, tx treeQuery, manifest string, batches uint64, empty bool, finalDigest string) (bool, error) {
	if !hexID(manifest) || !hexID(finalDigest) || empty && batches != 0 || !empty && batches == 0 {
		return false, ErrInvalid
	}
	for _, entry := range []struct{ label, value string }{
		{"historical-source-bound", ""}, {"historical-source-owner", manifest},
		{"historical-batch-end", manifest}, {"historical-source-complete", ""},
	} {
		var tag string
		var err error
		if entry.value == "" {
			tag, err = s.mediaFileTag(entry.label)
		} else {
			tag, err = s.mediaFileTag(entry.label, entry.value)
		}
		if err != nil {
			return false, err
		}
		present, err := mediaTagPresent(ctx, tx, tag)
		if err != nil || !present {
			return false, err
		}
	}
	owner, err := s.mediaFileTag("historical-source-complete-owner", manifest, strconv.FormatUint(batches, 10), strconv.FormatBool(empty), finalDigest)
	if err != nil {
		return false, err
	}
	present, err := mediaTagPresent(ctx, tx, owner)
	if err != nil || !present {
		return false, err
	}
	endIndex := "empty"
	if !empty {
		endIndex = strconv.FormatUint(batches-1, 10)
	}
	endOwner, err := s.mediaFileTag("historical-batch-end-owner", manifest, endIndex, finalDigest)
	if err != nil {
		return false, err
	}
	if present, err = mediaTagPresent(ctx, tx, endOwner); err != nil || !present {
		return false, err
	}
	slotIndex := "0"
	if !empty {
		slotIndex = endIndex
	}
	slot, err := s.mediaFileTag("historical-batch-slot", manifest, slotIndex)
	if err != nil {
		return false, err
	}
	present, err = mediaTagPresent(ctx, tx, slot)
	if err != nil || present == empty {
		return false, err
	}
	return true, nil
}

// reserveHistoricalMediaBatchTx is a private target-side checkpoint primitive,
// not source authentication or evidence that backfill is complete. Its caller
// must verify the entire source manifest, stream strictly increasing batches in
// order, authenticate each source frame and commit under the tree writer fence.
// The manifest digest must identify that fully authenticated exact stream.
func (s *SQLStore) reserveHistoricalMediaBatchTx(ctx context.Context, tx treeQuery, manifest string, batch uint64, final bool, digest string, ids []string) error {
	if !hexID(manifest) || !hexID(digest) || len(ids) == 0 || len(ids) > 256 {
		return ErrInvalid
	}
	for i, id := range ids {
		raw, err := hex.DecodeString(id)
		if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != id || i > 0 && ids[i-1] >= id {
			return ErrInvalid
		}
	}
	if err := s.bindHistoricalSourceTx(ctx, tx, manifest); err != nil {
		return err
	}
	index := strconv.FormatUint(batch, 10)
	slot, err := s.mediaFileTag("historical-batch-slot", manifest, index)
	if err != nil {
		return err
	}
	checkpoint, err := s.mediaFileTag("historical-batch", manifest, index, strconv.FormatBool(final), digest, strings.Join(ids, ""))
	if err != nil {
		return err
	}
	end, err := s.mediaFileTag("historical-batch-end", manifest)
	if err != nil {
		return err
	}
	endOwner, err := s.mediaFileTag("historical-batch-end-owner", manifest, index, digest)
	if err != nil {
		return err
	}
	done, err := mediaTagPresent(ctx, tx, slot)
	if err != nil {
		return err
	}
	if done {
		matched, checkErr := mediaTagPresent(ctx, tx, checkpoint)
		if checkErr != nil {
			return checkErr
		}
		if !matched {
			return ErrConflict
		}
		if final {
			for _, tag := range []string{end, endOwner} {
				present, e := mediaTagPresent(ctx, tx, tag)
				if e != nil {
					return e
				}
				if !present {
					return ErrInvalid
				}
			}
		}
		for _, id := range ids {
			tag, e := s.mediaFileTag("id", id)
			if e != nil {
				return e
			}
			present, e := mediaTagPresent(ctx, tx, tag)
			if e != nil {
				return e
			}
			if !present {
				return ErrInvalid
			}
		}
		return nil
	}
	ended, err := mediaTagPresent(ctx, tx, end)
	if err != nil {
		return err
	}
	if ended {
		return ErrConflict
	}
	if batch > 0 {
		previous, e := s.mediaFileTag("historical-batch-slot", manifest, strconv.FormatUint(batch-1, 10))
		if e != nil {
			return e
		}
		present, e := mediaTagPresent(ctx, tx, previous)
		if e != nil {
			return e
		}
		if !present {
			return ErrConflict
		}
	}
	for _, id := range ids {
		if err = s.reserveHistoricalMediaFileIDTx(ctx, tx, id); err != nil {
			return err
		}
	}
	if _, err = reserveID(ctx, tx, slot); err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, checkpoint); err != nil {
		return err
	}
	if final {
		if _, err = reserveID(ctx, tx, end); err != nil {
			return err
		}
		if _, err = reserveID(ctx, tx, endOwner); err != nil {
			return err
		}
		return nil
	}
	return err
}

// completeEmptyHistoricalMediaTx is only for an authenticated source manifest
// whose completed ID section has zero rows; it never proves source emptiness by
// itself. It shares the same terminal tag as nonempty historical imports.
func (s *SQLStore) completeEmptyHistoricalMediaTx(ctx context.Context, tx treeQuery, manifest, digest string) error {
	if !hexID(manifest) || !hexID(digest) {
		return ErrInvalid
	}
	if err := s.bindHistoricalSourceTx(ctx, tx, manifest); err != nil {
		return err
	}
	first, err := s.mediaFileTag("historical-batch-slot", manifest, "0")
	if err != nil {
		return err
	}
	present, err := mediaTagPresent(ctx, tx, first)
	if err != nil {
		return err
	}
	if present {
		return ErrConflict
	}
	end, err := s.mediaFileTag("historical-batch-end", manifest)
	if err != nil {
		return err
	}
	owner, err := s.mediaFileTag("historical-batch-end-owner", manifest, "empty", digest)
	if err != nil {
		return err
	}
	ended, err := mediaTagPresent(ctx, tx, end)
	if err != nil {
		return err
	}
	if ended {
		matched, e := mediaTagPresent(ctx, tx, owner)
		if e != nil {
			return e
		}
		if !matched {
			return ErrConflict
		}
		return nil
	}
	if _, err = reserveID(ctx, tx, end); err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, owner); err != nil {
		return err
	}
	return nil
}

// ApplyHistoricalMediaIDBatch is an internal integration boundary for a trusted
// authenticated-source consumer, not an HTTP-facing authorization API. The
// caller must fully verify the signed source before invoking it and supply a
// short-lived proof check that authenticates the exact IDs and stage identity.
// No completed-import/product readiness signal is produced by this operation.
func (s *SQLStore) ApplyHistoricalMediaIDBatch(ctx context.Context, manifest string, batch uint64, final bool, digest string, ids []string, check func([]string) error) error {
	return s.applyHistoricalMediaIDBatch(ctx, manifest, batch, final, digest, ids, nil, check)
}

// ApplyHistoricalMediaIDBatchGuarded is the target-coordinator variant. guard
// authenticates the actual target identity and maintenance lease from this same
// transaction; it is required both before changes and immediately pre-commit.
func (s *SQLStore) ApplyHistoricalMediaIDBatchGuarded(ctx context.Context, manifest string, batch uint64, final bool, digest string, ids []string, guard func(context.Context, *sql.Tx) error, check func([]string) error) error {
	if guard == nil {
		return ErrInvalid
	}
	return s.applyHistoricalMediaIDBatch(ctx, manifest, batch, final, digest, ids, guard, check)
}

func (s *SQLStore) applyHistoricalMediaIDBatch(ctx context.Context, manifest string, batch uint64, final bool, digest string, ids []string, guard func(context.Context, *sql.Tx) error, check func([]string) error) error {
	if !s.valid() || ctx == nil || check == nil || len(ids) > 256 || len(ids) == 0 && (batch != 0 || !final) {
		return ErrInvalid
	}
	stable := append([]string(nil), ids...)
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
	if guard != nil {
		if err = guard(ctx, tx); err != nil {
			return err
		}
	}
	if len(stable) == 0 {
		err = s.completeEmptyHistoricalMediaTx(ctx, tx, manifest, digest)
	} else {
		err = s.reserveHistoricalMediaBatchTx(ctx, tx, manifest, batch, final, digest, stable)
	}
	if err != nil {
		return err
	}
	if guard != nil {
		if err = guard(ctx, tx); err != nil {
			return err
		}
	}
	// Recheck the source proof last, under the target fence and immediately
	// before commit; a stale/changed stage rolls every write back.
	if err = check(append([]string(nil), stable...)); err != nil {
		return err
	}
	return tx.Commit()
}

// CompleteHistoricalMediaIDs must only receive a live authenticated complete-
// replay proof from the trusted source consumer. It records the ID phase only;
// it does not authorize startup, issuance, or pending/Owner recovery.
func (s *SQLStore) CompleteHistoricalMediaIDs(ctx context.Context, manifest string, batches uint64, empty bool, finalDigest string, check func() error) error {
	return s.completeHistoricalMediaIDs(ctx, manifest, batches, empty, finalDigest, nil, check)
}

// CompleteHistoricalMediaIDsGuarded validates the real target in the exact
// fenced transaction before persisting history completion.
func (s *SQLStore) CompleteHistoricalMediaIDsGuarded(ctx context.Context, manifest string, batches uint64, empty bool, finalDigest string, guard func(context.Context, *sql.Tx) error, check func() error) error {
	if guard == nil {
		return ErrInvalid
	}
	return s.completeHistoricalMediaIDs(ctx, manifest, batches, empty, finalDigest, guard, check)
}

func (s *SQLStore) completeHistoricalMediaIDs(ctx context.Context, manifest string, batches uint64, empty bool, finalDigest string, guard func(context.Context, *sql.Tx) error, check func() error) error {
	if !s.valid() || ctx == nil || check == nil {
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
	if guard != nil {
		if err = guard(ctx, tx); err != nil {
			return err
		}
	}
	if err = s.markHistoricalSourceCompleteTx(ctx, tx, manifest, batches, empty, finalDigest); err != nil {
		return err
	}
	if guard != nil {
		if err = guard(ctx, tx); err != nil {
			return err
		}
	}
	if err = check(); err != nil {
		return err
	}
	return tx.Commit()
}

// reserveMediaPreparationTx must be called under the tree writer fence, before
// a key envelope is returned. A lost response is retired rather than reused.
// Only opaque keyed tags, not metadata, file ID or binding, are persisted.
func (s *SQLStore) reserveMediaPreparationTx(ctx context.Context, tx treeQuery, meta mediacrypto.Metadata, binding string) error {
	id, prepared, err := s.mediaPreparationTags(meta, binding)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return err
	}
	_, err = reserveID(ctx, tx, prepared)
	return err
}

// HistoricalMediaIDScope must be loaded from the trusted completed migration,
// not accepted from a browser or asserted by an arbitrary request.
type HistoricalMediaIDScope struct {
	Manifest    string
	Batches     uint64
	Empty       bool
	FinalDigest string
}

// ReserveMediaPreparation permanently reserves a freshly server-generated
// descriptor before returning its key to a browser. It checks the persisted
// historical-ID phase, while callers must independently hold authenticated
// admission and pending/Owner recovery gates. A later wrapping/response failure
// retires this reservation permanently rather than returning it to the pool.
func (s *SQLStore) ReserveMediaPreparation(ctx context.Context, meta mediacrypto.Metadata, binding string, history HistoricalMediaIDScope) error {
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
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	complete, err := s.historicalSourceCompleteTx(ctx, tx, history.Manifest, history.Batches, history.Empty, history.FinalDigest)
	if err != nil {
		return err
	}
	if !complete {
		return ErrConflict
	}
	if err = s.reserveMediaPreparationTx(ctx, tx, meta, binding); err != nil {
		return err
	}
	return tx.Commit()
}

// ReserveNewMediaPreparation reserves a new upload ID under the same fenced
// SQLite transaction as the encrypted tree. It requires the caller to hold a
// real startup/readiness gate for the fresh data namespace. No legacy scan
// or migration is required. Reservations are permanent.
func (s *SQLStore) ReserveNewMediaPreparation(ctx context.Context, meta mediacrypto.Metadata, binding string) error {
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
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	if err = s.reserveMediaPreparationTx(ctx, tx, meta, binding); err != nil {
		return err
	}
	return tx.Commit()
}

func mediaTagPresent(ctx context.Context, tx treeQuery, id string) (bool, error) {
	var value string
	err := tx.QueryRowContext(ctx, `SELECT encryption_id FROM sealed_tree_encryption_ids WHERE encryption_id=?`, id).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && hmac.Equal([]byte(value), []byte(id)), err
}

// claimMediaPreparationTx permanently binds one preparation to one operation.
// Its caller must first verify the signed, unexpired preparation token, retain
// the writer fence, and insert the matching durable upload intent in this same
// transaction. Retrying the same operation is idempotent; a second is refused.
// A cancellation or deletion must never remove any of these tags.
func (s *SQLStore) claimMediaPreparationTx(ctx context.Context, tx treeQuery, meta mediacrypto.Metadata, binding, operation string) error {
	if !hexID(operation) {
		return ErrInvalid
	}
	id, prepared, err := s.mediaPreparationTags(meta, binding)
	if err != nil {
		return err
	}
	for _, tag := range []string{id, prepared} {
		ok, checkErr := mediaTagPresent(ctx, tx, tag)
		if checkErr != nil {
			return checkErr
		}
		if !ok {
			return ErrConflict
		}
	}
	claimed, err := s.mediaFileTag("claimed", meta.FileID)
	if err != nil {
		return err
	}
	owner, err := s.mediaFileTag("operation", meta.FileID, binding, operation)
	if err != nil {
		return err
	}
	exists, err := mediaTagPresent(ctx, tx, claimed)
	if err != nil {
		return err
	}
	if exists {
		match, checkErr := mediaTagPresent(ctx, tx, owner)
		if checkErr != nil {
			return checkErr
		}
		if !match {
			return ErrConflict
		}
		return nil
	}
	if _, err = reserveID(ctx, tx, claimed); err != nil {
		return err
	}
	_, err = reserveID(ctx, tx, owner)
	return err
}
