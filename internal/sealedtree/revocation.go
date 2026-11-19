package sealedtree

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func revocationReceipt(intent RevocationIntent) protocol.OpaqueRevocationReceipt {
	return protocol.OpaqueRevocationReceipt{Kind: "opaque-alias-revoke-v1", OperationID: intent.OperationID, MasterID: intent.MasterID, OwnerID: intent.OwnerID, RelationshipID: intent.RelationshipID, Alias: intent.Alias, Blob: intent.BlobID, Revision: intent.Revision, State: "revoked"}
}

func deletionReceipt(intent RevocationIntent) protocol.OpaqueDeletionReceipt {
	receipt := revocationReceipt(intent)
	receipt.Kind, receipt.State = "opaque-blob-delete-v1", "deleted"
	receipt.PublicationOperation = intent.FollowerPublication
	return protocol.OpaqueDeletionReceipt(receipt)
}

// pairedOwnerKey is read inside the same SQLite transaction as the intent
// mutation. A caller-provided public key is never a trust anchor.
func pairedOwnerKey(ctx context.Context, tx treeQuery, intent RevocationIntent) (string, string, string, error) {
	masterBinding, err := revocationMasterBinding(ctx, tx, intent.MasterID)
	if err != nil {
		return "", "", "", err
	}
	var peer, key, endpoint, credential, direction, state string
	var version int
	var createdAt int64
	if err := tx.QueryRowContext(ctx, `SELECT peer_id,peer_key,peer_endpoint,credential,direction,state,protocol,created_at FROM node_relationships WHERE relationship_id=?`, intent.RelationshipID).Scan(&peer, &key, &endpoint, &credential, &direction, &state, &version, &createdAt); err != nil || peer != intent.OwnerID || direction != "downstream" || state != "active" || version != protocol.Version || endpoint == "" || credential == "" || createdAt <= 0 {
		return "", "", "", ErrInvalid
	}
	raw, err := protocol.Decode(key)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return "", "", "", ErrInvalid
	}
	binding := store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: peer, RelationshipID: intent.RelationshipID, PublicKey: key, ControlEndpoint: endpoint, CredentialDigest: store.PeerCredentialDigest(credential), CreatedAt: createdAt})
	return key, binding, masterBinding, nil
}

func revocationMasterBinding(ctx context.Context, tx treeQuery, expectedID string) (string, error) {
	var master, role, sealedPrivate string
	var masterCreatedAt int64
	if err := tx.QueryRowContext(ctx, "SELECT node_id,`role`,private_key,created_at FROM node_identity WHERE singleton=1").Scan(&master, &role, &sealedPrivate, &masterCreatedAt); err != nil || role != "Master" || master != expectedID || sealedPrivate == "" || masterCreatedAt <= 0 {
		return "", ErrInvalid
	}
	// This instance digest is retained only in encrypted tree facts. It detects
	// ordinary identity replacement, not restoration of an identical old state.
	identity, err := json.Marshal(struct {
		ID            string `json:"id"`
		SealedPrivate string `json:"sealed_private"`
		CreatedAt     int64  `json:"created_at"`
	}{master, sealedPrivate, masterCreatedAt})
	if err != nil {
		return "", ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:sealed-tree:master-instance:v1\x00"))
	_, _ = h.Write(identity)
	clear(identity)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *SQLStore) revocationReservation(op string) (string, error) {
	if !lowerHex(op, 32) {
		return "", ErrInvalid
	}
	sum := sha256.Sum256([]byte("frontiercloud:sealed-tree:revoke-reservation:v1\x00" + op))
	return s.tree.BlobIndex(hex.EncodeToString(sum[:]))
}

func (s *SQLStore) verifyRevocation(ctx context.Context, tx treeQuery, intent *RevocationIntent, placement Placement) error {
	if intent == nil || intent.OwnerID != placement.OwnerID || intent.Alias != placement.ReadAlias || intent.BlobID != placement.BlobID {
		return ErrInvalid
	}
	revision, err := protocol.OpaquePlacementRevision(placement.ReadAlias, placement.BlobID, placement.SHA256, placement.Bytes, placement.Encryption)
	if err != nil || intent.Revision != revision {
		return ErrInvalid
	}
	index, err := s.revocationReservation(intent.OperationID)
	if err != nil {
		return ErrInvalid
	}
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, index).Scan(&n); err != nil || n != 1 {
		return ErrInvalid
	}
	objectIndex, err := s.tree.ObjectIndex(placement.ObjectID)
	if err != nil {
		return ErrInvalid
	}
	var stored string
	if err = tx.QueryRowContext(ctx, `SELECT object_index FROM sealed_tree_revocations WHERE operation_index=?`, index).Scan(&stored); err != nil || stored != objectIndex {
		return ErrInvalid
	}
	if intent.LocalDelete {
		return s.verifyMasterLocalDeleteIntent(ctx, tx, intent, placement)
	}
	if intent.SelectedDelete && s.verifyCompletedNativePublication(ctx, tx, placement.ObjectID, placement.BlobID, intent.FollowerPublication) != nil {
		return ErrInvalid
	}
	key, binding, masterBinding, keyErr := pairedOwnerKey(ctx, tx, *intent)
	if keyErr != nil || !hmac.Equal([]byte(binding), []byte(intent.RelationshipBinding)) || !hmac.Equal([]byte(masterBinding), []byte(intent.MasterBinding)) {
		return ErrInvalid
	}
	if intent.OwnerSignature != "" {
		payload, payloadErr := revocationReceipt(*intent).Payload()
		if payloadErr != nil || !hmac.Equal([]byte(key), []byte(intent.OwnerPublicKey)) || protocol.Verify(key, payload, intent.OwnerSignature) != nil {
			return ErrInvalid
		}
		if intent.DeletionSignature != "" {
			deletion, deletionErr := deletionReceipt(*intent).Payload()
			if deletionErr != nil || !hmac.Equal([]byte(key), []byte(intent.DeletionPublicKey)) || protocol.Verify(key, deletion, intent.DeletionSignature) != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}

// Reject before contacting an owner if the existing fixed-size encrypted
// facts cannot hold the worst-case signed acknowledgements and hide result.
// A future version must support larger legacy facts without truncating them.
func preflightRevocationFacts(facts Facts, intent RevocationIntent) error {
	proof := intent
	proof.OwnerPublicKey, proof.OwnerSignature = strings.Repeat("A", 128), strings.Repeat("A", 128)
	if intent.Action == "delete" {
		proof.DeletionPublicKey, proof.DeletionSignature = strings.Repeat("A", 128), strings.Repeat("A", 128)
	}
	candidate := facts
	candidate.Revocation = &proof
	raw, err := json.Marshal(candidate)
	defer clear(raw)
	if err != nil || len(raw) > factsPayloadBytes-2 {
		return ErrInvalid
	}
	if intent.Action == "hide" {
		candidate.Revocation = nil
		candidate.HiddenProof = &proof
		// Any valid 128-byte timestamp can expand sixfold under JSON escaping.
		candidate.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: strings.Repeat("\x01", 128)}
		hiddenRaw, e := json.Marshal(candidate)
		defer clear(hiddenRaw)
		if e != nil || len(hiddenRaw) > factsPayloadBytes-2 {
			return ErrInvalid
		}
	}
	return nil
}

// BeginOpaqueRevocation durably stops this Master from issuing new visible
// reads before an owner is contacted. It does NOT revoke previously issued
// owner grants or authorize deletion/migration. A caller must independently
// authenticate the user and the Master/relationship binding. No production
// route is installed. A retry with the same binding returns the original
// operation after a lost response. There is intentionally no local cancel or
// completion until owner-pinned acknowledgement and crash-safe protocol exist.
func (s *SQLStore) BeginOpaqueRevocation(ctx context.Context, objectID, masterID, relationshipID, action string, expectedFactsRevision, expectedPlacementRevision int64) (RevocationIntent, error) {
	if !s.valid() || ctx == nil || !hexID(objectID) || objectID == s.rootID || !lowerHex(masterID, 32) || !lowerHex(relationshipID, 32) || (action != "delete" && action != "migrate" && action != "hide") || expectedFactsRevision < 1 || expectedFactsRevision == math.MaxInt64 || expectedPlacementRevision < 1 {
		return RevocationIntent{}, ErrInvalid
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return RevocationIntent{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RevocationIntent{}, err
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return RevocationIntent{}, err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return RevocationIntent{}, err
	}
	record, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil || entry.Kind == "directory" || s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID) != nil {
		return RevocationIntent{}, ErrInvalid
	}
	placementRow, err := scanPlacement(tx.QueryRowContext(ctx, `SELECT object_index,blob_index,revision,encryption_id,sealed FROM sealed_tree_placements WHERE object_index=?`, record.ObjectIndex))
	if err != nil || placementRow.Revision != expectedPlacementRevision {
		return RevocationIntent{}, ErrConflict
	}
	placement, err := s.placementFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil || placement.State != "active" {
		return RevocationIntent{}, ErrInvalid
	}
	facts, factRevision, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return RevocationIntent{}, ErrInvalid
	}
	if facts.Revocation != nil {
		intent := *facts.Revocation
		if intent.MasterID != masterID || intent.RelationshipID != relationshipID || intent.Action != action || s.verifyRevocation(ctx, tx, &intent, placement) != nil {
			return RevocationIntent{}, ErrConflict
		}
		return intent, nil // rollback the transient writer-generation increment
	}
	if factRevision != expectedFactsRevision || factRevision == math.MaxInt64 {
		return RevocationIntent{}, ErrConflict
	}
	intent, err := s.beginOpaqueRevocationTx(ctx, tx, entry, record, facts, factRevision, placement, masterID, relationshipID, action, "")
	if err != nil {
		return RevocationIntent{}, err
	}
	if err = tx.Commit(); err != nil {
		return RevocationIntent{}, err
	}
	return intent, nil
}

// The caller holds the tree writer and has authenticated the file and its
// placement in this same transaction.
func (s *SQLStore) beginOpaqueRevocationTx(ctx context.Context, tx treeQuery, entry Entry, record Record, facts Facts, factRevision int64, placement Placement, masterID, relationshipID, action, selectedOperation string) (RevocationIntent, error) {
	if facts.Revocation != nil || facts.HiddenProof != nil || factRevision == math.MaxInt64 {
		return RevocationIntent{}, ErrConflict
	}
	_, binding, masterBinding, err := pairedOwnerKey(ctx, tx, RevocationIntent{MasterID: masterID, OwnerID: placement.OwnerID, RelationshipID: relationshipID})
	if err != nil {
		return RevocationIntent{}, ErrInvalid
	}
	operation := selectedOperation
	if operation == "" {
		raw, err := NewBlobID()
		if err != nil {
			return RevocationIntent{}, err
		}
		operation = raw[:32]
	}
	revision, err := protocol.OpaquePlacementRevision(placement.ReadAlias, placement.BlobID, placement.SHA256, placement.Bytes, placement.Encryption)
	if err != nil {
		return RevocationIntent{}, ErrInvalid
	}
	intent := RevocationIntent{OperationID: operation, MasterID: masterID, MasterBinding: masterBinding, OwnerID: placement.OwnerID, RelationshipID: relationshipID, RelationshipBinding: binding, Alias: placement.ReadAlias, BlobID: placement.BlobID, Revision: revision, Action: action, SelectedDelete: selectedOperation != ""}
	if intent.SelectedDelete {
		intent.FollowerPublication, err = s.completedNativePublicationOperation(ctx, tx, entry.ObjectID, placement.BlobID)
		if err != nil {
			return RevocationIntent{}, err
		}
	}
	if err = preflightRevocationFacts(facts, intent); err != nil {
		return RevocationIntent{}, err
	}
	if err = s.writeRevocationTx(ctx, tx, entry, record, facts, factRevision, intent); err != nil {
		return RevocationIntent{}, err
	}
	return intent, nil
}

func (s *SQLStore) writeRevocationTx(ctx context.Context, tx treeQuery, entry Entry, record Record, facts Facts, factRevision int64, intent RevocationIntent) error {
	if facts.Revocation != nil || facts.HiddenProof != nil || factRevision == math.MaxInt64 {
		return ErrConflict
	}
	oldClass := listingClass(&facts)
	facts.Revocation = &intent
	sealed, err := s.tree.SealFacts(facts, factRevision+1)
	if err != nil {
		return err
	}
	encID, err := FactsEncryptionID(sealed)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, encID); err != nil {
		return err
	}
	operationIndex, err := s.revocationReservation(intent.OperationID)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, operationIndex); err != nil {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_revocations(operation_index,object_index) VALUES(?,?)`, operationIndex, sealed.ObjectIndex); err != nil {
		return ErrConflict
	}
	updated, err := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, encID, sealed.Sealed, sealed.ObjectIndex, factRevision)
	if err != nil {
		return ErrConflict
	}
	if n, countErr := updated.RowsAffected(); countErr != nil || n != 1 {
		return ErrConflict
	}
	if nextClass := listingClass(&facts); oldClass != nextClass {
		if err = s.listingRemove(ctx, tx, entry, record, oldClass); err != nil {
			return err
		}
		if err = s.listingAdd(ctx, tx, entry, record, nextClass); err != nil {
			return err
		}
	}
	return nil
}

// RecordOpaqueRevocationAck independently verifies the exact owner receipt
// against the currently pinned active relationship inside the same SQLite
// write transaction, then encrypts the original signature and public key with
// the pending facts. It does not remove the pending intent, delete a blob,
// migrate ownership or authorize a new alias. Until those transactions and
// cross-node recovery exist, all new reads and Moves remain blocked.
func (s *SQLStore) RecordOpaqueRevocationAck(ctx context.Context, objectID string, receipt protocol.OpaqueRevocationReceipt, signature string) error {
	if !s.valid() || ctx == nil || !hexID(objectID) || objectID == s.rootID || signature == "" {
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
	if err != nil || facts.Revocation == nil || revision == math.MaxInt64 || s.verifyRevocation(ctx, tx, facts.Revocation, placement) != nil {
		return ErrInvalid
	}
	intent := facts.Revocation
	if receipt != revocationReceipt(*intent) {
		return ErrInvalid
	}
	key, binding, masterBinding, err := pairedOwnerKey(ctx, tx, *intent)
	if err != nil || !hmac.Equal([]byte(binding), []byte(intent.RelationshipBinding)) || !hmac.Equal([]byte(masterBinding), []byte(intent.MasterBinding)) {
		return ErrInvalid
	}
	payload, err := receipt.Payload()
	if err != nil || protocol.Verify(key, payload, signature) != nil {
		return ErrInvalid
	}
	if intent.OwnerSignature != "" {
		if !hmac.Equal([]byte(intent.OwnerSignature), []byte(signature)) || !hmac.Equal([]byte(intent.OwnerPublicKey), []byte(key)) {
			return ErrConflict
		}
		return nil // already committed; roll back the transient fence increment
	}
	intent.OwnerPublicKey, intent.OwnerSignature = key, signature
	sealed, err := s.tree.SealFacts(facts, revision+1)
	if err != nil {
		return err
	}
	encID, err := FactsEncryptionID(sealed)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, encID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, encID, sealed.Sealed, sealed.ObjectIndex, revision)
	if err != nil {
		return ErrConflict
	}
	if n, countErr := result.RowsAffected(); countErr != nil || n != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

// RecordOpaqueDeletionReceipt verifies and persists the second, distinct owner
// signature only after a valid revoked receipt was committed. It does not
// itself delete any Master record, update quota/lyrics, complete the operation
// or reopen access. The owner-side journal and actual delete route are not yet
// wired, so this method must not be exposed by the production runtime.
func (s *SQLStore) RecordOpaqueDeletionReceipt(ctx context.Context, objectID string, receipt protocol.OpaqueDeletionReceipt, signature string) error {
	if !s.valid() || ctx == nil || !hexID(objectID) || objectID == s.rootID || signature == "" {
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
	if err != nil || facts.Revocation == nil || facts.Revocation.Action != "delete" || facts.Revocation.OwnerSignature == "" || revision == math.MaxInt64 || s.verifyRevocation(ctx, tx, facts.Revocation, placement) != nil {
		return ErrInvalid
	}
	intent := facts.Revocation
	if receipt != deletionReceipt(*intent) {
		return ErrInvalid
	}
	key, binding, masterBinding, err := pairedOwnerKey(ctx, tx, *intent)
	if err != nil || !hmac.Equal([]byte(binding), []byte(intent.RelationshipBinding)) || !hmac.Equal([]byte(masterBinding), []byte(intent.MasterBinding)) {
		return ErrInvalid
	}
	payload, err := receipt.Payload()
	if err != nil || protocol.Verify(key, payload, signature) != nil {
		return ErrInvalid
	}
	if intent.DeletionSignature != "" {
		if !hmac.Equal([]byte(intent.DeletionSignature), []byte(signature)) || !hmac.Equal([]byte(intent.DeletionPublicKey), []byte(key)) {
			return ErrConflict
		}
		return nil
	}
	intent.DeletionPublicKey, intent.DeletionSignature = key, signature
	sealed, err := s.tree.SealFacts(facts, revision+1)
	if err != nil {
		return err
	}
	encID, err := FactsEncryptionID(sealed)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, encID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, encID, sealed.Sealed, sealed.ObjectIndex, revision)
	if err != nil {
		return ErrConflict
	}
	if n, countErr := result.RowsAffected(); countErr != nil || n != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

// RecoverOpaqueRevocationWithLease retrieves a single authenticated pending
// intent after restart. It does not verify an owner acknowledgement or prove
// external revocation. Retain the lease only for reading; release it before
// contacting the owner or beginning a future exclusive mutation.
func (s *SQLStore) RecoverOpaqueRevocationWithLease(ctx context.Context, lease *TreeLease, objectID string) (RevocationIntent, bool, error) {
	if !s.valid() || ctx == nil || lease == nil || !hexID(objectID) || objectID == s.rootID {
		return RevocationIntent{}, false, ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return RevocationIntent{}, false, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return RevocationIntent{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RevocationIntent{}, false, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return RevocationIntent{}, false, err
	}
	record, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil || entry.Kind == "directory" || s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID) != nil {
		return RevocationIntent{}, false, ErrInvalid
	}
	placement, err := s.placementFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return RevocationIntent{}, false, ErrInvalid
	}
	facts, _, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return RevocationIntent{}, false, ErrInvalid
	}
	var result RevocationIntent
	found := facts.Revocation != nil
	if found {
		result = *facts.Revocation
		if err = s.verifyRevocation(ctx, tx, &result, placement); err != nil {
			return RevocationIntent{}, false, err
		}
	} else {
		var pending int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?`, record.ObjectIndex).Scan(&pending); err != nil || pending != 0 {
			return RevocationIntent{}, false, ErrInvalid
		}
	}
	if err = tx.Commit(); err != nil {
		return RevocationIntent{}, false, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return RevocationIntent{}, false, err
	}
	return result, found, nil
}

// PendingRevocation is sensitive Master-only recovery state. It is neither an
// owner acknowledgement nor authority to remove a file.
type PendingRevocation struct {
	ObjectID  string
	Intent    RevocationIntent
	s3        *S3MediaDeletion
	s3Path    string
	local     string
	directory *store.SelectedMediaDeleteTarget
}

// RecoverOpaqueRevocationByOperationWithLease uses the keyed operation index
// to recover an exact pending intent without scanning. Absence is not proof
// that an operation was never completed or that a database was not rolled
// back. The returned state never substitutes for independently verifying the
// paired owner or the user's authorization.
func (s *SQLStore) RecoverOpaqueRevocationByOperationWithLease(ctx context.Context, lease *TreeLease, operationID string) (PendingRevocation, bool, error) {
	if !s.valid() || ctx == nil || lease == nil || !lowerHex(operationID, 32) {
		return PendingRevocation{}, false, ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return PendingRevocation{}, false, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return PendingRevocation{}, false, err
	}
	index, err := s.revocationReservation(operationID)
	if err != nil {
		return PendingRevocation{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return PendingRevocation{}, false, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return PendingRevocation{}, false, err
	}
	var objectIndex string
	err = tx.QueryRowContext(ctx, `SELECT object_index FROM sealed_tree_revocations WHERE operation_index=?`, index).Scan(&objectIndex)
	if err != nil && err != sql.ErrNoRows {
		return PendingRevocation{}, false, err
	}
	found := err == nil
	var result PendingRevocation
	if found {
		record, readErr := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE object_index=?`, objectIndex))
		if readErr != nil {
			return PendingRevocation{}, false, ErrInvalid
		}
		entry, readErr := s.tree.OpenRecord(record)
		if readErr != nil || entry.Kind == "directory" || s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID) != nil {
			return PendingRevocation{}, false, ErrInvalid
		}
		placement, readErr := s.placementFor(ctx, tx, entry, record.ObjectIndex)
		if readErr != nil {
			return PendingRevocation{}, false, ErrInvalid
		}
		facts, _, readErr := s.factsFor(ctx, tx, entry, record.ObjectIndex)
		if readErr != nil || facts.Revocation == nil || facts.Revocation.OperationID != operationID || s.verifyRevocation(ctx, tx, facts.Revocation, placement) != nil {
			return PendingRevocation{}, false, ErrInvalid
		}
		result = PendingRevocation{ObjectID: entry.ObjectID, Intent: *facts.Revocation}
	}
	if err = tx.Commit(); err != nil {
		return PendingRevocation{}, false, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return PendingRevocation{}, false, err
	}
	return result, found, nil
}

// ListOpaqueRevocationsWithLease incrementally reads the keyed pending index,
// authenticates each encrypted intent and verifies its placement binding. The
// cursor is a keyed index and must stay private. A page from a new lease is
// not one snapshot with prior pages; repeat a full pass after concurrent writes.
// Release the lease before network I/O or exclusive mutations.
func (s *SQLStore) ListOpaqueRevocationsWithLease(ctx context.Context, lease *TreeLease, after string, limit int) ([]PendingRevocation, string, error) {
	return s.listPendingRevocationsWithLease(ctx, lease, after, limit, pendingFollowerRevocation)
}

func (s *SQLStore) ListS3MediaDeletionsWithLease(ctx context.Context, lease *TreeLease, after string, limit int) ([]PendingS3MediaDeletion, string, error) {
	rows, next, err := s.listPendingRevocationsWithLease(ctx, lease, after, limit, pendingS3Deletion)
	if err != nil {
		return nil, "", err
	}
	pending := make([]PendingS3MediaDeletion, 0, len(rows))
	for _, row := range rows {
		pending = append(pending, PendingS3MediaDeletion{ObjectID: row.ObjectID, Path: row.s3Path, Intent: *row.s3})
	}
	return pending, next, nil
}

type pendingRevocationKind int

const (
	pendingFollowerRevocation pendingRevocationKind = iota
	pendingS3Deletion
	pendingMasterLocalDeletion
	pendingDirectoryDeletion
)

func (s *SQLStore) listPendingRevocationsWithLease(ctx context.Context, lease *TreeLease, after string, limit int, kind pendingRevocationKind) ([]PendingRevocation, string, error) {
	if !s.valid() || ctx == nil || lease == nil || (after != "" && !hexID(after)) || limit < 1 || limit > 64 {
		return nil, "", ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return nil, "", ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return nil, "", err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return nil, "", err
	}
	rows, err := tx.QueryContext(ctx, `SELECT operation_index,object_index FROM sealed_tree_revocations WHERE operation_index>? ORDER BY operation_index LIMIT ?`, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	type pair struct{ operation, object string }
	pairs := make([]pair, 0, limit+1)
	for rows.Next() {
		var v pair
		if err = rows.Scan(&v.operation, &v.object); err != nil || !hexID(v.operation) || !hexID(v.object) || v.operation <= after || (len(pairs) != 0 && v.operation <= pairs[len(pairs)-1].operation) {
			rows.Close()
			return nil, "", ErrInvalid
		}
		pairs = append(pairs, v)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, "", err
	}
	if err = rows.Close(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(pairs) > limit {
		pairs = pairs[:limit]
		next = pairs[len(pairs)-1].operation
	}
	result := make([]PendingRevocation, 0, len(pairs))
	for _, v := range pairs {
		record, readErr := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE object_index=?`, v.object))
		if readErr != nil {
			return nil, "", ErrInvalid
		}
		entry, readErr := s.tree.OpenRecord(record)
		if readErr != nil || s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID) != nil {
			return nil, "", ErrInvalid
		}
		facts, _, readErr := s.factsFor(ctx, tx, entry, record.ObjectIndex)
		if readErr != nil {
			return nil, "", ErrInvalid
		}
		if entry.Kind == "directory" {
			target, err := s.verifyDirectoryDeleteIntent(ctx, tx, entry, record, facts)
			if err != nil || s.directoryDeleteIndex(record.ObjectIndex, target.OperationID) != v.operation {
				return nil, "", ErrInvalid
			}
			if kind == pendingDirectoryDeletion {
				result = append(result, PendingRevocation{ObjectID: entry.ObjectID, directory: &target})
			}
			continue
		}
		if kind == pendingDirectoryDeletion {
			continue
		}
		if intent := facts.S3Deletion; intent != nil {
			if s.s3MediaDeletionIndex(record.ObjectIndex, *intent) != v.operation {
				return nil, "", ErrInvalid
			}
			if kind != pendingS3Deletion {
				continue
			}
			placement, id, err := s.s3DeletionPlacement(ctx, tx, record, entry)
			if err != nil || s.verifyS3MediaDeletion(ctx, tx, record, intent, placement, id) != nil {
				return nil, "", ErrInvalid
			}
			path, err := s.pathInTransaction(ctx, tx, entry)
			if err != nil {
				return nil, "", ErrInvalid
			}
			result = append(result, PendingRevocation{ObjectID: entry.ObjectID, s3: intent, s3Path: path})
			continue
		}
		if facts.Revocation == nil {
			return nil, "", ErrInvalid
		}
		if kind == pendingS3Deletion || facts.Revocation.LocalDelete != (kind == pendingMasterLocalDeletion) {
			// Validate physical owner authority only in its own worker.
			continue
		}
		placement, readErr := s.placementFor(ctx, tx, entry, record.ObjectIndex)
		if readErr != nil || s.verifyRevocation(ctx, tx, facts.Revocation, placement) != nil {
			return nil, "", ErrInvalid
		}
		actual, readErr := s.revocationReservation(facts.Revocation.OperationID)
		if readErr != nil || actual != v.operation {
			return nil, "", ErrInvalid
		}
		item := PendingRevocation{ObjectID: entry.ObjectID, Intent: *facts.Revocation}
		if kind == pendingMasterLocalDeletion {
			name, err := s.pathInTransaction(ctx, tx, entry)
			if err != nil || facts.Revocation.OperationID != s.masterLocalMediaDeleteOperation(entry.ObjectID, name) {
				return nil, "", ErrConflict
			}
			item.local = name
		}
		result = append(result, item)
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return nil, "", err
	}
	return result, next, nil
}
