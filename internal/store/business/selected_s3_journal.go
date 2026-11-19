package business

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// selectedS3Intent is trusted Master state, authenticated against the same
// selected reservation in the caller's transaction. Provider upload IDs can
// be 2048 bytes, so this record uses its own fixed-size, domain-separated
// envelope instead of the smaller opaque capacity record.
type selectedS3Intent struct {
	OperationID         string               `json:"op"`
	UploadID            string               `json:"upload"`
	MemberID            string               `json:"member"`
	ObjectID            string               `json:"object"`
	BlobID              string               `json:"blob"`
	Key                 string               `json:"key"`
	Owner               string               `json:"owner"`
	ProviderUploadID    string               `json:"provider_upload,omitempty"`
	ProviderProof       store.S3ObjectProof  `json:"proof"`
	ProofRecorded       bool                 `json:"proof_recorded"`
	CancellationBinding string               `json:"cancel_binding,omitempty"`
	LocationBinding     string               `json:"location"`
	CredentialRevision  int64                `json:"credential_revision"`
	CreatedAt           int64                `json:"created_at"`
	GrantUntil          int64                `json:"grant_until"`
	Bytes               int64                `json:"bytes"`
	Digest              string               `json:"digest"`
	PartCommitment      string               `json:"part_commitment"`
	Encryption          mediacrypto.Metadata `json:"encryption"`
	Phase               string               `json:"phase"`
	State               string               `json:"state"`
	Revision            int64                `json:"revision"`
}

const selectedS3IntentBytes = 8192

// selectedS3MemberBinding is computed inside the reservation transaction from
// the current Master-owned configuration, never from a browser request.
func selectedS3MemberBinding(key []byte, member store.S3Member, now int64) (string, error) {
	if !validCapacityKey(key) || !nodeIDPattern.MatchString(member.ID) || member.Kind != "S3" || member.Transport != "S3" || member.RelationshipID != nil || member.Enabled == 0 || member.Writable == 0 || member.Health != "online" || member.Draining || member.CleanupOnly || member.SealedCredentials == "" || member.Revision < 1 || member.CredentialRevision < 1 || member.ProbeState != "ready" || member.ProbeRevision != member.Revision || member.CredentialExpiresAt != 0 && member.CredentialExpiresAt <= now {
		return "", store.ErrNodeState
	}
	return selectedS3MemberIdentityBinding(key, member)
}

// Identity binding does not depend on transient probe/health state, allowing
// a restart to re-probe only the exact configuration already committed.
func selectedS3MemberIdentityBinding(key []byte, member store.S3Member) (string, error) {
	if !validCapacityKey(key) || !nodeIDPattern.MatchString(member.ID) || member.Kind != "S3" || member.Transport != "S3" || member.RelationshipID != nil || member.SealedCredentials == "" || member.Revision < 1 || member.CredentialRevision < 1 {
		return "", store.ErrNodeState
	}
	location := s3store.Config{Endpoint: member.Location.Endpoint, Bucket: member.Location.Bucket, Region: member.Location.Region, Prefix: member.Location.Prefix, AddressStyle: member.Location.Style}
	normalized, err := s3store.Normalize(location)
	if err != nil || normalized != location {
		return "", store.ErrNodeState
	}
	namespace, err := location.Namespace()
	if err != nil {
		return "", store.ErrNodeState
	}
	raw, err := json.Marshal(struct {
		Member             string            `json:"member"`
		Namespace          s3store.Namespace `json:"namespace"`
		Location           s3store.Config    `json:"location"`
		Credential         string            `json:"credential"`
		Revision           int64             `json:"revision"`
		CredentialRevision int64             `json:"credential_revision"`
	}{member.ID, namespace, location, member.SealedCredentials, member.Revision, member.CredentialRevision})
	if err != nil {
		return "", store.ErrNodeState
	}
	defer clear(raw)
	return hex.EncodeToString(capacityMAC(key, "selected-s3-member-binding", raw)), nil
}

func selectedS3Text(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, ch := range s {
		if ch < 33 || ch > 126 {
			return false
		}
	}
	return true
}

func validSelectedS3Intent(v selectedS3Intent) bool {
	if !validSelectedS3Commitment(v.Bytes, v.PartCommitment) {
		return false
	}
	if !nodeHashPattern.MatchString(v.OperationID) || !nodeIDPattern.MatchString(v.UploadID) || !nodeIDPattern.MatchString(v.MemberID) || !nodeHashPattern.MatchString(v.ObjectID) || !nodeHashPattern.MatchString(v.BlobID) || !nodeHashPattern.MatchString(v.Digest) || !nodeHashPattern.MatchString(v.LocationBinding) || v.OperationID == v.BlobID || v.ObjectID == v.BlobID || v.CredentialRevision < 1 || v.CreatedAt <= 0 || v.GrantUntil < 0 || v.Revision < 1 || v.Bytes < 1 || v.Bytes > store.S3MaxObjectBytes || v.Encryption.Validate() != nil || v.Encryption.CiphertextSize != v.Bytes || !selectedS3Text(v.ProviderUploadID, 2048) {
		return false
	}
	physical, ok := store.S3OpaqueOwner(v.Key)
	if !ok || physical != v.BlobID || !store.ValidS3MetadataIdentity(store.S3OpaqueMetadata, v.Key, v.Owner, v.ObjectID, v.ObjectID) || v.Owner == v.OperationID {
		return false
	}
	if v.ProofRecorded {
		p := v.ProviderProof
		if v.Phase != "completed" || p.MetadataFormat != store.S3OpaqueMetadata || p.MetadataOwner != v.Owner || p.Key != v.Key || p.SessionID != v.UploadID || p.MemberID != v.MemberID || p.MediaID != v.ObjectID || p.ObjectID != v.ObjectID || p.Bytes != v.Bytes || p.ETag == "" || len(p.ETag) > 128 || len(p.VersionID) > 1024 || p.CompositeSHA256 != v.PartCommitment {
			return false
		}
	} else if v.ProviderProof != (store.S3ObjectProof{}) {
		return false
	}
	if v.State == "cancelled" {
		if !nodeHashPattern.MatchString(v.CancellationBinding) {
			return false
		}
	} else if v.CancellationBinding != "" {
		return false
	}
	switch v.Phase {
	case "reserved", "creating", "create_unknown":
		if v.State != "pending" || v.ProviderUploadID != "" {
			return false
		}
	case "uploading", "completing", "aborting":
		if v.State != "pending" || v.ProviderUploadID == "" {
			return false
		}
	case "completed":
		if v.State != "completed" || v.ProviderUploadID == "" || !v.ProofRecorded {
			return false
		}
	case "cancelled":
		if v.State != "cancelled" {
			return false
		}
	default:
		return false
	}
	return true
}

func selectedS3RecordAAD(index, encryptionID string) []byte {
	return []byte("frontiercloud:selected-s3-intent:v1\x00" + index + ":" + encryptionID)
}

func sealSelectedS3Intent(key []byte, index string, value selectedS3Intent) (string, []byte, error) {
	if !validCapacityKey(key) || !nodeHashPattern.MatchString(index) || !validSelectedS3Intent(value) || index != opaqueCapacityIndex(key, value.OperationID) {
		return "", nil, store.ErrNodeState
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > selectedS3IntentBytes-2 {
		return "", nil, store.ErrNodeState
	}
	defer clear(raw)
	plain := make([]byte, selectedS3IntentBytes)
	defer clear(plain)
	binary.BigEndian.PutUint16(plain[:2], uint16(len(raw)))
	copy(plain[2:], raw)
	random := make([]byte, 44)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return "", nil, err
	}
	derived := capacityMAC(key, "selected-s3-intent-cipher", random[:32])
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return "", nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}
	id := hex.EncodeToString(capacityMAC(key, "selected-s3-intent-encryption-id", random))
	sealed := append([]byte{1}, random...)
	sealed = aead.Seal(sealed, random[32:], plain, selectedS3RecordAAD(index, id))
	return id, sealed, nil
}

func openSelectedS3Intent(key []byte, index, id string, sealed []byte) (selectedS3Intent, error) {
	var value selectedS3Intent
	if !validCapacityKey(key) || !nodeHashPattern.MatchString(index) || !nodeHashPattern.MatchString(id) || len(sealed) != 1+44+selectedS3IntentBytes+16 || sealed[0] != 1 {
		return value, store.ErrNodeState
	}
	random := sealed[1:45]
	expected := hex.EncodeToString(capacityMAC(key, "selected-s3-intent-encryption-id", random))
	if !hmac.Equal([]byte(id), []byte(expected)) {
		return value, store.ErrNodeState
	}
	derived := capacityMAC(key, "selected-s3-intent-cipher", random[:32])
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return value, store.ErrNodeState
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return value, store.ErrNodeState
	}
	plain, err := aead.Open(nil, random[32:], sealed[45:], selectedS3RecordAAD(index, id))
	if err != nil {
		return value, store.ErrNodeState
	}
	defer clear(plain)
	n := int(binary.BigEndian.Uint16(plain[:2]))
	if n == 0 || n > len(plain)-2 {
		return value, store.ErrNodeState
	}
	for _, b := range plain[n+2:] {
		if b != 0 {
			return value, store.ErrNodeState
		}
	}
	dec := json.NewDecoder(bytes.NewReader(plain[2 : 2+n]))
	dec.DisallowUnknownFields()
	if dec.Decode(&value) != nil || dec.Decode(new(any)) != io.EOF || !validSelectedS3Intent(value) || opaqueCapacityIndex(key, value.OperationID) != index {
		return selectedS3Intent{}, store.ErrNodeState
	}
	return value, nil
}

// readSelectedS3IntentTx only decodes a journal. Its caller must also verify
// the selected reservation, current member configuration and tree pending
// binding within this same transaction before using the result.
func (r *Repository) readSelectedS3IntentTx(ctx context.Context, q queryer, key []byte, operation string) (selectedS3Intent, bool, error) {
	var zero selectedS3Intent
	if ctx == nil || q == nil || !validCapacityKey(key) || !nodeHashPattern.MatchString(operation) {
		return zero, false, store.ErrNodeState
	}
	index := opaqueCapacityIndex(key, operation)
	var id, state string
	var sealed []byte
	err := q.QueryRowContext(ctx, `SELECT encryption_id,sealed,state FROM selected_s3_uploads WHERE operation_index=?`+r.lock(), index).Scan(&id, &sealed, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil || !capacityIDExists(ctx, q, id, r.lock()) {
		return zero, false, store.ErrNodeState
	}
	value, err := openSelectedS3Intent(key, index, id, sealed)
	if err != nil || value.OperationID != operation || value.State != state {
		return zero, false, store.ErrNodeState
	}
	return value, true, nil
}

func selectedS3Transition(old, next selectedS3Intent) bool {
	if next.Revision != old.Revision+1 || old.State != "pending" {
		return false
	}
	a, b := old, next
	a.ProviderUploadID, b.ProviderUploadID = "", ""
	a.GrantUntil, b.GrantUntil = 0, 0
	a.ProviderProof, b.ProviderProof, a.ProofRecorded, b.ProofRecorded = store.S3ObjectProof{}, store.S3ObjectProof{}, false, false
	a.CancellationBinding, b.CancellationBinding = "", ""
	a.Phase, b.Phase, a.State, b.State, a.Revision, b.Revision = "", "", "", "", 0, 0
	if a != b || next.GrantUntil < old.GrantUntil || next.GrantUntil != old.GrantUntil && !(old.Phase == "uploading" && next.Phase == "uploading") || old.ProviderUploadID != "" && old.ProviderUploadID != next.ProviderUploadID {
		return false
	}
	switch old.Phase {
	case "reserved":
		return next.Phase == "creating" || next.Phase == "cancelled"
	case "creating":
		return next.Phase == "uploading" || next.Phase == "create_unknown"
	case "create_unknown":
		return next.Phase == "uploading" || next.Phase == "cancelled"
	case "uploading":
		return next.Phase == "uploading" && next.GrantUntil > old.GrantUntil || next.Phase == "completing" || next.Phase == "aborting"
	case "completing":
		return next.Phase == "completed" || next.Phase == "aborting"
	case "aborting":
		return next.Phase == "cancelled"
	}
	return false
}

// writeSelectedS3IntentTx must be called in the same Owner -> ingress -> tree
// fenced SQL transaction as the selected reservation. check authenticates the
// durable selected intent, pending placement and any provider transition
// evidence; it must reject unproven completion/absence. This helper itself
// never performs network I/O or commits a transaction.
func (r *Repository) writeSelectedS3IntentTx(ctx context.Context, q queryer, key []byte, value selectedS3Intent, check func(context.Context, queryer, selectedS3Intent, bool) error) error {
	if check == nil || !validSelectedS3Intent(value) {
		return store.ErrNodeState
	}
	old, found, err := r.readSelectedS3IntentTx(ctx, q, key, value.OperationID)
	if err != nil {
		return err
	}
	if found {
		if !selectedS3Transition(old, value) {
			return store.ErrNodeState
		}
	} else if value.Revision != 1 || value.Phase != "reserved" || value.State != "pending" {
		return store.ErrNodeState
	}
	if err = check(ctx, q, old, found); err != nil {
		return err
	}
	index := opaqueCapacityIndex(key, value.OperationID)
	id, sealed, err := sealSelectedS3Intent(key, index, value)
	if err != nil {
		return err
	}
	if _, err = q.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, id); err != nil {
		return store.ErrNodeState
	}
	var result sql.Result
	if found {
		var oldID string
		if err = q.QueryRowContext(ctx, `SELECT encryption_id FROM selected_s3_uploads WHERE operation_index=?`+r.lock(), index).Scan(&oldID); err != nil {
			return store.ErrNodeState
		}
		result, err = q.ExecContext(ctx, `UPDATE selected_s3_uploads SET encryption_id=?,sealed=?,state=? WHERE operation_index=? AND encryption_id=? AND state=?`, id, sealed, value.State, index, oldID, old.State)
	} else {
		result, err = q.ExecContext(ctx, `INSERT INTO selected_s3_uploads(operation_index,encryption_id,sealed,state) VALUES(?,?,?,?)`, index, id, sealed, value.State)
	}
	if err != nil {
		return store.ErrNodeState
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return store.ErrNodeState
	}
	return nil
}

// ensureSelectedS3ReservationTx pins the random provider key and owner marker
// before any network operation, in the same transaction as the selected tree
// pending record and capacity reservation. A retry only reuses the old values.
func (r *Repository) ensureSelectedS3ReservationTx(ctx context.Context, q queryer, key []byte, selected selectedOpaqueIntent, pending sealedtree.SelectedPending, create bool, commitments ...[]string) (selectedS3Intent, error) {
	var zero selectedS3Intent
	if selected.Policy != "S3" || !validSelectedOwnerBinding(selected) || verifySelectedPendingBinding(key, selected, pending) != nil || pending.Placement.Encryption == nil {
		return zero, store.ErrNodeState
	}
	member, err := r.s3Member(ctx, q, selected.Capacity.MemberID, r.lock())
	if err != nil || member.Revision != selected.Revision {
		return zero, store.ErrNodeState
	}
	binding, err := selectedS3MemberBinding(key, member, time.Now().Unix())
	if err != nil || binding != selected.RelationshipBinding {
		return zero, store.ErrNodeState
	}
	old, found, err := r.readSelectedS3IntentTx(ctx, q, key, pending.OperationID)
	if err != nil {
		return zero, err
	}
	if found {
		if len(commitments) > 1 {
			return zero, store.ErrNodeState
		}
		if len(commitments) == 1 {
			commitment, e := selectedS3Commitment(pending.Placement.Bytes, commitments[0])
			if e != nil || commitment != old.PartCommitment {
				return zero, store.ErrNodeState
			}
		}
		if create || old.State != "pending" || old.UploadID != selected.UploadID || old.MemberID != selected.Capacity.MemberID || old.ObjectID != pending.ObjectID || old.BlobID != pending.Placement.BlobID || old.Bytes != pending.Placement.Bytes || old.Digest != pending.Placement.SHA256 || old.Encryption != *pending.Placement.Encryption || old.LocationBinding != binding || old.CredentialRevision != member.CredentialRevision {
			return zero, store.ErrNodeState
		}
		return old, nil
	}
	if !create {
		return zero, store.ErrNodeState
	}
	if len(commitments) != 1 {
		return zero, store.ErrNodeState
	}
	commitment, err := selectedS3Commitment(pending.Placement.Bytes, commitments[0])
	if err != nil {
		return zero, err
	}
	owner, err := randomID()
	if err != nil {
		return zero, err
	}
	blob := pending.Placement.BlobID
	value := selectedS3Intent{OperationID: pending.OperationID, UploadID: selected.UploadID, MemberID: member.ID, ObjectID: pending.ObjectID, BlobID: blob, Key: "objects/" + blob[:2] + "/" + blob[2:4] + "/" + blob + ".blob", Owner: owner, LocationBinding: binding, CredentialRevision: member.CredentialRevision, CreatedAt: time.Now().Unix(), Bytes: pending.Placement.Bytes, Digest: pending.Placement.SHA256, PartCommitment: commitment, Encryption: *pending.Placement.Encryption, Phase: "reserved", State: "pending", Revision: 1}
	err = r.writeSelectedS3IntentTx(ctx, q, key, value, func(_ context.Context, _ queryer, _ selectedS3Intent, exists bool) error {
		if exists {
			return store.ErrNodeState
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	if err = r.precommitSelectedS3PartsTx(ctx, q, key, value, commitments[0]); err != nil {
		return zero, err
	}
	return value, nil
}
