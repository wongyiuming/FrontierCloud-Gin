package opaqueledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// Query is an existing, caller-owned SQL transaction or SQLite immediate
// transaction connection. The verifier neither begins nor commits it.
type Query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type intent struct {
	OperationID string `json:"operation_id"`
	MasterID    string `json:"master_id"`
	MemberID    string `json:"member_id"`
	BlobID      string `json:"blob_id"`
	Digest      string `json:"digest"`
	Bytes       int64  `json:"bytes"`
}
type scope struct {
	OperationID         string `json:"operation_id"`
	Generation          string `json:"generation"`
	StageID             string `json:"stage_id"`
	MasterBinding       string `json:"master_binding"`
	RelationshipID      string `json:"relationship_id"`
	RelationshipBinding string `json:"relationship_binding"`
	PublishChallenge    string `json:"publish_challenge"`
	CleanupChallenge    string `json:"cleanup_challenge"`
	PublishedSignature  string `json:"published_signature,omitempty"`
	CleanupSignature    string `json:"cleanup_signature,omitempty"`
	Settled             bool   `json:"settled,omitempty"`
	CompletionBinding   string `json:"completion_binding,omitempty"`
}
type account struct {
	MemberID string `json:"member_id"`
	Total    int64  `json:"total"`
	Revision int64  `json:"revision"`
}

func keyed(key []byte, domain, value string) string {
	return hex.EncodeToString(MAC(key, domain, []byte(value)))
}

// CompletionBinding is encrypted in the settled scope and binds the fixed
// width tree completion fields without exposing them in the ledger index.
func CompletionBinding(object, blob, completion string) string {
	if !hashID.MatchString(object) || !hashID.MatchString(blob) || !hashID.MatchString(completion) {
		return ""
	}
	h := sha256.New()
	h.Write([]byte("frontiercloud:opaque-capacity:tree-completion:v1\x00" + object + blob + completion))
	return hex.EncodeToString(h.Sum(nil))
}
func decodeRecord(raw []byte, dst any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst) == nil && decoder.Decode(new(any)) == io.EOF
}
func hasID(ctx context.Context, q Query, id, lock string) bool {
	var got string
	return q.QueryRowContext(ctx, `SELECT encryption_id FROM sealed_tree_capacity_ids WHERE encryption_id=?`+lock, id).Scan(&got) == nil && got == id
}

// VerifyPublished reauthenticates a previously recorded owner signature,
// current Master vault identity, exact relationship instance, scope and
// encrypted reservation within the caller's existing SQL transaction. It is
// not source authorization, settlement, publication or proof of physical I/O.
// The only supported lock suffixes are SQLite's empty suffix and MySQL's row
// lock. The caller must hold its owner/tree/ingress fences in the agreed order.
func VerifyPublished(ctx context.Context, q Query, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature, lock string) error {
	return verifyPublished(ctx, q, key, nodeVault, receipt, signature, lock, true)
}

// VerifyCandidate performs the same checks before the first receipt is
// persisted. Any previously recorded signature must still match exactly.
func VerifyCandidate(ctx context.Context, q Query, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature, lock string) error {
	return verifyPublished(ctx, q, key, nodeVault, receipt, signature, lock, false)
}

func verifyPublished(ctx context.Context, q Query, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature, lock string, requireRecorded bool) error {
	if ctx == nil || q == nil || !ValidKey(key) || nodeVault == nil || signature == "" || lock != "" && lock != " FOR UPDATE" || receipt.Kind != "opaque-capacity-published-v1" || receipt.State != "published" {
		return ErrInvalid
	}
	if _, err := receipt.Payload(); err != nil {
		return ErrInvalid
	}
	var verifier string
	expectedVerifier := hex.EncodeToString(MAC(key, "verifier", nil))
	if q.QueryRowContext(ctx, `SELECT verifier FROM sealed_tree_capacity_meta WHERE singleton=1`).Scan(&verifier) != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(expectedVerifier)) != 1 {
		return ErrInvalid
	}
	var identity store.NodeIdentity
	if q.QueryRowContext(ctx, "SELECT node_id,`role`,endpoint,private_key,created_at FROM node_identity WHERE singleton=1"+lock).Scan(&identity.ID, &identity.Role, &identity.Endpoint, &identity.PrivateKey, &identity.CreatedAt) != nil || identity.Role != "Master" || identity.PrivateKey == "" || identity.CreatedAt <= 0 {
		return ErrInvalid
	}
	encoded, err := nodeVault.Unseal(identity.PrivateKey)
	if err != nil {
		return ErrInvalid
	}
	seed, err := protocol.Decode(encoded)
	if err != nil || len(seed) != ed25519.SeedSize {
		clear(seed)
		return ErrInvalid
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	ownerPublic := protocol.Encode(private.Public().(ed25519.PublicKey))
	index := keyed(key, "operation", receipt.OperationID)
	var memberIndex, blobIndex, intentID string
	var sealed []byte
	if q.QueryRowContext(ctx, `SELECT member_index,blob_index,encryption_id,sealed FROM sealed_tree_capacity_intents WHERE operation_index=?`+lock, index).Scan(&memberIndex, &blobIndex, &intentID, &sealed) != nil || !hasID(ctx, q, intentID, lock) {
		return ErrInvalid
	}
	raw, err := Open(key, index, intentID, sealed)
	if err != nil {
		return ErrInvalid
	}
	var in intent
	ok := decodeRecord(raw, &in)
	clear(raw)
	if !ok || in.OperationID != receipt.OperationID || in.MasterID != identity.ID || in.MemberID != receipt.OwnerID || in.BlobID != receipt.BlobID || in.Digest != receipt.Digest || in.Bytes != receipt.Bytes || in.Bytes < 0 || in.Bytes > 10*store.GiB || memberIndex != keyed(key, "member", in.MemberID) || blobIndex != keyed(key, "blob", in.BlobID) {
		return ErrInvalid
	}
	var scopeID string
	if q.QueryRowContext(ctx, `SELECT encryption_id,sealed FROM sealed_tree_capacity_scopes WHERE operation_index=?`+lock, index).Scan(&scopeID, &sealed) != nil || !hasID(ctx, q, scopeID, lock) {
		return ErrInvalid
	}
	raw, err = Open(key, index, scopeID, sealed)
	if err != nil {
		return ErrInvalid
	}
	var sc scope
	ok = decodeRecord(raw, &sc)
	clear(raw)
	bindingBytes, _ := json.Marshal(struct {
		ID      string `json:"id"`
		Sealed  string `json:"sealed_private"`
		Created int64  `json:"created_at"`
	}{identity.ID, identity.PrivateKey, identity.CreatedAt})
	h := sha256.New()
	h.Write([]byte("frontiercloud:sealed-tree:master-instance:v1\x00"))
	h.Write(bindingBytes)
	clear(bindingBytes)
	if !ok || sc.MasterBinding != hex.EncodeToString(h.Sum(nil)) || sc.OperationID != in.OperationID || sc.Generation != receipt.Generation || sc.StageID != receipt.StageID || sc.PublishChallenge != receipt.Challenge || requireRecorded && sc.PublishedSignature != signature || !requireRecorded && sc.PublishedSignature != "" && sc.PublishedSignature != signature || sc.CleanupSignature != "" || !hashID.MatchString(sc.CleanupChallenge) || !hasID(ctx, q, keyed(key, "challenge", sc.PublishChallenge), lock) || !hasID(ctx, q, keyed(key, "challenge", sc.CleanupChallenge), lock) {
		return ErrInvalid
	}
	if sc.Settled {
		var object, blob, completion string
		if !hashID.MatchString(sc.CompletionBinding) || q.QueryRowContext(ctx, `SELECT object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`+lock, in.OperationID).Scan(&object, &blob, &completion) != nil || CompletionBinding(object, blob, completion) != sc.CompletionBinding {
			return ErrInvalid
		}
		for _, table := range []string{"sealed_tree_pending_files", "sealed_tree_pending_facts"} {
			var count int
			if q.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE operation_id=?`, in.OperationID).Scan(&count) != nil || count != 0 {
				return ErrInvalid
			}
		}
	} else if sc.CompletionBinding != "" {
		return ErrInvalid
	}
	var kind string
	var relationship sql.NullString
	var reserved int64
	if q.QueryRowContext(ctx, `SELECT member_kind,relationship_id,reserved_bytes FROM cluster_storage_members WHERE member_id=?`+lock, in.MemberID).Scan(&kind, &relationship, &reserved) != nil {
		return ErrInvalid
	}
	var accountID string
	if q.QueryRowContext(ctx, `SELECT encryption_id,sealed FROM sealed_tree_capacity_accounts WHERE member_index=?`+lock, memberIndex).Scan(&accountID, &sealed) != nil || !hasID(ctx, q, accountID, lock) {
		return ErrInvalid
	}
	raw, err = Open(key, memberIndex, accountID, sealed)
	if err != nil {
		return ErrInvalid
	}
	var a account
	ok = decodeRecord(raw, &a)
	clear(raw)
	if !ok || a.MemberID != in.MemberID || a.Revision <= 0 || a.Total < 0 || !sc.Settled && a.Total < in.Bytes || a.Total > store.MaxStorageAllocation || reserved < a.Total {
		return ErrInvalid
	}
	if in.MemberID == identity.ID {
		if kind != "MasterLocal" || relationship.Valid || sc.RelationshipID != "" || sc.RelationshipBinding != "" {
			return ErrInvalid
		}
	} else {
		if kind != "Follower" || !relationship.Valid || relationship.String != sc.RelationshipID {
			return ErrInvalid
		}
		var peer, pub, endpoint, credential, direction, state string
		var version int
		var created int64
		if q.QueryRowContext(ctx, `SELECT peer_id,peer_key,peer_endpoint,credential,direction,state,protocol,created_at FROM node_relationships WHERE relationship_id=?`+lock, sc.RelationshipID).Scan(&peer, &pub, &endpoint, &credential, &direction, &state, &version, &created) != nil || peer != in.MemberID || direction != "downstream" || state != "active" || version != protocol.Version || endpoint == "" || credential == "" || created <= 0 {
			return ErrInvalid
		}
		binding := store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: peer, RelationshipID: sc.RelationshipID, PublicKey: pub, ControlEndpoint: endpoint, CredentialDigest: store.PeerCredentialDigest(credential), CreatedAt: created})
		if binding != sc.RelationshipBinding {
			return ErrInvalid
		}
		ownerPublic = pub
	}
	if receipt.MasterID != in.MasterID || receipt.RelationshipID != sc.RelationshipID || receipt.RelationshipBinding != sc.RelationshipBinding {
		return ErrInvalid
	}
	payload, err := receipt.Payload()
	if err != nil || protocol.Verify(ownerPublic, payload, signature) != nil {
		return ErrInvalid
	}
	return nil
}
