package business

// Isolated enrollment-intent persistence. It is not registered in startup,
// and it does not grant publication, prove all streams drained, or prevent
// whole-database rollback. A real activation requires a separately anchored
// recovery protocol and cross-protocol challenge coordination.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type LegacyReadEnrollmentIntent = store.LegacyReadEnrollmentIntent

func legacyEnrollmentIdentity(identity store.NodeIdentity) (string, error) {
	raw, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	sum := sha256.Sum256(append([]byte("frontiercloud:legacy-read:master-identity:v1\x00"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

func legacyEnrollmentRelationship(r store.Relationship) string {
	return store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: r.PeerID, RelationshipID: r.ID, PublicKey: r.PublicKey, ControlEndpoint: r.Endpoint, CredentialDigest: store.PeerCredentialDigest(r.Credential), CreatedAt: r.CreatedAt})
}

func (r *Repository) legacyEnrollmentAuthority(ctx context.Context, q queryer, expected store.NodeIdentity, v *vault.Vault, relationship string) (store.Relationship, string, error) {
	if v == nil || expected.Role != "Master" || !nodeIDPattern.MatchString(expected.ID) || !nodeIDPattern.MatchString(relationship) || !sourcePinVaultMatchesIdentity(v, expected) {
		return store.Relationship{}, "", store.ErrNodeState
	}
	actual, err := readNode(ctx, q, r.lock())
	if err != nil || actual != expected {
		return store.Relationship{}, "", store.ErrNodeState
	}
	rel, err := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), relationship))
	if err != nil || rel.State != "active" || rel.Direction != "downstream" || rel.Protocol != protocol.Version || !nodeIDPattern.MatchString(rel.PeerID) {
		return store.Relationship{}, "", store.ErrNodeState
	}
	binding := legacyEnrollmentRelationship(rel)
	if !nodeHashPattern.MatchString(binding) {
		return store.Relationship{}, "", store.ErrNodeState
	}
	return rel, binding, nil
}

func readLegacyEnrollment(ctx context.Context, q queryer, v *vault.Vault, index, challengeTag, lock string) (LegacyReadEnrollmentIntent, int64, error) {
	var out LegacyReadEnrollmentIntent
	var tag string
	var nonce, sealed []byte
	var revision int64
	err := q.QueryRowContext(ctx, "SELECT challenge_tag,nonce,revision,sealed FROM legacy_read_control_intents WHERE operation_index=?"+lock, index).Scan(&tag, &nonce, &revision, &sealed)
	if err != nil {
		return out, 0, err
	}
	if tag != challengeTag || revision < 1 {
		return out, 0, store.ErrNodeState
	}
	raw, err := v.OpenLegacyReadIntent(index, tag, revision, nonce, sealed)
	if err != nil {
		return out, 0, store.ErrNodeState
	}
	defer clear(raw)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Version != 1 || out.State != "pending" && out.State != "confirmed" {
		return LegacyReadEnrollmentIntent{}, 0, store.ErrNodeState
	}
	operationIndex, actualTag, err := v.LegacyReadIntentIndexes(out.OperationID, out.Challenge)
	if err != nil || operationIndex != index || actualTag != tag || out.State == "pending" && (out.Receipt != nil || out.Signature != "") || out.State == "confirmed" && (out.Receipt == nil || out.Signature == "") {
		return LegacyReadEnrollmentIntent{}, 0, store.ErrNodeState
	}
	return out, revision, nil
}

// BeginLegacyReadEnrollment persists the operation and challenge before any
// network request. The caller generates both independently with CSPRNG. This
// function has a bounded five-minute admission window and holds no network IO.
func (r *Repository) BeginLegacyReadEnrollment(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, relationship, operation, challenge string, expiresAt int64) (LegacyReadEnrollmentIntent, error) {
	var result LegacyReadEnrollmentIntent
	if ctx == nil || v == nil {
		return result, store.ErrNodeState
	}
	index, tag, err := v.LegacyReadIntentIndexes(operation, challenge)
	if err != nil {
		return result, store.ErrNodeState
	}
	err = r.ingressWrite(ctx, func(q queryer) error {
		now := time.Now().Unix()
		if expiresAt <= now || expiresAt > now+300 {
			return store.ErrNodeState
		}
		rel, binding, e := r.legacyEnrollmentAuthority(ctx, q, expected, v, relationship)
		if e != nil {
			return e
		}
		identity, e := legacyEnrollmentIdentity(expected)
		if e != nil {
			return e
		}
		head, headRevision, reuse, e := r.prepareEnrollmentHead(ctx, q, v, expected, rel, binding, identity, operation, challenge)
		if e != nil {
			return e
		}
		want := LegacyReadEnrollmentIntent{Version: 1, OperationID: operation, Challenge: challenge, ExpiresAt: expiresAt, MasterID: expected.ID, MasterIdentity: identity, OwnerID: rel.PeerID, RelationshipID: rel.ID, MasterRelationshipBinding: binding, State: "pending"}
		old, _, e := readLegacyEnrollment(ctx, q, v, index, tag, r.lock())
		if e == nil {
			if !reuse || old.State != "pending" || old != want {
				return store.ErrNodeState
			}
			result = old
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if reuse {
			return store.ErrNodeState
		}
		raw, e := json.Marshal(want)
		if e != nil {
			return e
		}
		defer clear(raw)
		nonce, sealed, e := v.SealLegacyReadIntent(index, tag, 1, raw)
		if e != nil {
			return store.ErrNodeState
		}
		if _, e = q.ExecContext(ctx, "INSERT INTO legacy_read_control_intents(operation_index,challenge_tag,nonce,revision,sealed) VALUES(?,?,?,1,?)", index, tag, nonce, sealed); e != nil {
			return e
		}
		if e = saveLegacyHead(ctx, q, v, head, headRevision); e != nil {
			return e
		}
		if ctx.Err() != nil || time.Now().Unix() >= expiresAt {
			return store.ErrNodeState
		}
		result = want
		return nil
	})
	if err != nil {
		return LegacyReadEnrollmentIntent{}, err
	}
	return result, nil
}

// ConfirmLegacyReadEnrollment revalidates the same Master/pair inside the
// write transaction and verifies the Owner's Ed25519 signature. A durable
// confirmed observation is not an activation permission.
func (r *Repository) ConfirmLegacyReadEnrollment(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, operation string, receipt protocol.LegacyReadEnrollmentReceipt, signature string) (LegacyReadEnrollmentIntent, error) {
	var result LegacyReadEnrollmentIntent
	if ctx == nil || v == nil {
		return result, store.ErrNodeState
	}
	payload, err := receipt.Payload()
	if err != nil {
		return result, store.ErrNodeState
	}
	index, tag, err := v.LegacyReadIntentIndexes(operation, receipt.Challenge)
	if err != nil {
		return result, store.ErrNodeState
	}
	err = r.ingressWrite(ctx, func(q queryer) error {
		rel, binding, e := r.legacyEnrollmentAuthority(ctx, q, expected, v, receipt.RelationshipID)
		if e != nil {
			return e
		}
		identity, e := legacyEnrollmentIdentity(expected)
		if e != nil {
			return e
		}
		head, _, e := readLegacyHead(ctx, q, v, rel.ID, r.lock())
		if e != nil || !validLegacyHead(head, expected, rel, binding, identity) || head.EnrollmentOperation != operation || head.EnrollmentChallenge != receipt.Challenge {
			return store.ErrNodeState
		}
		old, revision, e := readLegacyEnrollment(ctx, q, v, index, tag, r.lock())
		if e != nil {
			return store.ErrNodeState
		}
		if old.OperationID != operation || old.MasterID != expected.ID || old.MasterIdentity != identity || old.OwnerID != rel.PeerID || old.MasterRelationshipBinding != binding || old.ExpiresAt <= time.Now().Unix() || receipt.MasterID != old.MasterID || receipt.OwnerID != old.OwnerID || receipt.RelationshipID != old.RelationshipID || receipt.Challenge != old.Challenge || protocol.Verify(rel.PublicKey, payload, signature) != nil {
			return store.ErrNodeState
		}
		if old.State == "confirmed" {
			if old.Receipt == nil || *old.Receipt != receipt || old.Signature != signature {
				return store.ErrNodeState
			}
			result = old
			return nil
		}
		if revision == int64(^uint64(0)>>1) {
			return store.ErrNodeState
		}
		old.State = "confirmed"
		old.Receipt = &receipt
		old.Signature = signature
		raw, e := json.Marshal(old)
		if e != nil {
			return e
		}
		defer clear(raw)
		nonce, sealed, e := v.SealLegacyReadIntent(index, tag, revision+1, raw)
		if e != nil {
			return store.ErrNodeState
		}
		res, e := q.ExecContext(ctx, "UPDATE legacy_read_control_intents SET nonce=?,revision=?,sealed=? WHERE operation_index=? AND revision=?", nonce, revision+1, sealed, index, revision)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil || n != 1 || ctx.Err() != nil || time.Now().Unix() >= old.ExpiresAt {
			return store.ErrNodeState
		}
		result = old
		return nil
	})
	if err != nil {
		return LegacyReadEnrollmentIntent{}, err
	}
	return result, nil
}

// RecoverLegacyReadEnrollment reopens and re-verifies stored history against
// the current Master identity and pair. fresh is true only for an unexpired
// confirmed receipt; neither value is an activation or rollback-proof authority.
func (r *Repository) RecoverLegacyReadEnrollment(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, relationship, operation, challenge string) (LegacyReadEnrollmentIntent, bool, error) {
	var result LegacyReadEnrollmentIntent
	if ctx == nil || v == nil {
		return result, false, store.ErrNodeState
	}
	index, tag, err := v.LegacyReadIntentIndexes(operation, challenge)
	if err != nil {
		return result, false, store.ErrNodeState
	}
	fresh := false
	err = r.ingressWrite(ctx, func(q queryer) error {
		rel, binding, e := r.legacyEnrollmentAuthority(ctx, q, expected, v, relationship)
		if e != nil {
			return e
		}
		identity, e := legacyEnrollmentIdentity(expected)
		if e != nil {
			return e
		}
		head, _, e := readLegacyHead(ctx, q, v, relationship, r.lock())
		if e != nil || !validLegacyHead(head, expected, rel, binding, identity) {
			return store.ErrNodeState
		}
		old, _, e := readLegacyEnrollment(ctx, q, v, index, tag, r.lock())
		if e != nil {
			return store.ErrNodeState
		}
		if old.OperationID != operation || old.Challenge != challenge || old.MasterID != expected.ID || old.MasterIdentity != identity || old.OwnerID != rel.PeerID || old.RelationshipID != rel.ID || old.MasterRelationshipBinding != binding {
			return store.ErrNodeState
		}
		if old.State == "confirmed" {
			payload, e := old.Receipt.Payload()
			if e != nil || old.Receipt.Challenge != challenge || old.Receipt.MasterID != expected.ID || old.Receipt.OwnerID != rel.PeerID || old.Receipt.RelationshipID != rel.ID || protocol.Verify(rel.PublicKey, payload, old.Signature) != nil {
				return store.ErrNodeState
			}
		}
		if ctx.Err() != nil {
			return store.ErrNodeState
		}
		result = old
		fresh = head.EnrollmentOperation == operation && head.EnrollmentChallenge == challenge && old.State == "confirmed" && time.Now().Unix() < old.ExpiresAt
		return nil
	})
	if err != nil {
		return LegacyReadEnrollmentIntent{}, false, err
	}
	return result, fresh, nil
}
