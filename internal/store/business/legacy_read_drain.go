package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func readLegacyDrain(ctx context.Context, q queryer, v *vault.Vault, index, tag, lock string) (store.LegacyReadDrainIntent, int64, error) {
	var out store.LegacyReadDrainIntent
	var storedTag string
	var nonce, sealed []byte
	var revision int64
	err := q.QueryRowContext(ctx, "SELECT challenge_tag,nonce,revision,sealed FROM legacy_read_control_intents WHERE operation_index=?"+lock, index).Scan(&storedTag, &nonce, &revision, &sealed)
	if err != nil {
		return out, 0, err
	}
	if storedTag != tag || revision < 1 {
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
		return store.LegacyReadDrainIntent{}, 0, store.ErrNodeState
	}
	i, t, e := v.LegacyReadIntentIndexes(out.OperationID, out.Challenge)
	if e != nil || i != index || t != tag || out.State == "pending" && (out.Receipt != nil || out.Signature != "") || out.State == "confirmed" && (out.Receipt == nil || out.Signature == "") {
		return store.LegacyReadDrainIntent{}, 0, store.ErrNodeState
	}
	return out, revision, nil
}

func verifyLegacyEnrollmentRecord(old LegacyReadEnrollmentIntent, expected store.NodeIdentity, rel store.Relationship, binding, identity string) error {
	if old.State != "confirmed" || old.Receipt == nil || old.MasterID != expected.ID || old.MasterIdentity != identity || old.OwnerID != rel.PeerID || old.RelationshipID != rel.ID || old.MasterRelationshipBinding != binding {
		return store.ErrNodeState
	}
	payload, e := old.Receipt.Payload()
	if e != nil || old.Receipt.MasterID != old.MasterID || old.Receipt.OwnerID != old.OwnerID || old.Receipt.RelationshipID != old.RelationshipID || old.Receipt.Challenge != old.Challenge || protocol.Verify(rel.PublicKey, payload, old.Signature) != nil {
		return store.ErrNodeState
	}
	return nil
}

func readDrainEnrollment(ctx context.Context, q queryer, v *vault.Vault, expected store.NodeIdentity, rel store.Relationship, binding, identity, operation, challenge, lock string) (LegacyReadEnrollmentIntent, error) {
	i, t, e := v.LegacyReadIntentIndexes(operation, challenge)
	if e != nil {
		return LegacyReadEnrollmentIntent{}, store.ErrNodeState
	}
	old, _, e := readLegacyEnrollment(ctx, q, v, i, t, lock)
	if e != nil || old.OperationID != operation || old.Challenge != challenge || verifyLegacyEnrollmentRecord(old, expected, rel, binding, identity) != nil {
		return LegacyReadEnrollmentIntent{}, store.ErrNodeState
	}
	return old, nil
}

// BeginLegacyReadDrain persists a separate operation and challenge, linked to
// the exact currently valid, signed enrollment, before any network call.
func (r *Repository) BeginLegacyReadDrain(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, relationship, enrollmentOperation, enrollmentChallenge, operation, challenge string) (store.LegacyReadDrainIntent, error) {
	var result store.LegacyReadDrainIntent
	if ctx == nil || v == nil || operation == enrollmentOperation || challenge == enrollmentChallenge {
		return result, store.ErrNodeState
	}
	index, tag, err := v.LegacyReadIntentIndexes(operation, challenge)
	if err != nil {
		return result, store.ErrNodeState
	}
	err = r.ingressWrite(ctx, func(q queryer) error {
		rel, binding, e := r.legacyEnrollmentAuthority(ctx, q, expected, v, relationship)
		if e != nil {
			return e
		}
		identity, e := legacyEnrollmentIdentity(expected)
		if e != nil {
			return e
		}
		head, headRevision, e := readLegacyHead(ctx, q, v, relationship, r.lock())
		if e != nil || !validLegacyHead(head, expected, rel, binding, identity) || head.EnrollmentOperation != enrollmentOperation || head.EnrollmentChallenge != enrollmentChallenge {
			return store.ErrNodeState
		}
		reuse := head.DrainOperation == operation && head.DrainChallenge == challenge
		if head.DrainOperation != "" && !reuse {
			return store.ErrNodeState
		}
		enrollment, e := readDrainEnrollment(ctx, q, v, expected, rel, binding, identity, enrollmentOperation, enrollmentChallenge, r.lock())
		if e != nil || time.Now().Unix() >= enrollment.ExpiresAt {
			return store.ErrNodeState
		}
		want := store.LegacyReadDrainIntent{Version: 1, OperationID: operation, Challenge: challenge, ExpiresAt: enrollment.ExpiresAt, EnrollmentOperation: enrollmentOperation, EnrollmentChallenge: enrollmentChallenge, MasterID: expected.ID, MasterIdentity: identity, OwnerID: rel.PeerID, RelationshipID: rel.ID, MasterRelationshipBinding: binding, Enrollment: *enrollment.Receipt, EnrollmentSignature: enrollment.Signature, State: "pending"}
		old, _, e := readLegacyDrain(ctx, q, v, index, tag, r.lock())
		if e == nil {
			if !reuse || !reflect.DeepEqual(old, want) {
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
		head.DrainOperation, head.DrainChallenge = operation, challenge
		if e = saveLegacyHead(ctx, q, v, head, headRevision); e != nil {
			return e
		}
		if ctx.Err() != nil || time.Now().Unix() >= want.ExpiresAt {
			return store.ErrNodeState
		}
		result = want
		return nil
	})
	if err != nil {
		return store.LegacyReadDrainIntent{}, err
	}
	return result, nil
}

func verifyLegacyDrainRecord(ctx context.Context, q queryer, v *vault.Vault, expected store.NodeIdentity, rel store.Relationship, binding, identity string, old store.LegacyReadDrainIntent, lock string) error {
	if old.MasterID != expected.ID || old.MasterIdentity != identity || old.OwnerID != rel.PeerID || old.RelationshipID != rel.ID || old.MasterRelationshipBinding != binding {
		return store.ErrNodeState
	}
	enrollment, e := readDrainEnrollment(ctx, q, v, expected, rel, binding, identity, old.EnrollmentOperation, old.EnrollmentChallenge, lock)
	if e != nil || enrollment.Receipt == nil || *enrollment.Receipt != old.Enrollment || enrollment.Signature != old.EnrollmentSignature || old.ExpiresAt != enrollment.ExpiresAt {
		return store.ErrNodeState
	}
	return nil
}

func verifyLegacyDrainReceipt(rel store.Relationship, old store.LegacyReadDrainIntent, receipt protocol.LegacyReadDrainReceipt, signature string) error {
	payload, e := receipt.Payload()
	enrollment := old.Enrollment
	if e != nil || receipt.OperationID != old.OperationID || receipt.Challenge != old.Challenge || receipt.ExpiresAt != old.ExpiresAt || receipt.MasterID != old.MasterID || receipt.OwnerID != old.OwnerID || receipt.RelationshipID != old.RelationshipID || receipt.RelationshipBinding != enrollment.RelationshipBinding || receipt.OwnerBinding != enrollment.OwnerBinding || receipt.FenceBinding != enrollment.FenceBinding || protocol.Verify(rel.PublicKey, payload, signature) != nil {
		return store.ErrNodeState
	}
	return nil
}

// ConfirmLegacyReadDrain records the exact Owner-signed terminal observation.
// A late response may be retained as history but cannot renew expired authority.
func (r *Repository) ConfirmLegacyReadDrain(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, operation string, receipt protocol.LegacyReadDrainReceipt, signature string) (store.LegacyReadDrainIntent, error) {
	var result store.LegacyReadDrainIntent
	if ctx == nil || v == nil {
		return result, store.ErrNodeState
	}
	index, tag, e := v.LegacyReadIntentIndexes(operation, receipt.Challenge)
	if e != nil {
		return result, store.ErrNodeState
	}
	err := r.ingressWrite(ctx, func(q queryer) error {
		rel, binding, e := r.legacyEnrollmentAuthority(ctx, q, expected, v, receipt.RelationshipID)
		if e != nil {
			return e
		}
		identity, e := legacyEnrollmentIdentity(expected)
		if e != nil {
			return e
		}
		head, _, e := readLegacyHead(ctx, q, v, rel.ID, r.lock())
		if e != nil || !validLegacyHead(head, expected, rel, binding, identity) || head.DrainOperation != operation || head.DrainChallenge != receipt.Challenge {
			return store.ErrNodeState
		}
		old, revision, e := readLegacyDrain(ctx, q, v, index, tag, r.lock())
		if e != nil || old.OperationID != operation || head.EnrollmentOperation != old.EnrollmentOperation || head.EnrollmentChallenge != old.EnrollmentChallenge || verifyLegacyDrainRecord(ctx, q, v, expected, rel, binding, identity, old, r.lock()) != nil || verifyLegacyDrainReceipt(rel, old, receipt, signature) != nil {
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
		if e != nil || n != 1 || ctx.Err() != nil {
			return store.ErrNodeState
		}
		result = old
		return nil
	})
	if err != nil {
		return store.LegacyReadDrainIntent{}, err
	}
	return result, nil
}

// RecoverLegacyReadDrain verifies both signed records and the current pair.
// fresh is false after the original deadline and never replaces a new status
// authorization or an external anti-rollback anchor.
func (r *Repository) RecoverLegacyReadDrain(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, relationship, operation, challenge string) (store.LegacyReadDrainIntent, bool, error) {
	var result store.LegacyReadDrainIntent
	if ctx == nil || v == nil {
		return result, false, store.ErrNodeState
	}
	index, tag, e := v.LegacyReadIntentIndexes(operation, challenge)
	if e != nil {
		return result, false, store.ErrNodeState
	}
	fresh := false
	err := r.ingressWrite(ctx, func(q queryer) error {
		rel, binding, e := r.legacyEnrollmentAuthority(ctx, q, expected, v, relationship)
		if e != nil {
			return e
		}
		identity, e := legacyEnrollmentIdentity(expected)
		if e != nil {
			return e
		}
		head, _, e := readLegacyHead(ctx, q, v, relationship, r.lock())
		if e != nil || !validLegacyHead(head, expected, rel, binding, identity) || head.DrainOperation != operation || head.DrainChallenge != challenge {
			return store.ErrNodeState
		}
		old, _, e := readLegacyDrain(ctx, q, v, index, tag, r.lock())
		if e != nil || old.OperationID != operation || old.Challenge != challenge || head.EnrollmentOperation != old.EnrollmentOperation || head.EnrollmentChallenge != old.EnrollmentChallenge || verifyLegacyDrainRecord(ctx, q, v, expected, rel, binding, identity, old, r.lock()) != nil {
			return store.ErrNodeState
		}
		if old.State == "confirmed" && verifyLegacyDrainReceipt(rel, old, *old.Receipt, old.Signature) != nil {
			return store.ErrNodeState
		}
		if ctx.Err() != nil {
			return store.ErrNodeState
		}
		result = old
		fresh = old.State == "confirmed" && time.Now().Unix() < old.ExpiresAt
		return nil
	})
	if err != nil {
		return store.LegacyReadDrainIntent{}, false, err
	}
	return result, fresh, nil
}
