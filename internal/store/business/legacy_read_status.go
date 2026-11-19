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

func readLegacyStatus(ctx context.Context, q queryer, v *vault.Vault, index, tag, lock string) (store.LegacyReadStatusIntent, int64, error) {
	var out store.LegacyReadStatusIntent
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
		return store.LegacyReadStatusIntent{}, 0, store.ErrNodeState
	}
	i, t, e := v.LegacyReadIntentIndexes(out.Request.RequestID, out.Request.Challenge)
	if e != nil || i != index || t != tag || out.State == "pending" && (out.Receipt != nil || out.Signature != "") || out.State == "confirmed" && (out.Receipt == nil || out.Signature == "") {
		return store.LegacyReadStatusIntent{}, 0, store.ErrNodeState
	}
	return out, revision, nil
}

func readStatusDrain(ctx context.Context, q queryer, v *vault.Vault, expected store.NodeIdentity, rel store.Relationship, binding, identity, operation, challenge, lock string) (store.LegacyReadDrainIntent, error) {
	i, t, e := v.LegacyReadIntentIndexes(operation, challenge)
	if e != nil {
		return store.LegacyReadDrainIntent{}, store.ErrNodeState
	}
	old, _, e := readLegacyDrain(ctx, q, v, i, t, lock)
	if e != nil || old.OperationID != operation || old.Challenge != challenge || verifyLegacyDrainRecord(ctx, q, v, expected, rel, binding, identity, old, lock) != nil {
		return store.LegacyReadDrainIntent{}, store.ErrNodeState
	}
	if old.State == "confirmed" && verifyLegacyDrainReceipt(rel, old, *old.Receipt, old.Signature) != nil {
		return store.LegacyReadDrainIntent{}, store.ErrNodeState
	}
	return old, nil
}

// BeginLegacyReadStatus stores a new request/challenge before network IO. The
// trusted caller must independently authenticate the administrator. It may
// inspect an expired original drain, but cannot infer that streams drained.
func (r *Repository) BeginLegacyReadStatus(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, relationship, action, originalOperation, originalChallenge, requestID, challenge string, expiresAt int64) (store.LegacyReadStatusIntent, error) {
	var result store.LegacyReadStatusIntent
	if ctx == nil || v == nil || action != "status" && action != "resume" || requestID == originalOperation || challenge == originalChallenge {
		return result, store.ErrNodeState
	}
	index, tag, e := v.LegacyReadIntentIndexes(requestID, challenge)
	if e != nil {
		return result, store.ErrNodeState
	}
	err := r.ingressWrite(ctx, func(q queryer) error {
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
		head, headRevision, e := readLegacyHead(ctx, q, v, relationship, r.lock())
		if e != nil || !validLegacyHead(head, expected, rel, binding, identity) || head.DrainOperation != originalOperation || head.DrainChallenge != originalChallenge {
			return store.ErrNodeState
		}
		reuse := head.StatusRequest == requestID && head.StatusChallenge == challenge
		if head.StatusRequest != "" && !reuse {
			pi, pt, err := v.LegacyReadIntentIndexes(head.StatusRequest, head.StatusChallenge)
			if err != nil {
				return store.ErrNodeState
			}
			previous, _, err := readLegacyStatus(ctx, q, v, pi, pt, r.lock())
			if err != nil || verifyLegacyStatusRecord(ctx, q, v, expected, rel, binding, identity, head, previous, r.lock()) != nil {
				return store.ErrNodeState
			}
			if previous.State == "confirmed" && verifyLegacyStatusReceipt(rel, previous, *previous.Receipt, previous.Signature) != nil {
				return store.ErrNodeState
			}
			if previous.ExpiresAt > now && (previous.State == "pending" || previous.Receipt.State == "revoked") {
				return store.ErrNodeState
			}
		}
		drain, e := readStatusDrain(ctx, q, v, expected, rel, binding, identity, originalOperation, originalChallenge, r.lock())
		if e != nil || head.EnrollmentOperation != drain.EnrollmentOperation || head.EnrollmentChallenge != drain.EnrollmentChallenge {
			return store.ErrNodeState
		}
		req := protocol.LegacyReadStatusRequest{Action: action, RequestID: requestID, Challenge: challenge, OriginalOperationID: originalOperation, OriginalChallenge: originalChallenge, OriginalExpiresAt: drain.ExpiresAt, ExpiresAt: expiresAt, MasterID: drain.MasterID, OwnerID: drain.OwnerID, RelationshipID: drain.RelationshipID, RelationshipBinding: drain.Enrollment.RelationshipBinding, OwnerBinding: drain.Enrollment.OwnerBinding, FenceBinding: drain.Enrollment.FenceBinding}
		if _, e = req.Receipt("revoked"); e != nil {
			return store.ErrNodeState
		}
		want := store.LegacyReadStatusIntent{Version: 1, Request: req, ExpiresAt: expiresAt, MasterIdentity: identity, MasterRelationshipBinding: binding, State: "pending"}
		old, _, e := readLegacyStatus(ctx, q, v, index, tag, r.lock())
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
		head.StatusRequest, head.StatusChallenge = requestID, challenge
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
		return store.LegacyReadStatusIntent{}, err
	}
	return result, nil
}

func verifyLegacyStatusRecord(ctx context.Context, q queryer, v *vault.Vault, expected store.NodeIdentity, rel store.Relationship, binding, identity string, head legacyReadHead, old store.LegacyReadStatusIntent, lock string) error {
	if _, err := old.Request.Receipt("revoked"); err != nil {
		return store.ErrNodeState
	}
	if old.MasterIdentity != identity || old.MasterRelationshipBinding != binding || old.Request.MasterID != expected.ID || old.Request.OwnerID != rel.PeerID || old.Request.RelationshipID != rel.ID {
		return store.ErrNodeState
	}
	drain, e := readStatusDrain(ctx, q, v, expected, rel, binding, identity, old.Request.OriginalOperationID, old.Request.OriginalChallenge, lock)
	if e != nil {
		return e
	}
	if head.DrainOperation != drain.OperationID || head.DrainChallenge != drain.Challenge || head.EnrollmentOperation != drain.EnrollmentOperation || head.EnrollmentChallenge != drain.EnrollmentChallenge || old.Request.OriginalExpiresAt != drain.ExpiresAt || old.Request.ExpiresAt != old.ExpiresAt || old.Request.RelationshipBinding != drain.Enrollment.RelationshipBinding || old.Request.OwnerBinding != drain.Enrollment.OwnerBinding || old.Request.FenceBinding != drain.Enrollment.FenceBinding {
		return store.ErrNodeState
	}
	return nil
}
func verifyLegacyStatusReceipt(rel store.Relationship, old store.LegacyReadStatusIntent, receipt protocol.LegacyReadStatus, signature string) error {
	if old.Request.Action == "resume" && receipt.State != "revoked" {
		return store.ErrNodeState
	}
	want, e := old.Request.Receipt(receipt.State)
	if e != nil || want != receipt {
		return store.ErrNodeState
	}
	payload, e := receipt.Payload()
	if e != nil || protocol.Verify(rel.PublicKey, payload, signature) != nil {
		return store.ErrNodeState
	}
	return nil
}

// ConfirmLegacyReadStatus retains a signed result; an expired or draining
// response is historical only and cannot renew activation authority.
func (r *Repository) ConfirmLegacyReadStatus(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, receipt protocol.LegacyReadStatus, signature string) (store.LegacyReadStatusIntent, error) {
	var result store.LegacyReadStatusIntent
	if ctx == nil || v == nil {
		return result, store.ErrNodeState
	}
	index, tag, e := v.LegacyReadIntentIndexes(receipt.RequestID, receipt.Challenge)
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
		if e != nil || !validLegacyHead(head, expected, rel, binding, identity) || head.StatusRequest != receipt.RequestID || head.StatusChallenge != receipt.Challenge {
			return store.ErrNodeState
		}
		old, revision, e := readLegacyStatus(ctx, q, v, index, tag, r.lock())
		if e != nil || verifyLegacyStatusRecord(ctx, q, v, expected, rel, binding, identity, head, old, r.lock()) != nil || verifyLegacyStatusReceipt(rel, old, receipt, signature) != nil {
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
		return store.LegacyReadStatusIntent{}, err
	}
	return result, nil
}

// RecoverLegacyReadStatus returns fresh only for a currently valid, signed
// revoked observation. It never substitutes for external rollback anchoring.
func (r *Repository) RecoverLegacyReadStatus(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, relationship, requestID, challenge string) (store.LegacyReadStatusIntent, bool, error) {
	var result store.LegacyReadStatusIntent
	if ctx == nil || v == nil {
		return result, false, store.ErrNodeState
	}
	index, tag, e := v.LegacyReadIntentIndexes(requestID, challenge)
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
		if e != nil || !validLegacyHead(head, expected, rel, binding, identity) {
			return store.ErrNodeState
		}
		old, _, e := readLegacyStatus(ctx, q, v, index, tag, r.lock())
		if e != nil || old.Request.RequestID != requestID || old.Request.Challenge != challenge || verifyLegacyStatusRecord(ctx, q, v, expected, rel, binding, identity, head, old, r.lock()) != nil {
			return store.ErrNodeState
		}
		if old.State == "confirmed" && verifyLegacyStatusReceipt(rel, old, *old.Receipt, old.Signature) != nil {
			return store.ErrNodeState
		}
		if ctx.Err() != nil {
			return store.ErrNodeState
		}
		result = old
		fresh = head.StatusRequest == requestID && head.StatusChallenge == challenge && old.State == "confirmed" && old.Receipt.State == "revoked" && time.Now().Unix() < old.ExpiresAt
		return nil
	})
	if err != nil {
		return store.LegacyReadStatusIntent{}, false, err
	}
	return result, fresh, nil
}
