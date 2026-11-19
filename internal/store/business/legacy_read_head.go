package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type legacyReadHead struct {
	Version             int    `json:"version"`
	MasterID            string `json:"master_id"`
	MasterIdentity      string `json:"master_identity"`
	OwnerID             string `json:"owner_id"`
	RelationshipID      string `json:"relationship_id"`
	MasterBinding       string `json:"master_binding"`
	EnrollmentOperation string `json:"enrollment_operation"`
	EnrollmentChallenge string `json:"enrollment_challenge"`
	DrainOperation      string `json:"drain_operation,omitempty"`
	DrainChallenge      string `json:"drain_challenge,omitempty"`
	StatusRequest       string `json:"status_request,omitempty"`
	StatusChallenge     string `json:"status_challenge,omitempty"`
}

type legacyReadAnchor struct {
	Version        int    `json:"version"`
	MasterID       string `json:"master_id"`
	MasterIdentity string `json:"master_identity"`
	OwnerID        string `json:"owner_id"`
	RelationshipID string `json:"relationship_id"`
	MasterBinding  string `json:"master_binding"`
}

func anchorForHead(h legacyReadHead) legacyReadAnchor {
	return legacyReadAnchor{Version: 1, MasterID: h.MasterID, MasterIdentity: h.MasterIdentity, OwnerID: h.OwnerID, RelationshipID: h.RelationshipID, MasterBinding: h.MasterBinding}
}

func readLegacyAnchor(ctx context.Context, q queryer, v *vault.Vault, relationship, lock string) (legacyReadAnchor, error) {
	var out legacyReadAnchor
	index, tag, e := v.LegacyReadAnchorIndexes(relationship)
	if e != nil {
		return out, store.ErrNodeState
	}
	var actual string
	var nonce, sealed []byte
	var revision int64
	e = q.QueryRowContext(ctx, "SELECT challenge_tag,nonce,revision,sealed FROM legacy_read_control_intents WHERE operation_index=?"+lock, index).Scan(&actual, &nonce, &revision, &sealed)
	if e != nil {
		return out, e
	}
	if actual != tag || revision != 1 {
		return out, store.ErrNodeState
	}
	raw, e := v.OpenLegacyReadIntent(index, tag, revision, nonce, sealed)
	if e != nil {
		return out, store.ErrNodeState
	}
	defer clear(raw)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Version != 1 || out.RelationshipID != relationship {
		return legacyReadAnchor{}, store.ErrNodeState
	}
	return out, nil
}

func readLegacyHead(ctx context.Context, q queryer, v *vault.Vault, relationship, lock string) (legacyReadHead, int64, error) {
	var out legacyReadHead
	anchor, anchorErr := readLegacyAnchor(ctx, q, v, relationship, lock)
	if anchorErr != nil && !errors.Is(anchorErr, sql.ErrNoRows) {
		return out, 0, store.ErrNodeState
	}
	index, tag, e := v.LegacyReadHeadIndexes(relationship)
	if e != nil {
		return out, 0, store.ErrNodeState
	}
	var actual string
	var nonce, sealed []byte
	var revision int64
	e = q.QueryRowContext(ctx, "SELECT challenge_tag,nonce,revision,sealed FROM legacy_read_control_intents WHERE operation_index=?"+lock, index).Scan(&actual, &nonce, &revision, &sealed)
	if e != nil {
		if errors.Is(e, sql.ErrNoRows) && errors.Is(anchorErr, sql.ErrNoRows) {
			return out, 0, sql.ErrNoRows
		}
		return out, 0, store.ErrNodeState
	}
	if anchorErr != nil {
		return out, 0, store.ErrNodeState
	}
	if actual != tag || revision < 1 {
		return out, 0, store.ErrNodeState
	}
	raw, e := v.OpenLegacyReadIntent(index, tag, revision, nonce, sealed)
	if e != nil {
		return out, 0, store.ErrNodeState
	}
	defer clear(raw)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Version != 1 || out.RelationshipID != relationship || !nodeIDPattern.MatchString(out.EnrollmentOperation) || !nodeHashPattern.MatchString(out.EnrollmentChallenge) || (out.DrainOperation == "") != (out.DrainChallenge == "") || (out.StatusRequest == "") != (out.StatusChallenge == "") || out.StatusRequest != "" && out.DrainOperation == "" {
		return legacyReadHead{}, 0, store.ErrNodeState
	}
	if out.DrainOperation != "" && (!nodeIDPattern.MatchString(out.DrainOperation) || !nodeHashPattern.MatchString(out.DrainChallenge)) {
		return legacyReadHead{}, 0, store.ErrNodeState
	}
	if out.StatusRequest != "" && (!nodeIDPattern.MatchString(out.StatusRequest) || !nodeHashPattern.MatchString(out.StatusChallenge)) {
		return legacyReadHead{}, 0, store.ErrNodeState
	}
	if anchorForHead(out) != anchor {
		return legacyReadHead{}, 0, store.ErrNodeState
	}
	return out, revision, nil
}

func saveLegacyHead(ctx context.Context, q queryer, v *vault.Vault, head legacyReadHead, revision int64) error {
	index, tag, e := v.LegacyReadHeadIndexes(head.RelationshipID)
	if e != nil || revision < 0 || revision == int64(^uint64(0)>>1) {
		return store.ErrNodeState
	}
	raw, e := json.Marshal(head)
	if e != nil {
		return e
	}
	defer clear(raw)
	nonce, sealed, e := v.SealLegacyReadIntent(index, tag, revision+1, raw)
	if e != nil {
		return store.ErrNodeState
	}
	if revision == 0 {
		anchorIndex, anchorTag, err := v.LegacyReadAnchorIndexes(head.RelationshipID)
		if err != nil {
			return store.ErrNodeState
		}
		anchorRaw, err := json.Marshal(anchorForHead(head))
		if err != nil {
			return err
		}
		defer clear(anchorRaw)
		anchorNonce, anchorSealed, err := v.SealLegacyReadIntent(anchorIndex, anchorTag, 1, anchorRaw)
		if err != nil {
			return store.ErrNodeState
		}
		if _, err = q.ExecContext(ctx, "INSERT INTO legacy_read_control_intents(operation_index,challenge_tag,nonce,revision,sealed) VALUES(?,?,?,1,?)", anchorIndex, anchorTag, anchorNonce, anchorSealed); err != nil {
			return err
		}
		_, e = q.ExecContext(ctx, "INSERT INTO legacy_read_control_intents(operation_index,challenge_tag,nonce,revision,sealed) VALUES(?,?,?,1,?)", index, tag, nonce, sealed)
		return e
	}
	res, e := q.ExecContext(ctx, "UPDATE legacy_read_control_intents SET nonce=?,revision=?,sealed=? WHERE operation_index=? AND revision=?", nonce, revision+1, sealed, index, revision)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil || n != 1 {
		return store.ErrNodeState
	}
	return nil
}

func validLegacyHead(head legacyReadHead, expected store.NodeIdentity, rel store.Relationship, binding, identity string) bool {
	return head.MasterID == expected.ID && head.MasterIdentity == identity && head.OwnerID == rel.PeerID && head.RelationshipID == rel.ID && head.MasterBinding == binding
}

// CurrentLegacyReadControl resolves only the current encrypted pointer for a
// pair and verifies every linked signature inside one transaction. Its values
// are server-internal, and do not authorize publication or rollback recovery.
func (r *Repository) CurrentLegacyReadControl(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, relationship string) (store.LegacyReadControlCurrent, error) {
	result, found, err := r.FindCurrentLegacyReadControl(ctx, expected, v, relationship)
	if err != nil || !found {
		return store.LegacyReadControlCurrent{}, store.ErrNodeState
	}
	return result, nil
}

// FindCurrentLegacyReadControl distinguishes a truly uninitialized pair from
// a missing half of its sealed anchor/head. Simultaneous rollback/deletion of
// both still requires an independent external anchor and never grants access.
func (r *Repository) FindCurrentLegacyReadControl(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, relationship string) (store.LegacyReadControlCurrent, bool, error) {
	var result store.LegacyReadControlCurrent
	if ctx == nil || v == nil {
		return result, false, store.ErrNodeState
	}
	found := false
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
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil || !validLegacyHead(head, expected, rel, binding, identity) {
			return store.ErrNodeState
		}
		found = true
		i, tag, e := v.LegacyReadIntentIndexes(head.EnrollmentOperation, head.EnrollmentChallenge)
		if e != nil {
			return store.ErrNodeState
		}
		enrollment, _, e := readLegacyEnrollment(ctx, q, v, i, tag, r.lock())
		if e != nil || enrollment.OperationID != head.EnrollmentOperation || enrollment.Challenge != head.EnrollmentChallenge || enrollment.MasterID != expected.ID || enrollment.MasterIdentity != identity || enrollment.OwnerID != rel.PeerID || enrollment.RelationshipID != rel.ID || enrollment.MasterRelationshipBinding != binding {
			return store.ErrNodeState
		}
		if enrollment.State == "confirmed" && verifyLegacyEnrollmentRecord(enrollment, expected, rel, binding, identity) != nil {
			return store.ErrNodeState
		}
		result.Enrollment = enrollment
		if head.DrainOperation != "" {
			drain, e := readStatusDrain(ctx, q, v, expected, rel, binding, identity, head.DrainOperation, head.DrainChallenge, r.lock())
			if e != nil || drain.EnrollmentOperation != head.EnrollmentOperation || drain.EnrollmentChallenge != head.EnrollmentChallenge {
				return store.ErrNodeState
			}
			result.Drain = &drain
		}
		if head.StatusRequest != "" {
			i, tag, e := v.LegacyReadIntentIndexes(head.StatusRequest, head.StatusChallenge)
			if e != nil {
				return store.ErrNodeState
			}
			status, _, e := readLegacyStatus(ctx, q, v, i, tag, r.lock())
			if e != nil || verifyLegacyStatusRecord(ctx, q, v, expected, rel, binding, identity, head, status, r.lock()) != nil {
				return store.ErrNodeState
			}
			if status.Request.RequestID != head.StatusRequest || status.Request.Challenge != head.StatusChallenge || status.Request.OriginalOperationID != head.DrainOperation || status.Request.OriginalChallenge != head.DrainChallenge {
				return store.ErrNodeState
			}
			if status.State == "confirmed" && verifyLegacyStatusReceipt(rel, status, *status.Receipt, status.Signature) != nil {
				return store.ErrNodeState
			}
			result.Status = &status
		}
		if ctx.Err() != nil {
			return store.ErrNodeState
		}
		return nil
	})
	if err != nil {
		return store.LegacyReadControlCurrent{}, false, err
	}
	return result, found, nil
}

// prepareEnrollmentHead permits a new enrollment only before a drain exists,
// and only when the previous enrollment has expired. It never erases history.
func (r *Repository) prepareEnrollmentHead(ctx context.Context, q queryer, v *vault.Vault, expected store.NodeIdentity, rel store.Relationship, binding, identity, operation, challenge string) (legacyReadHead, int64, bool, error) {
	head, revision, e := readLegacyHead(ctx, q, v, rel.ID, r.lock())
	if errors.Is(e, sql.ErrNoRows) {
		return legacyReadHead{Version: 1, MasterID: expected.ID, MasterIdentity: identity, OwnerID: rel.PeerID, RelationshipID: rel.ID, MasterBinding: binding, EnrollmentOperation: operation, EnrollmentChallenge: challenge}, 0, false, nil
	}
	if e != nil || !validLegacyHead(head, expected, rel, binding, identity) {
		return legacyReadHead{}, 0, false, store.ErrNodeState
	}
	if head.EnrollmentOperation == operation && head.EnrollmentChallenge == challenge {
		return head, revision, true, nil
	}
	if head.DrainOperation != "" {
		return legacyReadHead{}, 0, false, store.ErrNodeState
	}
	i, tag, e := v.LegacyReadIntentIndexes(head.EnrollmentOperation, head.EnrollmentChallenge)
	if e != nil {
		return legacyReadHead{}, 0, false, store.ErrNodeState
	}
	previous, _, e := readLegacyEnrollment(ctx, q, v, i, tag, r.lock())
	if e != nil || previous.ExpiresAt > time.Now().Unix() || previous.OperationID != head.EnrollmentOperation || previous.Challenge != head.EnrollmentChallenge || previous.MasterID != expected.ID || previous.MasterIdentity != identity || previous.OwnerID != rel.PeerID || previous.RelationshipID != rel.ID || previous.MasterRelationshipBinding != binding {
		return legacyReadHead{}, 0, false, store.ErrNodeState
	}
	if previous.State == "confirmed" && verifyLegacyEnrollmentRecord(previous, expected, rel, binding, identity) != nil {
		return legacyReadHead{}, 0, false, store.ErrNodeState
	}
	head.EnrollmentOperation, head.EnrollmentChallenge = operation, challenge
	return head, revision, false, nil
}
