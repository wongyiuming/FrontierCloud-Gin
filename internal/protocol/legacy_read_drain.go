package protocol

import "errors"

const LegacyReadDrainPath = "/internal/v1/opaque-control/legacy-read-drain"
const LegacyReadEnrollmentPath = "/internal/v1/opaque-control/legacy-read-enrollment"
const LegacyReadStatusPath = "/internal/v1/opaque-control/legacy-read-status"

type LegacyReadStatusRequest struct {
	Action              string `json:"action"`
	RequestID           string `json:"request_id"`
	Challenge           string `json:"challenge"`
	OriginalOperationID string `json:"original_operation_id"`
	OriginalChallenge   string `json:"original_challenge"`
	OriginalExpiresAt   int64  `json:"original_expires_at"`
	ExpiresAt           int64  `json:"expires_at"`
	MasterID            string `json:"master_id"`
	OwnerID             string `json:"owner_id"`
	RelationshipID      string `json:"relationship_id"`
	RelationshipBinding string `json:"relationship_binding"`
	OwnerBinding        string `json:"owner_binding"`
	FenceBinding        string `json:"fence_binding"`
}

func (r LegacyReadStatusRequest) Receipt(state string) (LegacyReadStatus, error) {
	result := LegacyReadStatus{Kind: "legacy-media-status-v1", Action: r.Action, RequestID: r.RequestID, Challenge: r.Challenge, OriginalOperationID: r.OriginalOperationID, OriginalChallenge: r.OriginalChallenge, OriginalExpiresAt: r.OriginalExpiresAt, ExpiresAt: r.ExpiresAt, MasterID: r.MasterID, OwnerID: r.OwnerID, RelationshipID: r.RelationshipID, RelationshipBinding: r.RelationshipBinding, OwnerBinding: r.OwnerBinding, FenceBinding: r.FenceBinding, State: state}
	_, err := result.Payload()
	return result, err
}

type LegacyReadStatus struct {
	Kind                string `json:"kind"`
	Action              string `json:"action"`
	RequestID           string `json:"request_id"`
	Challenge           string `json:"challenge"`
	OriginalOperationID string `json:"original_operation_id"`
	OriginalChallenge   string `json:"original_challenge"`
	OriginalExpiresAt   int64  `json:"original_expires_at"`
	ExpiresAt           int64  `json:"expires_at"`
	MasterID            string `json:"master_id"`
	OwnerID             string `json:"owner_id"`
	RelationshipID      string `json:"relationship_id"`
	RelationshipBinding string `json:"relationship_binding"`
	OwnerBinding        string `json:"owner_binding"`
	FenceBinding        string `json:"fence_binding"`
	State               string `json:"state"`
}

func (r LegacyReadStatus) Payload() (map[string]any, error) {
	if r.Kind != "legacy-media-status-v1" || r.Action != "status" && r.Action != "resume" || r.State != "draining" && r.State != "revoked" || r.Action == "resume" && r.State != "revoked" || r.OriginalExpiresAt <= 0 || r.ExpiresAt <= 0 || !identifier.MatchString(r.RequestID) || !identifier.MatchString(r.OriginalOperationID) || r.RequestID == r.OriginalOperationID || !objectID.MatchString(r.Challenge) || !objectID.MatchString(r.OriginalChallenge) || r.Challenge == r.OriginalChallenge || !identifier.MatchString(r.MasterID) || !identifier.MatchString(r.OwnerID) || !identifier.MatchString(r.RelationshipID) || !objectID.MatchString(r.RelationshipBinding) || !objectID.MatchString(r.OwnerBinding) || !objectID.MatchString(r.FenceBinding) {
		return nil, errors.New("invalid legacy read status")
	}
	return map[string]any{"kind": r.Kind, "action": r.Action, "request_id": r.RequestID, "challenge": r.Challenge, "original_operation_id": r.OriginalOperationID, "original_challenge": r.OriginalChallenge, "original_expires_at": r.OriginalExpiresAt, "expires_at": r.ExpiresAt, "master_id": r.MasterID, "owner_id": r.OwnerID, "relationship_id": r.RelationshipID, "relationship_binding": r.RelationshipBinding, "owner_binding": r.OwnerBinding, "fence_binding": r.FenceBinding, "state": r.State}, nil
}

type LegacyReadEnrollmentRequest struct {
	RelationshipID string `json:"relationship_id"`
	Challenge      string `json:"challenge"`
}

func (r LegacyReadEnrollmentRequest) Valid() bool {
	return identifier.MatchString(r.RelationshipID) && objectID.MatchString(r.Challenge)
}

// The owner, not Master, computes these local vault and relationship digests.
// Master must authenticate and persist the exact signed scope before drain.
type LegacyReadEnrollmentReceipt struct {
	Kind                string `json:"kind"`
	Challenge           string `json:"challenge"`
	MasterID            string `json:"master_id"`
	OwnerID             string `json:"owner_id"`
	RelationshipID      string `json:"relationship_id"`
	RelationshipBinding string `json:"relationship_binding"`
	OwnerBinding        string `json:"owner_binding"`
	FenceBinding        string `json:"fence_binding"`
	State               string `json:"state"`
}

func (r LegacyReadEnrollmentReceipt) Payload() (map[string]any, error) {
	if r.Kind != "legacy-media-enrollment-v1" || r.State != "active" || !objectID.MatchString(r.Challenge) || !identifier.MatchString(r.MasterID) || !identifier.MatchString(r.OwnerID) || !identifier.MatchString(r.RelationshipID) || !objectID.MatchString(r.RelationshipBinding) || !objectID.MatchString(r.OwnerBinding) || !objectID.MatchString(r.FenceBinding) {
		return nil, errors.New("invalid legacy read enrollment receipt")
	}
	return map[string]any{"kind": r.Kind, "challenge": r.Challenge, "master_id": r.MasterID, "owner_id": r.OwnerID, "relationship_id": r.RelationshipID, "relationship_binding": r.RelationshipBinding, "owner_binding": r.OwnerBinding, "fence_binding": r.FenceBinding, "state": r.State}, nil
}

// LegacyReadDrainReceipt is only evidence about cooperating, locally fenced
// Go readers for the exact owner and operation. It is not proof that an older
// process, Nginx handoff, another host or a rolled-back owner was drained.
type LegacyReadDrainReceipt struct {
	Kind                string `json:"kind"`
	OperationID         string `json:"operation_id"`
	Challenge           string `json:"challenge"`
	ExpiresAt           int64  `json:"expires_at"`
	MasterID            string `json:"master_id"`
	OwnerID             string `json:"owner_id"`
	RelationshipID      string `json:"relationship_id"`
	RelationshipBinding string `json:"relationship_binding"`
	OwnerBinding        string `json:"owner_binding"`
	FenceBinding        string `json:"fence_binding"`
	State               string `json:"state"`
}

func (r LegacyReadDrainReceipt) Payload() (map[string]any, error) {
	if r.Kind != "legacy-media-drain-v1" || r.State != "revoked" || r.ExpiresAt <= 0 || !identifier.MatchString(r.OperationID) || !identifier.MatchString(r.MasterID) || !identifier.MatchString(r.OwnerID) || !identifier.MatchString(r.RelationshipID) || !objectID.MatchString(r.Challenge) || !objectID.MatchString(r.RelationshipBinding) || !objectID.MatchString(r.OwnerBinding) || !objectID.MatchString(r.FenceBinding) {
		return nil, errors.New("invalid legacy read drain receipt")
	}
	return map[string]any{"kind": r.Kind, "operation_id": r.OperationID, "challenge": r.Challenge, "expires_at": r.ExpiresAt, "master_id": r.MasterID, "owner_id": r.OwnerID, "relationship_id": r.RelationshipID, "relationship_binding": r.RelationshipBinding, "owner_binding": r.OwnerBinding, "fence_binding": r.FenceBinding, "state": r.State}, nil
}
