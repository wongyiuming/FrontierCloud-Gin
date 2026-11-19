package protocol

import (
	"errors"
	"time"
)

const OpaqueRevokePath = "/internal/v1/opaque-control/revoke"
const OpaqueDeletePath = "/internal/v1/opaque-control/delete"

// OpaqueDeletionVerificationTimeout bounds the Owner's single sequential
// verification of up to 10 GiB of encrypted media before a durable unlink.
const OpaqueDeletionVerificationTimeout = 15 * time.Minute

// OpaqueOwnerBinding contains random identities and a full content-version
// proof; it carries no logical filename or historical media identifier.
type OpaqueOwnerBinding struct {
	MasterID       string `json:"master_id"`
	OwnerID        string `json:"owner_id"`
	RelationshipID string `json:"relationship_id"`
	Alias          string `json:"alias"`
	Blob           string `json:"blob"`
	Revision       string `json:"revision"`
	Digest         string `json:"digest"`
	Descriptor     string `json:"descriptor"`
	Size           int64  `json:"size"`
}

func (b OpaqueOwnerBinding) Valid() bool {
	if !identifier.MatchString(b.MasterID) || !identifier.MatchString(b.OwnerID) || !identifier.MatchString(b.RelationshipID) {
		return false
	}
	revision, err := OpaquePlacementRevisionFromDescriptor(b.Alias, b.Blob, b.Digest, b.Descriptor, b.Size)
	return err == nil && revision == b.Revision
}

type OpaqueRevocationRequest struct {
	OperationID string             `json:"operation_id"`
	Binding     OpaqueOwnerBinding `json:"binding"`
}

func (r OpaqueRevocationRequest) Receipt() (OpaqueRevocationReceipt, error) {
	if !identifier.MatchString(r.OperationID) || !r.Binding.Valid() {
		return OpaqueRevocationReceipt{}, errors.New("invalid opaque revocation request")
	}
	b := r.Binding
	return OpaqueRevocationReceipt{Kind: "opaque-alias-revoke-v1", OperationID: r.OperationID, MasterID: b.MasterID, OwnerID: b.OwnerID, RelationshipID: b.RelationshipID, Alias: b.Alias, Blob: b.Blob, Revision: b.Revision, State: "revoked"}, nil
}

// OpaqueRevocationReceipt is signed by the paired owner only after its
// permanent tombstone is durable. Replays are scoped to this exact operation
// and placement; no name, historical ID or bearer appears in the receipt.
type OpaqueRevocationReceipt struct {
	Kind                 string `json:"kind"`
	OperationID          string `json:"operation_id"`
	MasterID             string `json:"master_id"`
	OwnerID              string `json:"owner_id"`
	RelationshipID       string `json:"relationship_id"`
	Alias                string `json:"alias"`
	Blob                 string `json:"blob"`
	Revision             string `json:"revision"`
	State                string `json:"state"`
	PublicationOperation string `json:"publication_operation,omitempty"`
}

func (r OpaqueRevocationReceipt) Payload() (map[string]any, error) {
	if r.Kind != "opaque-alias-revoke-v1" || r.State != "revoked" || r.PublicationOperation != "" || !identifier.MatchString(r.OperationID) || !identifier.MatchString(r.MasterID) || !identifier.MatchString(r.OwnerID) || !identifier.MatchString(r.RelationshipID) || !objectID.MatchString(r.Alias) || !objectID.MatchString(r.Blob) || r.Alias == r.Blob || !objectID.MatchString(r.Revision) {
		return nil, errors.New("invalid opaque revocation receipt")
	}
	return map[string]any{"kind": r.Kind, "operation_id": r.OperationID, "master_id": r.MasterID, "owner_id": r.OwnerID, "relationship_id": r.RelationshipID, "alias": r.Alias, "blob": r.Blob, "revision": r.Revision, "state": r.State}, nil
}

// OpaqueDeletionReceipt is separate from revocation: a signed revoked alias
// is never evidence that the physical blob was removed and synced.
type OpaqueDeletionReceipt OpaqueRevocationReceipt

func (r OpaqueDeletionReceipt) Payload() (map[string]any, error) {
	if r.Kind != "opaque-blob-delete-v1" || r.State != "deleted" {
		return nil, errors.New("invalid opaque deletion receipt")
	}
	fields := OpaqueRevocationReceipt(r)
	fields.Kind, fields.State = "opaque-alias-revoke-v1", "revoked"
	fields.PublicationOperation = ""
	payload, err := fields.Payload()
	if err != nil {
		return nil, err
	}
	payload["kind"], payload["state"] = r.Kind, r.State
	if op := r.PublicationOperation; op != "" {
		if !objectID.MatchString(op) || op == r.Blob || op == r.Alias {
			return nil, errors.New("invalid opaque publication operation")
		}
		payload["publication_operation"] = op
	}
	return payload, nil
}
