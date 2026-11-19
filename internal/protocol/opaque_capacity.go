package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// OpaqueCapacityReceipt is a proposed, unregistered owner proof. Published
// attests the exact final blob; cleaned attests the operation was durably
// stopped after draining in-flight publications, and both stage and final blob
// are absent after directory synchronization. A signature is an owner's claim,
// not proof that a hostile owner erased every copy. The Master must separately
// persist and consume the challenge and verify the current owner instance.
type OpaqueCapacityReceipt struct {
	Kind                string `json:"kind"`
	MasterID            string `json:"master_id"`
	OwnerID             string `json:"owner_id"`
	RelationshipID      string `json:"relationship_id"`
	RelationshipBinding string `json:"relationship_binding"`
	Generation          string `json:"generation"`
	OperationID         string `json:"operation_id"`
	StageID             string `json:"stage_id"`
	BlobID              string `json:"blob_id"`
	Digest              string `json:"digest"`
	Challenge           string `json:"challenge"`
	Bytes               int64  `json:"bytes"`
	State               string `json:"state"`
}

// Payload is the complete domain-separated Ed25519 signing input, without
// paths, legacy IDs, media keys or client-controlled proxy destinations.
func (r OpaqueCapacityReceipt) Payload() (map[string]any, error) {
	validState := r.Kind == "opaque-capacity-published-v1" && r.State == "published" || r.Kind == "opaque-capacity-cleaned-v1" && r.State == "cleaned"
	empty := sha256.Sum256(nil)
	if !validState || !identifier.MatchString(r.MasterID) || !identifier.MatchString(r.OwnerID) || !objectID.MatchString(r.Generation) || !objectID.MatchString(r.OperationID) || !objectID.MatchString(r.StageID) || !objectID.MatchString(r.BlobID) || !objectID.MatchString(r.Digest) || !objectID.MatchString(r.Challenge) || r.Bytes < 0 || r.Bytes > MaxOpaquePlainBytes || r.Bytes == 0 && r.Digest != hex.EncodeToString(empty[:]) {
		return nil, errors.New("invalid opaque capacity receipt")
	}
	if r.OwnerID == r.MasterID {
		if r.RelationshipID != "" || r.RelationshipBinding != "" {
			return nil, errors.New("invalid local owner binding")
		}
	} else if !identifier.MatchString(r.RelationshipID) || !objectID.MatchString(r.RelationshipBinding) {
		return nil, errors.New("invalid peer owner binding")
	}
	if r.OperationID == r.StageID || r.OperationID == r.BlobID || r.OperationID == r.Challenge || r.StageID == r.BlobID || r.StageID == r.Challenge || r.BlobID == r.Challenge {
		return nil, errors.New("duplicate opaque capacity identifier")
	}
	return map[string]any{"kind": r.Kind, "master_id": r.MasterID, "owner_id": r.OwnerID, "relationship_id": r.RelationshipID, "relationship_binding": r.RelationshipBinding, "generation": r.Generation, "operation_id": r.OperationID, "stage_id": r.StageID, "blob_id": r.BlobID, "digest": r.Digest, "challenge": r.Challenge, "bytes": r.Bytes, "state": r.State}, nil
}
