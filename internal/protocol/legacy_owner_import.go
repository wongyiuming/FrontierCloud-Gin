package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"strings"
)

// LegacyOwnerImportPlan is signed by the paired Master. Digest is an
// independently established full ciphertext/plaintext SHA-256, not an Owner
// self-report or a weak legacy ETag. The original source is never deleted.
type LegacyOwnerImportPlan struct {
	Kind                string `json:"kind"`
	MasterID            string `json:"master_id"`
	OwnerID             string `json:"owner_id"`
	RelationshipID      string `json:"relationship_id"`
	RelationshipBinding string `json:"relationship_binding"`
	OwnerBinding        string `json:"owner_binding"`
	FenceBinding        string `json:"fence_binding"`
	Generation          string `json:"generation"`
	OperationID         string `json:"operation_id"`
	StageID             string `json:"stage_id"`
	BlobID              string `json:"blob_id"`
	SourceID            string `json:"source_id"`
	SourcePath          string `json:"source_path"`
	Digest              string `json:"digest"`
	Bytes               int64  `json:"bytes"`
	Challenge           string `json:"challenge"`
	ExpiresAt           int64  `json:"expires_at"`
}

// PublishedReceipt is path-free and binds the exact signed plan, including
// its source path, source ID, authorization challenge and expiration.
func (p LegacyOwnerImportPlan) PublishedReceipt() (map[string]any, error) {
	payload, err := p.Payload()
	if err != nil {
		return nil, err
	}
	canonical, err := Canonical(payload)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return map[string]any{"kind": "legacy-owner-import-published-v1", "master_id": p.MasterID, "owner_id": p.OwnerID, "relationship_id": p.RelationshipID, "relationship_binding": p.RelationshipBinding, "owner_binding": p.OwnerBinding, "fence_binding": p.FenceBinding, "generation": p.Generation, "operation_id": p.OperationID, "stage_id": p.StageID, "blob_id": p.BlobID, "digest": p.Digest, "bytes": p.Bytes, "challenge": p.Challenge, "plan_digest": hex.EncodeToString(sum[:]), "state": "published"}, nil
}

func (p LegacyOwnerImportPlan) Payload() (map[string]any, error) {
	receipt := OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: p.MasterID, OwnerID: p.OwnerID, RelationshipID: p.RelationshipID, RelationshipBinding: p.RelationshipBinding, Generation: p.Generation, OperationID: p.OperationID, StageID: p.StageID, BlobID: p.BlobID, Digest: p.Digest, Challenge: p.Challenge, Bytes: p.Bytes, State: "published"}
	if _, err := receipt.Payload(); err != nil || p.Kind != "legacy-owner-import-v1" || p.MasterID == p.OwnerID || !objectID.MatchString(p.OwnerBinding) || !objectID.MatchString(p.FenceBinding) || !objectID.MatchString(p.SourceID) || p.ExpiresAt <= 0 || len(p.SourcePath) > 4096 || p.SourcePath != path.Clean(p.SourcePath) || strings.ContainsAny(p.SourcePath, "\\\x00") || !(strings.HasPrefix(p.SourcePath, "music/") || strings.HasPrefix(p.SourcePath, "vido/")) {
		return nil, errors.New("invalid legacy owner import plan")
	}
	for _, part := range strings.Split(p.SourcePath, "/") {
		if part == "" || strings.HasPrefix(part, ".") {
			return nil, errors.New("invalid legacy owner source")
		}
	}
	return map[string]any{"kind": p.Kind, "master_id": p.MasterID, "owner_id": p.OwnerID, "relationship_id": p.RelationshipID, "relationship_binding": p.RelationshipBinding, "owner_binding": p.OwnerBinding, "fence_binding": p.FenceBinding, "generation": p.Generation, "operation_id": p.OperationID, "stage_id": p.StageID, "blob_id": p.BlobID, "source_id": p.SourceID, "source_path": p.SourcePath, "digest": p.Digest, "bytes": p.Bytes, "challenge": p.Challenge, "expires_at": p.ExpiresAt}, nil
}
