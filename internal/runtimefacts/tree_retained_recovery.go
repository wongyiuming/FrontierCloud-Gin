package runtimefacts

import (
	"encoding/hex"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

const MaxTreeRetainedRecoveryRequest = recovery.MaxManifest + 4096
const MaxTreeRetainedRecoveryControl = 4096

// TreeRetainedRecoveryRequest is sent only over the local foc child pipe.
// Rebind and verify-local carry the host-verified manifest.
type TreeRetainedRecoveryRequest struct {
	Action           string             `json:"action"`
	Nonce            string             `json:"nonce"`
	BindingSHA256    string             `json:"binding_sha256"`
	DatabaseRelative string             `json:"database_relative,omitempty"`
	ArchiveSHA256    string             `json:"archive_sha256,omitempty"`
	NodeID           string             `json:"node_id,omitempty"`
	Manifest         *recovery.Manifest `json:"manifest,omitempty"`
}

type TreeRetainedRecoveryCommit struct {
	Nonce         string `json:"nonce"`
	BindingSHA256 string `json:"binding_sha256"`
}

type TreeRetainedRecoveryMounts struct {
	UID     uint32          `json:"uid"`
	GID     uint32          `json:"gid"`
	UIDMap  string          `json:"uid_map"`
	Data    TreeBackupMount `json:"data"`
	Secrets TreeBackupMount `json:"secrets"`
}

type TreeRetainedRecoveryReply struct {
	Phase         string                     `json:"phase"`
	Action        string                     `json:"action"`
	Nonce         string                     `json:"nonce"`
	BindingSHA256 string                     `json:"binding_sha256"`
	Mounts        TreeRetainedRecoveryMounts `json:"mounts"`
	Already       *bool                      `json:"already,omitempty"`
	Local         *TreeRetainedLocalProof    `json:"local,omitempty"`
}

// TreeRetainedLocalProof is a redacted observation of a held Master. Remote
// storage stays separately pending. This is not a site-opening receipt.
type TreeRetainedLocalProof struct {
	Version          int    `json:"version"`
	TreeGeneration   int64  `json:"tree_generation"`
	Media            int64  `json:"media"`
	Recordings       int64  `json:"recordings"`
	LocalObjects     int64  `json:"local_objects"`
	LocalBytes       int64  `json:"local_bytes"`
	FollowerOwners   int    `json:"follower_owners"`
	S3Owners         int    `json:"s3_owners"`
	CensusCommitment string `json:"census_commitment"`
	ProofCommitment  string `json:"proof_commitment"`
}

func (p TreeRetainedLocalProof) Valid() bool {
	validDigest := func(value string) bool {
		if len(value) != 64 {
			return false
		}
		raw, err := hex.DecodeString(value)
		return err == nil && hex.EncodeToString(raw) == value
	}
	return p.Version == 1 && p.TreeGeneration >= 0 && p.Media >= 0 && p.Media <= 100000 && p.Recordings >= 0 && p.Recordings <= 100000 &&
		p.LocalObjects >= 0 && p.LocalObjects <= p.Media+p.Recordings && p.LocalBytes >= 0 && (p.LocalObjects == 0) == (p.LocalBytes == 0) &&
		p.FollowerOwners >= 0 && p.S3Owners >= 0 && p.FollowerOwners <= 1024 && p.S3Owners <= 1024 &&
		validDigest(p.CensusCommitment) && validDigest(p.ProofCommitment)
}
