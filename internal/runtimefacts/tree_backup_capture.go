package runtimefacts

import "github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"

// TreeBackupCaptureRequest is exchanged only through the local foc-to-runtime
// pipe. It carries no private key material.
type TreeBackupCaptureRequest struct {
	Nonce            string            `json:"nonce"`
	DatabaseRelative string            `json:"database_relative"`
	Selection        []string          `json:"selection"`
	Classes          []string          `json:"classes"`
	StageLimit       uint64            `json:"stage_limit"`
	Manifest         recovery.Manifest `json:"manifest"`
}

type TreeBackupCaptureReply struct {
	Phase   string             `json:"phase"`
	Mounts  *TreeBackupRuntime `json:"mounts,omitempty"`
	Scratch string             `json:"scratch,omitempty"`
	Report  *recovery.Report   `json:"report,omitempty"`
}
