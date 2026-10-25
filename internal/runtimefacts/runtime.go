// Package runtimefacts contains read-only native runtime observations shared
// with management clients. It has no host tooling or deployment side effects.
package runtimefacts

import "github.com/wongyiuming/FrontierCloud-Gin/internal/store"

// RuntimeFact is an allowlist, excluding credentials and arbitrary summaries.
type RuntimeFact struct {
	NodeID            string                    `json:"node_id"`
	Role              string                    `json:"role"`
	Maintenance       bool                      `json:"maintenance"`
	NativeMaintenance bool                      `json:"native_maintenance"`
	Database          store.MaintenanceSnapshot `json:"database"`
	Nodes             []NodeFact                `json:"nodes"`
}

type NodeFact struct {
	NodeID        string `json:"node_id"`
	Direction     string `json:"direction"`
	State         string `json:"state"`
	Health        string `json:"health"`
	LastHeartbeat int64  `json:"last_heartbeat"`
	Protocol      int    `json:"protocol"`
}
