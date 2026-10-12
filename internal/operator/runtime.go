package operator

import "github.com/wongyiuming/FrontierCloud-Gin/internal/store"

// RuntimeFact is an allowlist. It excludes credentials, endpoints, arbitrary
// peer summaries, authentication material and certificate export envelopes.
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
