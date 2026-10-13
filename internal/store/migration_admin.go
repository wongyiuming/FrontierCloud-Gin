package store

import "context"

type MigrationStage struct {
	State         string `json:"state"`
	Count         int64  `json:"count"`
	Bytes         int64  `json:"size_bytes"`
	VerifiedBytes int64  `json:"verified_bytes"`
}
type MigrationObjectStatus struct {
	ID            string `json:"logical_id"`
	UnitID        string `json:"unit_id"`
	Resource      string `json:"resource_kind"`
	Path          string `json:"physical_path"`
	State         string `json:"state"`
	Bytes         int64  `json:"size_bytes"`
	VerifiedBytes int64  `json:"verified_bytes"`
	UpdatedAt     int64  `json:"updated_at"`
}
type MigrationTaskPage struct {
	Tasks     []MigrationTask `json:"tasks"`
	AfterTime int64           `json:"after_time"`
	AfterID   string          `json:"after_id"`
	NextTime  int64           `json:"next_time"`
	NextID    string          `json:"next_id"`
	Complete  bool            `json:"complete"`
}
type MigrationStatus struct {
	Task            MigrationTask           `json:"task"`
	ObjectStages    []MigrationStage        `json:"object_stages"`
	UnitStages      []MigrationStage        `json:"unit_stages"`
	Objects         []MigrationObjectStatus `json:"objects"`
	After           string                  `json:"after"`
	Next            string                  `json:"next"`
	Complete        bool                    `json:"complete"`
	RetirementReady bool                    `json:"retirement_ready"`
}
type MigrationAdminRepository interface {
	MigrationTasksPage(context.Context, int64, string) (MigrationTaskPage, error)
	MigrationStatus(context.Context, string, string) (MigrationStatus, error)
	ControlMigrationRevision(context.Context, string, string, int64, NodeAudit) (MigrationTask, error)
}
