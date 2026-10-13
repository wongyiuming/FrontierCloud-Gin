package store

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
)

type MigrationTraffic struct {
	NodeID string               `json:"node_id"`
	Role   string               `json:"role"`
	View   businesstraffic.View `json:"traffic"`
}
type MigrationExecution struct {
	TaskID       string             `json:"task_id"`
	State        string             `json:"state"`
	ObjectID     string             `json:"object_id,omitempty"`
	CurrentBytes int64              `json:"current_bytes"`
	CurrentTotal int64              `json:"current_total_bytes"`
	Speed        int64              `json:"bytes_per_second"`
	ObservedAt   int64              `json:"observed_at_ms"`
	WaitingNode  string             `json:"waiting_node_id,omitempty"`
	Traffic      []MigrationTraffic `json:"traffic"`
}

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
	Queue     bool            `json:"queue,omitempty"`
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
	QueuePosition   int64                   `json:"queue_position"`
	Execution       *MigrationExecution     `json:"execution,omitempty"`
}
type MigrationAdminRepository interface {
	MigrationTasksPage(context.Context, int64, string) (MigrationTaskPage, error)
	MigrationStatus(context.Context, string, string) (MigrationStatus, error)
	ControlMigrationRevision(context.Context, string, string, int64, NodeAudit) (MigrationTask, error)
}
