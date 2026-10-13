package store

import "context"

type RetirementBlocker struct {
	Code      string   `json:"code"`
	Count     int64    `json:"count"`
	SampleIDs []string `json:"sample_ids"`
	NextStep  string   `json:"next_step"`
}
type RetirementLedger struct {
	MemberID                     string              `json:"member_id"`
	RelationshipID               string              `json:"relationship_id"`
	Role                         string              `json:"role"`
	CheckedAt                    int64               `json:"checked_at"`
	DatabaseClear                bool                `json:"database_clear"`
	RequiresPhysicalVerification bool                `json:"requires_physical_verification"`
	Blockers                     []RetirementBlocker `json:"blockers"`
}
type RetirementRepository interface {
	RetirementLedger(context.Context, string, string) (RetirementLedger, error)
}

// RetirementMigrationRepository resolves retained byte checkpoints against
// bounded, authenticated terminal history. It never grants deletion or revoke.
type RetirementMigrationRepository interface {
	RetirementMigration(context.Context, string, string, string, string, string) (MigrationPeerObject, error)
}

type RetirementFence struct {
	MemberID       string `json:"member_id"`
	RelationshipID string `json:"relationship_id"`
	MasterID       string `json:"master_id"`
	FencedAt       int64  `json:"fenced_at"`
	CompletedAt    int64  `json:"completed_at"`
}

type RetirementFenceRepository interface {
	BeginRetirement(context.Context, string, string, NodeAudit) (RetirementFence, error)
	CompleteRetirement(context.Context, string, string, NodeAudit) (RetirementFence, error)
	RetirementFence(context.Context, string, string) (RetirementFence, error)
	ReserveRetirementNonce(context.Context, string, string, string, int64, bool) (Relationship, error)
}
