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
