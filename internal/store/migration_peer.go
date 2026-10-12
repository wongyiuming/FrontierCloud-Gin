package store

import "context"

// Peer registrations are resource/control facts only. They never contain a
// Master business database, private identity, relationship key or media key.
type MigrationPeerHeader struct {
	Format             string `json:"format"`
	Version            int    `json:"version"`
	TaskID             string `json:"task_id"`
	MasterID           string `json:"master_id"`
	SourceID           string `json:"source_id"`
	TargetID           string `json:"target_id"`
	SourceRelationship string `json:"source_relationship"`
	TargetRelationship string `json:"target_relationship"`
	PlanSHA            string `json:"plan_sha256"`
	ObjectCount        int64  `json:"object_count"`
	Bytes              int64  `json:"size_bytes"`
}
type MigrationPeerObject struct {
	Object MigrationObject    `json:"object"`
	Proof  MigrationDiskProof `json:"proof"`
}
type MigrationPeerRepository interface {
	RegisterPeerMigration(context.Context, string, MigrationPeerHeader, MigrationLease, string, int64, NodeAudit) error
	RegisterPeerMigrationObject(context.Context, string, MigrationLease, MigrationPeerObject, NodeAudit) error
	AuthorizePeerMigration(context.Context, string, MigrationLease, string, string) (MigrationPeerObject, error)
	FencePeerMigration(context.Context, string, string, int64, string, NodeAudit) error
}
