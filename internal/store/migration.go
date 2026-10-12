package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

var ErrMigrationState = errors.New("resource migration state changed")
var ErrMigrationLease = errors.New("resource migration runner lease lost")
var ErrMigrationInventoryLimit = errors.New("resource migration inventory requires paginated planning beyond the current bounded snapshot")

const MaxMigrationObjects = 10000
const MaxMigrationPlanBytes = 16 << 20
const MigrationCapability = "resource-migration-v1"

type MigrationBlocker struct {
	Code     string `json:"code"`
	Resource string `json:"resource,omitempty"`
}
type MigrationObject struct {
	ID         string                `json:"logical_id"`
	Resource   string                `json:"resource_kind"`
	ObjectID   string                `json:"source_object_id"`
	Path       string                `json:"physical_path"`
	TargetPath string                `json:"target_physical_path"`
	Parent     string                `json:"parent_path"`
	Kind       string                `json:"object_kind"`
	Bytes      int64                 `json:"size_bytes"`
	Version    string                `json:"source_version"`
	ETag       string                `json:"etag"`
	Encryption *mediacrypto.Metadata `json:"encryption,omitempty"`
	Recording  *RecordingProof       `json:"recording_binding,omitempty"`
}
type MigrationCatalog struct {
	SourceBackup  MigrationBackupFact `json:"source_backup"`
	MasterID      string              `json:"master_id"`
	Source        StorageMember       `json:"source"`
	Target        StorageMember       `json:"target"`
	SourceBinding string              `json:"source_identity_binding"`
	TargetBinding string              `json:"target_identity_binding"`
	Objects       []MigrationObject   `json:"objects"`
	TotalBytes    int64               `json:"total_bytes"`
	Blockers      []MigrationBlocker  `json:"blockers"`
	Version       string              `json:"catalog_version"`
}
type MigrationBackupFact struct {
	Enabled    int    `json:"enabled"`
	Generation int64  `json:"generation"`
	Checksum   string `json:"checksum"`
	State      string `json:"state"`
}

// Physical proofs are supplied only by the service after authenticated peer
// inventory. Catalog lengths alone are not disk-content or collision proof.
type MigrationDiskProof struct {
	ID      string `json:"logical_id"`
	Version string `json:"source_version"`
	Bytes   int64  `json:"size_bytes"`
	SHA256  string `json:"sha256"`
}

// Supplied only by the service after a fresh authenticated target disk scan.
// Stored publication facts alone do not prove current target bytes are intact.
type MigrationCleanupProof struct {
	MigrationDiskProof
	VerifiedAt int64 `json:"verified_at"`
}
type MigrationCleanupGrant struct {
	TaskID           string          `json:"task_id"`
	MasterID         string          `json:"master_id"`
	SourceID         string          `json:"source_id"`
	TargetID         string          `json:"target_id"`
	PlanSHA          string          `json:"plan_sha256"`
	UnitID           string          `json:"unit_id"`
	UnitVersion      string          `json:"unit_source_version"`
	Object           MigrationObject `json:"object"`
	SHA256           string          `json:"sha256"`
	CommittedAt      int64           `json:"committed_at"`
	CleanupAfter     int64           `json:"cleanup_after"`
	TargetVerifiedAt int64           `json:"target_verified_at"`
}
type MigrationPlan struct {
	ID           string               `json:"plan_id"`
	Catalog      MigrationCatalog     `json:"catalog"`
	Proofs       []MigrationDiskProof `json:"disk_proofs"`
	TargetFree   int64                `json:"target_physical_free"`
	TargetAbsent bool                 `json:"target_objects_absent"`
	CreatedAt    int64                `json:"created_at"`
	ExpiresAt    int64                `json:"expires_at"`
}

func MigrationDigest(v any) (string, error) {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > MaxMigrationPlanBytes {
		return "", ErrMigrationState
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

type MigrationTask struct {
	ID             string `json:"task_id"`
	MasterID       string `json:"master_id"`
	SourceID       string `json:"source_id"`
	TargetID       string `json:"target_id"`
	PlanSHA        string `json:"plan_sha256"`
	State          string `json:"state"`
	Revision       int64  `json:"revision"`
	ObjectCount    int64  `json:"object_count"`
	TotalBytes     int64  `json:"total_bytes"`
	CommittedBytes int64  `json:"committed_bytes"`
	ErrorCode      string `json:"error_code"`
	CreatedAt      int64  `json:"created_at"`
	UpdatedAt      int64  `json:"updated_at"`
}
type MigrationLease struct {
	TaskID    string `json:"task_id"`
	RunnerID  string `json:"runner_id"`
	Epoch     int64  `json:"epoch"`
	ExpiresAt int64  `json:"expires_at"`
}
type MigrationCheckpoint struct {
	Object        MigrationObject `json:"object"`
	UnitID        string          `json:"unit_id"`
	State         string          `json:"state"`
	SourceSHA     string          `json:"source_sha256"`
	TargetSHA     string          `json:"target_sha256"`
	VerifiedBytes int64           `json:"verified_bytes"`
}
type MigrationUnit struct {
	ID           string `json:"unit_id"`
	Resource     string `json:"resource_kind"`
	Parent       string `json:"parent_path"`
	State        string `json:"state"`
	ObjectCount  int64  `json:"object_count"`
	Bytes        int64  `json:"size_bytes"`
	CommittedAt  int64  `json:"committed_at"`
	CleanupAfter int64  `json:"cleanup_after"`
}
type MigrationWork struct {
	Task    MigrationTask         `json:"task"`
	Plan    MigrationPlan         `json:"plan"`
	Units   []MigrationUnit       `json:"units"`
	Objects []MigrationCheckpoint `json:"objects"`
}

// This boundary is shared by server-side GUI/CLI services. It neither opens
// network connections nor grants a caller permission to bypass peer proofs.
type MigrationRepository interface {
	MigrationCatalog(context.Context, string, string) (MigrationCatalog, error)
	StartMigration(context.Context, MigrationPlan, NodeAudit) (MigrationTask, error)
	MigrationTask(context.Context, string) (MigrationTask, error)
	MigrationTasks(context.Context, int) ([]MigrationTask, error)
	ControlMigration(context.Context, string, string, NodeAudit) (MigrationTask, error)
	ClaimMigration(context.Context, string, string, time.Duration) (MigrationLease, error)
	RenewMigration(context.Context, MigrationLease, time.Duration) (MigrationLease, error)
	ReleaseMigration(context.Context, MigrationLease) error
	ReleaseMigrationDrain(context.Context, string, string, NodeAudit) error
	MigrationWork(context.Context, string) (MigrationWork, error)
	VerifyMigrationObject(context.Context, MigrationLease, string, int64, string) error
	PrepareMigrationPublication(context.Context, MigrationLease, string) error
	PublishMigrationObject(context.Context, MigrationLease, string) error
	CommitMigrationUnit(context.Context, MigrationLease, string, NodeAudit) error
	MigrationRunState(context.Context, MigrationLease, string, string, string, NodeAudit) error
	ValidateMigrationLease(context.Context, MigrationLease) error
	NextMigrationRun(context.Context) (string, error)
	AuthorizeMigrationCleanup(context.Context, MigrationLease, string, MigrationCleanupProof) (MigrationCleanupGrant, error)
}
