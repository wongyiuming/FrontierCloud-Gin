package store

import (
	"context"
	"errors"
)

// ErrSealedTreeInventoryLimit means this bounded assessment refused to scan
// more rows; it must not be mistaken for an empty or complete report.
var ErrSealedTreeInventoryLimit = errors.New("sealed tree inventory row limit exceeded")

// SealedTreeInventory contains aggregate facts only, with no names, paths,
// hashes, IDs or keys. It is a read-only assessment of one Master database
// snapshot, not a source snapshot, migration authorization or readiness gate.
type SealedTreeInventory struct {
	SchemaGeneration         int   `json:"schema_generation"`
	LocalObjectRows          int64 `json:"local_object_rows"`
	LocalTreePreflightFailed bool  `json:"local_tree_preflight_failed"`
	LocalTreePreflightNodes  int   `json:"local_tree_preflight_nodes"`
	GlobalObjectRows         int64 `json:"global_object_rows"`
	UploadRows               int64 `json:"upload_rows"`
	VisibilityRows           int64 `json:"visibility_rows"`
	LyricLinkRows            int64 `json:"lyric_link_rows"`
	LyricMissingTargetRows   int64 `json:"lyric_missing_target_rows"`
	LyricInvalidTrackRows    int64 `json:"lyric_invalid_track_rows"`
	PlaybackStatRows         int64 `json:"playback_stat_rows"`
	RecordingRows            int64 `json:"recording_rows"`
	EncryptedDescriptorRows  int64 `json:"encrypted_descriptor_rows"`
	EncryptionTombstoneRows  int64 `json:"encryption_tombstone_rows"`
	InvalidDescriptorRows    int64 `json:"invalid_descriptor_rows"`
	NonCanonicalPathValues   int64 `json:"noncanonical_path_values"`
	UnsupportedMediaIDValues int64 `json:"unsupported_media_id_values"`
	PathDerivedMediaIDValues int64 `json:"path_derived_media_id_values"`
	UnsupportedLyricIDValues int64 `json:"unsupported_lyric_id_values"`
	PathDerivedLyricIDValues int64 `json:"path_derived_lyric_id_values"`
	UnkeyedPathLocatorValues int64 `json:"unkeyed_path_locator_values"`
	OtherPathLocatorValues   int64 `json:"other_path_locator_values"`
	MigrationPathIndexRows   int64 `json:"migration_path_index_rows"`
	MigrationScopePathRows   int64 `json:"migration_scope_path_rows"`
	MigrationUnitPathRows    int64 `json:"migration_unit_path_rows"`
	MigrationObjectPathRows  int64 `json:"migration_object_path_rows"`
	MigrationJournalPathRows int64 `json:"migration_journal_path_rows"`
	GlobalMissingOwnerRows   int64 `json:"global_missing_owner_rows"`
	DeleteJournalRows        int64 `json:"delete_journal_rows"`
	NodeAuditRows            int64 `json:"node_audit_rows"`
	AdminAuditRows           int64 `json:"admin_audit_rows"`
	StorageMemberRows        int64 `json:"storage_member_rows"`
	InvalidQuotaValues       int64 `json:"invalid_quota_values"`
	UnsettledIndicators      int64 `json:"unsettled_indicators"`
	DatabaseSnapshotOnly     bool  `json:"database_snapshot_only"`
	RuntimeReady             bool  `json:"runtime_ready"`
}

// SealedTreeInventoryRepository is optional and Master-only. The caller must
// separately hold the appropriate mutation/cluster fence, protect this report,
// and verify source objects, remote nodes, permissions, quota, key recovery,
// backups and historical plaintext remnants before planning any migration.
// ID and locator counts cover only the selected media/local/global/upload
// rows; migration indexes and other ID-bearing columns need separate review.
type SealedTreeInventoryRepository interface {
	SealedTreeInventory(context.Context) (SealedTreeInventory, error)
}
