// Package migrations owns the physical schemas used by both runtime implementations.
package migrations

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

const Generation = 13
const JournalName = "create-schema-migration-journal"
const JournalChecksum = "aee46be69d8c5b005cbee58ebfd37feb41d3431eb1fb23bb8339c9076147c03e"

const EncryptionName = "browser-media-encryption-descriptors"

// SHA256 of the two canonical SQLite generation-3 CREATE TABLE statements joined
// by one newline. MySQL applies equivalent DDL under the same migration identity.
const EncryptionChecksum = "e5cee839fd964c7146758c365abf72fbde94dab1e74c4a9f8dc20df8ea62176b"

const PriorityName = "priority-range-negative7-to-500000"
const PriorityMySQLAlter = "ALTER TABLE media_playback_stats DROP CHECK chk_media_preference, MODIFY COLUMN preference INT NOT NULL DEFAULT 0, ADD CONSTRAINT chk_media_preference CHECK (preference BETWEEN -7 AND 500000)"

//go:embed mysql/*.json sqlite/*.json
var assets embed.FS

func Statements(backend string) ([]string, error) {
	if backend != "mysql" && backend != "sqlite" {
		return nil, fmt.Errorf("unsupported schema backend %q", backend)
	}
	data, err := assets.ReadFile(fmt.Sprintf("%s/%04d-schema.json", backend, Generation))
	if err != nil {
		return nil, err
	}
	var document struct {
		Generation int      `json:"generation"`
		Statements []string `json:"statements"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if document.Generation != Generation {
		return nil, fmt.Errorf("shared schema generation mismatch")
	}
	return document.Statements, nil
}

// SHA256 of SQLite CREATE plus the equivalent atomic MySQL ALTER.
const PriorityChecksum = "40ed2a2da3227bc3835f9196d5bd1cc81fc547bf1ada05f410cff929715487f1"

const ResourceMigrationName = "durable-storage-resource-migration"
const ResourceMigrationChecksum = "64e2817e07fd7a65dc651297425ce9a0ca26d6a8f4e7abb21d3154a359c3ce3c"

const PeerBindingsName = "immutable-peer-resource-bindings"
const PeerBindingsChecksum = "1fda21be7bc2c0b5f1b14bfc6f74e352a1bc070688c5409ad000d47ce555aed8"

const MigrationPlansName = "paged-master-migration-plans"
const MigrationPlansChecksum = "e190dd09f369fea46adc941a3a43addbd87fd211261f5da0ea9ec384297f85cd"

const S3Name = "master-owned-s3-durable-multipart"

// SHA256 of "sqlite\n" + additive SQLite DDL + "\nmysql\n" + additive MySQL
// DDL, joining each backend's generation-8 statements by one newline.
const S3Checksum = "fd063b0ff95182337eb1418efc844705d90bf703880d1b274e6b215b4001a943"

// PublicRoutingChecksum binds the additive SQLite and MySQL generation-9 DDL.
const PublicRoutingName = "public-ingress-native-transport-model"
const PublicRoutingChecksum = "fdad1ca9bc242de1147fadddc493cff77e0f450ac937a78cc845a4cbfe92fada"

// SealedTreeChecksum covers the exact additive backend DDL. These tables do
// not activate encrypted-tree operation or migrate any historical data.
const SealedTreeName = "master-sealed-tree-dormant-storage"
const SealedTreeChecksum = "a24a35d6d903f481dcb9e8302dea193cc92c01b01ba59b3377e9547203972ca7"

const LegacyReadIntentName = "legacy-read-control-intents"
const LegacyReadIntentChecksum = "4c95fabb7c86ad07a4f398fd7a39a0c9a84b75bd387e73735b5692d2e00b3036"

// Generation 12 reserves opaque, authenticated state for selected uploads,
// S3 multipart uploads and recordings. Schema alone opens no endpoint.
const SelectedUploadIntentName = "selected-upload-encrypted-intents"
const SelectedUploadIntentChecksum = "48544c3dd8556a1908eb63b512521416f27f10e8f48527b491bbc95e1e353688"

// Generation 13 adds the sealed native migration task, unit and object
// journals while retaining the common migration queue and capacity tables.
const OpaqueMigrationName = "sealed-native-migration-ledger"
const OpaqueMigrationChecksum = "62d740dc8614a698c8b6f06fe42e477da5d17bec600b21a9a694f9d8b12afad1"

func OpaqueMigrationStatements(backend string) ([]string, error) {
	all, err := Statements(backend)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, statement := range all {
		if strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS opaque_migration_") ||
			strings.HasPrefix(statement, "CREATE UNIQUE INDEX IF NOT EXISTS uq_opaque_migration_") ||
			strings.HasPrefix(statement, "CREATE INDEX IF NOT EXISTS idx_opaque_migration_") {
			result = append(result, statement)
		}
	}
	return result, nil
}

func SelectedUploadIntentStatements(backend string) ([]string, error) {
	all, err := Statements(backend)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, statement := range all {
		if strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS selected_upload_intents") || strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS selected_upload_parent_scopes") || strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS selected_upload_cancellations") || strings.HasPrefix(statement, "CREATE UNIQUE INDEX IF NOT EXISTS uq_selected_upload_") || strings.HasPrefix(statement, "CREATE INDEX IF NOT EXISTS idx_selected_upload_") || IsSelectedS3Statement(statement) || isRecordingAudioStatement(statement) {
			result = append(result, statement)
		}
	}
	return result, nil
}

func isRecordingAudioStatement(statement string) bool {
	return strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS sealed_recording_audio ") ||
		strings.HasPrefix(statement, "CREATE UNIQUE INDEX IF NOT EXISTS uq_sealed_recording_audio_")
}

func RecordingAudioStatements(backend string) ([]string, error) {
	all, err := Statements(backend)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, statement := range all {
		if isRecordingAudioStatement(statement) {
			result = append(result, statement)
		}
	}
	return result, nil
}

// IsSelectedS3Statement identifies the S3 multipart journals within generation 12.
func IsSelectedS3Statement(statement string) bool {
	return strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS selected_s3_") ||
		strings.HasPrefix(statement, "CREATE UNIQUE INDEX IF NOT EXISTS uq_selected_s3_") ||
		strings.HasPrefix(statement, "CREATE INDEX IF NOT EXISTS idx_selected_s3_")
}

func SelectedS3Statements(backend string) ([]string, error) {
	all, err := SelectedUploadIntentStatements(backend)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, statement := range all {
		if IsSelectedS3Statement(statement) {
			result = append(result, statement)
		}
	}
	return result, nil
}

// LegacyReadIntentStatements is the generation-11 addition only. It must not
// change the independently checksummed generation-10 sealed tree DDL.
func LegacyReadIntentStatements(backend string) ([]string, error) {
	all, err := Statements(backend)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, statement := range all {
		if strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS legacy_read_control_intents") || strings.HasPrefix(statement, "CREATE UNIQUE INDEX IF NOT EXISTS uq_legacy_read_control_") {
			result = append(result, statement)
		}
	}
	return result, nil
}

// SealedTreeStatements returns only additive encrypted-tree DDL from the
// canonical current snapshot. Callers must not infer migration readiness from
// table existence: legacy paths and physical layouts can still be plaintext.
func SealedTreeStatements(backend string) ([]string, error) {
	all, err := Statements(backend)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, statement := range all {
		if strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS sealed_tree_") || strings.HasPrefix(statement, "CREATE UNIQUE INDEX IF NOT EXISTS uq_st_") {
			result = append(result, statement)
		}
	}
	return result, nil
}
