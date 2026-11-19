package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// The artifact is staged in memory because it can contain historical paths,
// account hashes and other private state. Refuse larger input before reading.
const MaxBusinessStateBytes = 128 << 20

type BusinessStateReport struct {
	TargetMasterID     string           `json:"target_master_id"`
	SourceGeneration   int64            `json:"source_generation"`
	SourceSHA256       string           `json:"source_sha256"`
	ImportedRows       map[string]int64 `json:"imported_rows"`
	ArchivedRecordings int64            `json:"archived_recordings"`
	ArchivedUsageBytes int64            `json:"archived_usage_bytes"`
	AlreadyApplied     bool             `json:"already_applied"`
	RestoreReady       bool             `json:"restore_ready"`
}

var ErrBusinessStateTarget = errors.New("business state target is not a fresh matching Master or has conflicting state")

// Explicit projections keep generated columns, old asset references and old
// runtime bookkeeping out of the target. Original audit details remain in
// the protected source; imported history retains policy-relevant fields.
var businessStateTables = []struct {
	table, columns, order, sourceColumns string
}{
	{"ip_security_audit_log", "id,ip_address,action,detail,session_id_hash,request_id,trace_id,created_at", "id", "id,ip_address,action,'{}',session_id_hash,request_id,trace_id,created_at"},
	{"ip_security_summary", "ip_address,attack_count,last_attack_at", "ip_address", ""},
	{"ip_auto_ban_events", "id,ip_address,trigger_count,window_started_at,banned_at,expires_at,last_method,last_path,user_agent,ban_kind,reason,created_by_session_hash,status,released_at,released_by_session_hash", "id", "id,ip_address,trigger_count,window_started_at,banned_at,expires_at,last_method,NULL,NULL,ban_kind,reason,created_by_session_hash,status,released_at,released_by_session_hash"},
	{"ip_permanent_whitelist", "ip_address,created_at,created_by_session_hash,note", "ip_address", ""},
	{"webrtc_observation_events", "id,client_ip,webrtc_ip,outcome,matches_verified,observed_at", "id", ""},
	{"webrtc_observation_summary", "client_ip,webrtc_ip_key,webrtc_ip,observation_count,matching_count,first_seen,last_seen,last_outcome", "client_ip,webrtc_ip_key", ""},
	{"karaoke_users", "user_id,username,username_key,password_hash,status,quota_bytes,used_bytes,created_at,updated_at", "user_id", "user_id,username,username_key,password_hash,status,quota_bytes,0,created_at,updated_at"},
	{"karaoke_registration_daily", "client_ip,day_key,failure_count,success_count,updated_at", "client_ip,day_key", ""},
	{"karaoke_audit_log", "id,user_id,action,result,client_ip,webrtc_addresses,detail,request_id,trace_id,created_at", "id", "id,user_id,action,result,client_ip,webrtc_addresses,'{}',request_id,trace_id,created_at"},
}

// MatchesImport checks a native report before an operator presents it as the
// result of a particular import. A row report does not certify site recovery.
func (r BusinessStateReport) MatchesImport(expected Expectation, masterID string) bool {
	if r.TargetMasterID != masterID || r.SourceGeneration != expected.Generation || r.SourceSHA256 != expected.Checksum || r.RestoreReady ||
		len(r.ImportedRows) != len(businessStateTables) || r.ArchivedRecordings < 0 || r.ArchivedUsageBytes < 0 {
		return false
	}
	for _, spec := range businessStateTables {
		if count, ok := r.ImportedRows[spec.table]; !ok || count < 0 {
			return false
		}
	}
	return true
}

// ImportBusinessState consumes an independently pinned v2 artifact. The caller
// holds the target's native offline fence. It must not run inside a source
// repository callback that has yet to verify its own source snapshot.
func ImportBusinessState(ctx context.Context, reader io.Reader, expected Expectation, target *sql.DB, masterID string, checkFence func() error) (BusinessStateReport, error) {
	if !validBackupInput(reader, expected) || expected.Bytes > MaxBusinessStateBytes {
		return BusinessStateReport{}, store.ErrBackupState
	}
	if target == nil || !hexID(masterID, 32) || checkFence == nil {
		return BusinessStateReport{}, ErrBusinessStateTarget
	}
	if err := checkFence(); err != nil {
		return BusinessStateReport{}, err
	}
	source, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return BusinessStateReport{}, err
	}
	defer source.Close()
	source.SetMaxOpenConns(1)
	for _, statement := range []string{"PRAGMA temp_store=MEMORY", "PRAGMA foreign_keys=ON"} {
		if _, err := source.ExecContext(ctx, statement); err != nil {
			return BusinessStateReport{}, err
		}
	}
	staged, err := stageBackup(ctx, source, reader, expected)
	if err != nil {
		return BusinessStateReport{}, err
	}
	report := BusinessStateReport{
		TargetMasterID: masterID, SourceGeneration: expected.Generation, SourceSHA256: expected.Checksum,
		ImportedRows: make(map[string]int64, len(businessStateTables)), ArchivedRecordings: staged.Rows["karaoke_recordings"],
	}
	if err := source.QueryRowContext(ctx, "SELECT COALESCE(SUM(used_bytes),0) FROM karaoke_users").Scan(&report.ArchivedUsageBytes); err != nil {
		return BusinessStateReport{}, store.ErrBackupState
	}
	tx, err := target.BeginTx(ctx, nil)
	if err != nil {
		return BusinessStateReport{}, err
	}
	defer tx.Rollback()
	if err := checkBusinessStateTarget(ctx, tx, masterID); err != nil {
		return BusinessStateReport{}, err
	}
	for _, spec := range businessStateTables {
		var present bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+spec.table+")").Scan(&present); err != nil {
			return BusinessStateReport{}, ErrBusinessStateTarget
		}
		report.AlreadyApplied = report.AlreadyApplied || present
	}
	for _, spec := range businessStateTables {
		columns := spec.sourceColumns
		if columns == "" {
			columns = spec.columns
		}
		rows, err := source.QueryContext(ctx, "SELECT "+columns+" FROM "+spec.table+" ORDER BY "+spec.order)
		if err != nil {
			return BusinessStateReport{}, fmt.Errorf("%w: read %s", store.ErrBackupState, spec.table)
		}
		if err := applyBusinessStateRows(ctx, tx, rows, spec.table, spec.columns, spec.order, report.AlreadyApplied); err != nil {
			return BusinessStateReport{}, fmt.Errorf("%w: %s", err, spec.table)
		}
		report.ImportedRows[spec.table] = staged.Rows[spec.table]
	}
	if !report.AlreadyApplied && (report.ImportedRows["ip_auto_ban_events"] != 0 || report.ImportedRows["ip_permanent_whitelist"] != 0) {
		result, err := tx.ExecContext(ctx, "UPDATE ip_security_projection SET generation=generation+1 WHERE singleton=1 AND generation<9223372036854775807")
		if err != nil {
			return BusinessStateReport{}, ErrBusinessStateTarget
		}
		if updated, err := result.RowsAffected(); err != nil || updated != 1 {
			return BusinessStateReport{}, ErrBusinessStateTarget
		}
	}
	if err := checkFence(); err != nil {
		return BusinessStateReport{}, err
	}
	if err := tx.Commit(); err != nil {
		return BusinessStateReport{}, err
	}
	return report, nil
}

func checkBusinessStateTarget(ctx context.Context, tx *sql.Tx, masterID string) error {
	var id, role string
	var generation int
	if err := tx.QueryRowContext(ctx, "SELECT n.node_id,n.role,s.generation FROM node_identity n JOIN frontiercloud_schema s ON n.singleton=s.singleton WHERE n.singleton=1").Scan(&id, &role, &generation); err != nil || id != masterID || role != "Master" || generation != migrations.Generation {
		return ErrBusinessStateTarget
	}
	for _, table := range []string{
		"node_relationships", "global_media_objects", "karaoke_recordings", "s3_objects",
		"sealed_tree_records", "sealed_tree_placements", "sealed_tree_pending_files", "sealed_tree_revocations",
		"sealed_recording_audio", "selected_upload_intents", "selected_s3_uploads",
	} {
		var present bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+")").Scan(&present); err != nil || present {
			return ErrBusinessStateTarget
		}
	}
	var legacyMedia bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM media_objects WHERE NOT (object_kind='lyric' AND media_path='lyrics/default.lrc'))").Scan(&legacyMedia); err != nil || legacyMedia {
		return ErrBusinessStateTarget
	}
	return nil
}

func applyBusinessStateRows(ctx context.Context, target *sql.Tx, source *sql.Rows, table, columns, order string, compare bool) error {
	defer source.Close()
	count := strings.Count(columns, ",") + 1
	values, addresses := make([]any, count), make([]any, count)
	for i := range values {
		addresses[i] = &values[i]
	}
	var existing *sql.Rows
	var insert *sql.Stmt
	var other, otherAddresses []any
	if compare {
		var err error
		existing, err = target.QueryContext(ctx, "SELECT "+columns+" FROM "+table+" ORDER BY "+order)
		if err != nil {
			return ErrBusinessStateTarget
		}
		defer existing.Close()
		other, otherAddresses = make([]any, count), make([]any, count)
		for i := range other {
			otherAddresses[i] = &other[i]
		}
	} else {
		var err error
		insert, err = target.PrepareContext(ctx, "INSERT INTO "+table+" ("+columns+") VALUES (?"+strings.Repeat(",?", count-1)+")")
		if err != nil {
			return ErrBusinessStateTarget
		}
		defer insert.Close()
	}
	for source.Next() {
		if err := source.Scan(addresses...); err != nil {
			return store.ErrBackupState
		}
		if compare {
			if !existing.Next() || existing.Scan(otherAddresses...) != nil || !reflect.DeepEqual(values, other) {
				return ErrBusinessStateTarget
			}
		} else {
			for i, value := range values {
				if date, ok := value.(time.Time); ok {
					values[i] = date.UTC().Format("2006-01-02 15:04:05.000000")
				}
			}
			if _, err := insert.ExecContext(ctx, values...); err != nil {
				return ErrBusinessStateTarget
			}
		}
	}
	if err := source.Err(); err != nil {
		return err
	}
	if compare && (existing.Next() || existing.Err() != nil) {
		return ErrBusinessStateTarget
	}
	return nil
}
