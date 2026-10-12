package business

import (
	"context"
	"database/sql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

type retirementQuery struct {
	code, from, id, next string
	args                 []any
}

// The ledger is a read-only diagnostic snapshot. Empty SQL is not proof of
// empty disks, satisfied retention, expired capabilities or safe revocation.
func (r *Repository) RetirementLedger(ctx context.Context, relationship, member string) (store.RetirementLedger, error) {
	result := store.RetirementLedger{MemberID: member, RelationshipID: relationship, RequiresPhysicalVerification: true, Blockers: []store.RetirementBlocker{}}
	if !nodeIDPattern.MatchString(relationship) || !nodeIDPattern.MatchString(member) {
		return result, store.ErrNodeState
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	var node, role, peer, direction, state string
	var protocol int
	if e = tx.QueryRowContext(ctx, "SELECT node_id,role FROM node_identity WHERE singleton=1").Scan(&node, &role); e != nil {
		return result, e
	}
	if e = tx.QueryRowContext(ctx, "SELECT peer_id,direction,state,protocol FROM node_relationships WHERE relationship_id=?", relationship).Scan(&peer, &direction, &state, &protocol); e != nil {
		return result, e
	}
	if state != "active" || protocol != 2 || role == "Master" && (member == node || member != peer || direction != "downstream") || role == "Follower" && (member != node || direction != "upstream") || role != "Master" && role != "Follower" {
		return result, store.ErrNodeState
	}
	now := time.Now().Unix()
	result.Role = role
	result.CheckedAt = now
	checks := []retirementQuery{
		{"recordings", "karaoke_recordings WHERE storage_member_id=? AND state<>'deleted'", "recording_id", "migrate_or_resolve_recordings", []any{member}},
		{"uploads", "cluster_upload_sessions WHERE storage_member_id=? AND state NOT IN ('complete','cancelled')", "upload_id", "finish_or_cancel_uploads", []any{member}},
		{"storage_accounting", "cluster_storage_members WHERE member_id=? AND (used_bytes<>0 OR reserved_bytes<>0)", "member_id", "reconcile_used_and_reserved_bytes", []any{member}},
		{"migration_tasks", "migration_tasks WHERE (source_id=? OR target_id=?) AND state NOT IN ('completed','cancelled')", "task_id", "finish_or_resolve_migration", []any{member, member}},
		{"migration_scopes", "migration_scopes WHERE member_id=?", "scope_id", "reconcile_task_scope_receipts", []any{member}},
		{"migration_reservations", "migration_capacity WHERE member_id=? AND reserved_bytes<>0", "task_id", "reconcile_task_reservations", []any{member}},
		{"active_read_leases", "migration_read_leases WHERE member_id=? AND expires_at>?", "lease_id", "wait_for_or_resolve_read_dependencies", []any{member, now}},
	}
	if role == "Follower" {
		checks = append(checks,
			retirementQuery{"managed_media", "media_objects WHERE object_kind IN ('audio','video')", "media_id", "migrate_or_resolve_media", nil},
			retirementQuery{"backup_generations", "cluster_business_backups", "CAST(generation AS CHAR)", "retain_or_replace_verified_recovery_points", nil},
			retirementQuery{"backup_chunks", "cluster_business_backup_chunks", "CAST(generation AS CHAR)", "reconcile_receiving_or_orphan_backup_material", nil},
			retirementQuery{"file_transactions", "media_delete_operations WHERE state<>'rename_done'", "operation_id", "finish_native_file_recovery", nil},
			retirementQuery{"migration_journals", "migration_storage_journal j LEFT JOIN migration_tasks t ON t.task_id=j.task_id WHERE (j.source_id=? OR j.target_id=?) AND (t.task_id IS NULL OR t.state NOT IN ('completed','cancelled'))", "j.task_id", "reconcile_peer_task_and_file_receipts", []any{member, member}})
	} else {
		checks = append(checks,
			retirementQuery{"managed_media", "global_media_objects WHERE storage_member_id=? AND state<>'deleted'", "media_id", "migrate_or_resolve_media", []any{member}},
			retirementQuery{"backup_placement", "cluster_backup_members WHERE member_id=? AND (generation>0 OR state NOT IN ('ready','disabled','failed'))", "member_id", "verify_replacement_backup_and_stop_delivery", []any{member}},
			retirementQuery{"node_offline", "cluster_storage_members WHERE member_id=? AND health<>'online'", "member_id", "restore_connectivity_for_final_reconciliation", []any{member}})
	}
	for _, check := range checks {
		var count int64
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+check.from, check.args...).Scan(&count); e != nil {
			return result, e
		}
		if count == 0 {
			continue
		}
		block := store.RetirementBlocker{Code: check.code, Count: count, SampleIDs: []string{}, NextStep: check.next}
		rows, e := tx.QueryContext(ctx, "SELECT "+check.id+" FROM "+check.from+" ORDER BY "+check.id+" LIMIT 8", check.args...)
		if e != nil {
			return result, e
		}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return result, e
			}
			if len(id) > 128 {
				rows.Close()
				return result, store.ErrNodeState
			}
			block.SampleIDs = append(block.SampleIDs, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return result, e
		}
		result.Blockers = append(result.Blockers, block)
	}
	result.DatabaseClear = len(result.Blockers) == 0
	if e = tx.Commit(); e != nil {
		return result, e
	}
	return result, nil
}
