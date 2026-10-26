package business

import (
	"context"
	"database/sql"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// The v2 artifact remains a stable business projection, not a transfer of
// signing authority or provider recovery intents. Full state archives retain
// the original database and vault instead, including every S3 journal row.
func checkS3BusinessBackup(ctx context.Context, tx *sql.Tx) error {
	now := time.Now().Unix()
	for _, query := range []string{
		"SELECT COUNT(*) FROM s3_members WHERE cleanup_only<>0",
		"SELECT COUNT(*) FROM s3_uploads WHERE state NOT IN ('published','aborted') OR create_uncertain<>0 OR grant_until>?",
		"SELECT COUNT(*) FROM s3_upload_parts p LEFT JOIN s3_uploads u ON u.upload_id=p.upload_id WHERE p.grant_until>? OR u.upload_id IS NULL",
		"SELECT COUNT(*) FROM s3_probe_journal WHERE state<>'settled' OR grant_until>?",
		"SELECT COUNT(*) FROM s3_objects WHERE state NOT IN ('active','deleted') OR grant_until>?",
	} {
		var count int64
		var args []any
		if query != "SELECT COUNT(*) FROM s3_members WHERE cleanup_only<>0" {
			args = []any{now}
		}
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return store.ErrBackupBusy
		}
	}
	for _, query := range []string{
		"SELECT COUNT(*) FROM s3_members m LEFT JOIN cluster_storage_members s ON s.member_id=m.member_id WHERE s.member_id IS NULL OR s.member_kind<>'S3' OR s.transport<>'S3' OR s.relationship_id IS NOT NULL",
		"SELECT COUNT(*) FROM cluster_storage_members s LEFT JOIN s3_members m ON m.member_id=s.member_id WHERE s.member_kind='S3' AND m.member_id IS NULL",
		"SELECT COUNT(*) FROM s3_objects o LEFT JOIN global_media_objects g ON g.media_id=o.media_id LEFT JOIN s3_members m ON m.member_id=o.member_id WHERE o.state='active' AND (g.media_id IS NULL OR m.member_id IS NULL OR g.state<>'active' OR g.storage_member_id<>o.member_id OR g.object_id<>o.object_id)",
		"SELECT COUNT(*) FROM global_media_objects g JOIN cluster_storage_members s ON s.member_id=g.storage_member_id LEFT JOIN s3_objects o ON o.media_id=g.media_id WHERE s.member_kind='S3' AND (o.media_id IS NULL OR o.state<>'active')",
		"SELECT COUNT(*) FROM karaoke_recordings r JOIN cluster_storage_members s ON s.member_id=r.storage_member_id WHERE s.member_kind='S3'",
		"SELECT COUNT(*) FROM cluster_compute_members c JOIN cluster_storage_members s ON s.member_id=c.member_id WHERE s.member_kind='S3'",
		"SELECT COUNT(*) FROM cluster_backup_members b JOIN cluster_storage_members s ON s.member_id=b.member_id WHERE s.member_kind='S3'",
	} {
		var count int64
		if err := tx.QueryRowContext(ctx, query).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return store.ErrBackupState
		}
	}
	return nil
}

func projectS3BackupRow(table string, row map[string]any) bool {
	switch table {
	case "s3_members":
		row["sealed_credentials"] = ""
		row["credential_expires_at"] = int64(0)
		row["probe_revision"] = int64(0)
		row["probe_state"] = "unchecked"
		row["cleanup_only"] = int64(0)
		row["error_code"] = "credentials_required"
	case "cluster_storage_members":
		if row["member_kind"] == "S3" {
			row["storage_enabled"] = int64(0)
			row["writable"] = int64(0)
			row["health"] = "offline"
			row["physical_free_bytes"] = int64(0)
		}
	case "s3_objects":
		return row["state"] == "active"
	}
	return true
}
