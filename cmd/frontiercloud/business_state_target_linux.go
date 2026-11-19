//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func businessStateTargetGuard(settings config.Config, raw string) (func() error, error) {
	if settings.DeploymentMode != config.DeploymentBusiness || settings.DatabaseType != config.DatabaseSQLite || !settings.TLSEnabled {
		return nil, backup.ErrBusinessStateTarget
	}
	var expected []runtimefacts.TreeBackupMount
	if _, err := protocol.ParseStrictJSON([]byte(raw), 1024); err != nil ||
		json.Unmarshal([]byte(raw), &expected) != nil || len(expected) != 2 || expected[0].Inode == 0 || expected[1].Inode == 0 {
		return nil, backup.ErrBusinessStateTarget
	}
	return func() error {
		mounts, err := inspectRetainedTreeMounts([2]string{settings.DataRoot, settings.SecretsDirectory})
		if err != nil || mounts.Data != expected[0] || mounts.Secrets != expected[1] {
			return backup.ErrBusinessStateTarget
		}
		for _, hold := range []string{maintenance.TreeRecoveryHold, maintenance.OwnerImportHold} {
			if _, err := os.Lstat(filepath.Join(settings.DataRoot, hold)); !os.IsNotExist(err) {
				return backup.ErrBusinessStateTarget
			}
		}
		return nil
	}, nil
}

// A first-import target has no peers, managed placements, or selected writes.
// The bootstrap lyric and authenticated empty Owner are allowed.
func verifyFreshBusinessResources(ctx context.Context, db *sqlitestore.Store, root *os.Root) error {
	var occupied bool
	if err := db.Database().QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM node_relationships) OR EXISTS(SELECT 1 FROM global_media_objects) OR
		EXISTS(SELECT 1 FROM media_objects WHERE NOT (object_kind='lyric' AND media_path='lyrics/default.lrc')) OR
		EXISTS(SELECT 1 FROM s3_members) OR EXISTS(SELECT 1 FROM s3_objects) OR
		EXISTS(SELECT 1 FROM sealed_tree_records) OR EXISTS(SELECT 1 FROM sealed_tree_placements) OR
		EXISTS(SELECT 1 FROM sealed_tree_pending_files) OR EXISTS(SELECT 1 FROM sealed_tree_pending_facts) OR
		EXISTS(SELECT 1 FROM sealed_tree_revocations) OR EXISTS(SELECT 1 FROM sealed_tree_capacity_intents) OR
		EXISTS(SELECT 1 FROM legacy_read_control_intents) OR EXISTS(SELECT 1 FROM selected_upload_intents) OR
		EXISTS(SELECT 1 FROM selected_s3_uploads) OR EXISTS(SELECT 1 FROM karaoke_recordings) OR
		EXISTS(SELECT 1 FROM sealed_recording_audio)`).Scan(&occupied); err != nil || occupied {
		return backup.ErrBusinessStateTarget
	}
	return sealedtree.CheckEmptyStorageDestination(root)
}
