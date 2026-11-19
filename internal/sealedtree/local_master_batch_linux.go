//go:build linux

package sealedtree

import (
	"context"
	"database/sql"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

const localMasterBatchLimit = 16

// localMasterBatch is progress, not a proof of full migration or readiness.
// Each committed operation is persisted in the tree. Restarting from an empty
// cursor revalidates those operations and is safe; the caller's cursor is not
// trusted as a completeness proof.
type localMasterBatch struct {
	After     string
	Processed int
	HasMore   bool
}

func migrateLocalMasterBatchOffline(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, s *SQLStore, treeRoot, mediaRoot *os.Root, ownerFence *ownerfence.Fence, nodeVault *vault.Vault, masterID, after string, limit int) (localMasterBatch, error) {
	result := localMasterBatch{After: after}
	if (after != "" && !hexID(after)) || limit < 1 || limit > localMasterBatchLimit {
		return result, ErrInvalid
	}
	err := withLocalMasterScope(ctx, gate, dataRoot, databasePath, s, treeRoot, mediaRoot, ownerFence, nodeVault, masterID, func(scope *localMasterScope) error {
		tx, err := scope.s.db.BeginTx(scope.ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		if err = scope.guard(tx); err != nil {
			tx.Rollback()
			return err
		}
		// Enumerate all old candidate media, including unsupported owners and
		// states, so an unhandled resource stops the batch instead of disappearing.
		rows, err := tx.QueryContext(scope.ctx, `SELECT candidate.media_id,COALESCE(member.member_kind='S3' AND member.transport='S3',0)
			FROM (SELECT media_id FROM global_media_objects UNION SELECT media_id FROM media_objects WHERE object_kind IN ('audio','video','lyric') AND media_path<>'lyrics/default.lrc') candidate
			LEFT JOIN global_media_objects media ON media.media_id=candidate.media_id
			LEFT JOIN cluster_storage_members member ON member.member_id=media.storage_member_id
			WHERE candidate.media_id>? ORDER BY candidate.media_id LIMIT ?`, after, limit+1)
		if err != nil {
			tx.Rollback()
			return err
		}
		type candidate struct {
			id string
			s3 bool
		}
		items := make([]candidate, 0, limit+1)
		for rows.Next() {
			var item candidate
			if err = rows.Scan(&item.id, &item.s3); err != nil || !hexID(item.id) {
				rows.Close()
				tx.Rollback()
				return ErrInvalid
			}
			items = append(items, item)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			tx.Rollback()
			return err
		}
		if err = rows.Close(); err != nil {
			tx.Rollback()
			return err
		}
		if err = scope.guard(tx); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Rollback(); err != nil {
			return err
		}
		if len(items) > limit {
			result.HasMore = true
			items = items[:limit]
		}
		for _, item := range items {
			if item.s3 {
				if e := migrateLegacyS3Held(scope, item.id); e != nil {
					return e
				}
			} else {
				p, verified, e := prepareLocalMasterHeld(scope, item.id)
				if e != nil {
					return e
				}
				if !verified {
					if e = publishLocalMasterHeld(scope, p.OperationID); e != nil {
						return e
					}
				}
			}
			if e := scope.checkFences(); e != nil {
				return e
			}
			result.After = item.id
			result.Processed++
		}
		return nil
	})
	return result, err
}
