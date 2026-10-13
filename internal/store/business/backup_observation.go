package business

import (
	"context"
	"database/sql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) ReadyBackupManifest(ctx context.Context, relationship, member, master string, generation int64) (store.BackupManifest, error) {
	var empty store.BackupManifest
	if generation <= 0 {
		return empty, store.ErrBackupState
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	if e = inventoryIdentity(ctx, tx, relationship, member, master); e != nil {
		return empty, e
	}
	manifest, e := scanBackup(tx.QueryRowContext(ctx, "SELECT "+backupReadColumns+" FROM cluster_business_backups WHERE master_id=? AND generation=? AND state='ready'", master, generation))
	if e != nil {
		return empty, e
	}
	if manifest.State != "ready" || !nodeHashPattern.MatchString(manifest.Checksum) || manifest.Bytes < 0 || manifest.Chunks < 1 || manifest.Chunks > store.MaxBackupChunkIndex+1 || manifest.Bytes > int64(manifest.Chunks)*store.MaxBackupChunk {
		return empty, store.ErrBackupState
	}
	return manifest, nil
}
