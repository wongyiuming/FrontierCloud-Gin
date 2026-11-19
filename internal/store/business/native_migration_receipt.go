package business

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RecordNativeMigrationTargetReceipt consumes the admitted challenge only once.
// A retry may recover the same signed proof after its challenge expires, but a
// new proof always needs the current lease, current pairing and live challenge.
func (r *Repository) RecordNativeMigrationTargetReceipt(ctx context.Context, key []byte, lease store.MigrationLease, unitIndex, objectIndex string, receipt protocol.OpaqueMigrationTargetReceipt, signature string) error {
	taskIndex := nativeMigrationTaskIndex(key, lease.TaskID)
	if r == nil || ctx == nil || taskIndex == "" || !nodeHashPattern.MatchString(unitIndex) || !nodeHashPattern.MatchString(objectIndex) || len(signature) != 86 {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(c queryer) error {
		task, err := r.checkMigrationLease(ctx, c, lease)
		if err != nil {
			return err
		}
		if !migrationRunnable(task.State) || task.State == "cleanup_pending" {
			return store.ErrMigrationState
		}
		intent, err := r.loadNativeMigrationTask(ctx, c, key, taskIndex, task)
		if err != nil {
			return err
		}
		unit, err := r.loadNativeMigrationUnit(ctx, c, key, taskIndex, unitIndex, intent)
		if err != nil {
			return err
		}
		if unit.state != "publishing" || !unit.activeParent.Valid || unit.committedAt != 0 {
			return store.ErrMigrationState
		}
		object, err := r.loadNativeMigrationObject(ctx, c, key, taskIndex, unitIndex, objectIndex, intent, unit.intent)
		if err != nil {
			return err
		}
		if object.verified != object.intent.Object.Bytes || object.retiredAlias.Valid {
			return store.ErrMigrationState
		}
		_, _, targetPublic, err := r.nativeMigrationPeers(ctx, c, intent, time.Now().Unix())
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if object.state == "published" && object.receiptID.Valid {
			old, err := openNativeMigrationReceipt(key, taskIndex, unitIndex, objectIndex, object.receiptID.String, object.signed)
			if err != nil || old.Receipt != receipt || old.Signature != signature || old.AcceptedAt > now || verifyNativeMigrationReceipt(object.intent, old, targetPublic) != nil {
				return store.ErrMigrationState
			}
			return nil
		}
		if object.state != "publishing" || object.receiptID.Valid || len(object.signed) != 0 {
			return store.ErrMigrationState
		}
		record := nativeMigrationReceiptRecord{TaskID: task.ID, UnitID: unit.intent.UnitID, ObjectID: object.intent.Object.ObjectID, Receipt: receipt, Signature: signature, AcceptedAt: now}
		if err := verifyNativeMigrationReceipt(object.intent, record, targetPublic); err != nil {
			return err
		}
		enc, sealed, err := sealNativeMigrationReceipt(key, record)
		if err != nil {
			return err
		}
		if _, err := r.checkMigrationLease(ctx, c, lease); err != nil {
			return err
		}
		result, err := c.ExecContext(ctx, `UPDATE opaque_migration_objects SET state='published',receipt_encryption_id=?,receipt_sealed=?,updated_at=?
			WHERE task_id=? AND unit_id=? AND object_index=? AND state='publishing' AND receipt_encryption_id IS NULL AND receipt_sealed IS NULL`,
			enc, sealed, now, task.ID, unitIndex, objectIndex)
		return nativeMigrationChangedOne(result, err)
	})
}
