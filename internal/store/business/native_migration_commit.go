package business

import (
	"context"
	"database/sql"
	"math"
	"slices"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const nativeMigrationCleanupGrace = 3600

type nativeMigrationUnitState struct {
	intent                    nativeMigrationUnitRecord
	state, encryptionID       string
	activeParent              sql.NullString
	committedAt, cleanupAfter int64
}

type nativeMigrationObjectState struct {
	intent       nativeMigrationObjectRecord
	state        string
	verified     int64
	retiredAlias sql.NullString
	receiptID    sql.NullString
	signed       []byte
}

// CommitNativeMigrationUnit changes the whole authenticated parent and settles
// the Master quota under the same SQLite transaction. The worker must already
// have stored each admitted target publication and its signed receipt.
func (r *Repository) CommitNativeMigrationUnit(ctx context.Context, tree *sealedtree.SQLStore, key []byte, lease store.MigrationLease, unitIndex string, audit store.NodeAudit) error {
	taskIndex := nativeMigrationTaskIndex(key, lease.TaskID)
	if ctx == nil || taskIndex == "" || !nodeHashPattern.MatchString(unitIndex) {
		return store.ErrMigrationState
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		task, err := r.checkMigrationLease(c, q, lease)
		if err != nil {
			return err
		}
		intent, err := r.loadNativeMigrationTask(c, q, key, taskIndex, task)
		if err != nil {
			return err
		}
		unit, err := r.loadNativeMigrationUnit(c, q, key, taskIndex, unitIndex, intent)
		if err != nil {
			return err
		}
		if err := checkNativeMigrationTotals(c, q, intent, task.CommittedBytes); err != nil {
			return err
		}
		if unit.state == "cleanup_pending" || unit.state == "cleaned" {
			return checkNativeMigrationCommittedUnit(c, q, intent.TaskID, unitIndex, unit)
		}
		if unit.state != "publishing" || !unit.activeParent.Valid || unit.committedAt != 0 || unit.cleanupAfter != 0 ||
			!migrationRunnable(task.State) || task.State == "cleanup_pending" || task.Revision == math.MaxInt64 ||
			unit.intent.Bytes > task.TotalBytes-task.CommittedBytes {
			return store.ErrMigrationState
		}
		now := time.Now().Unix()
		source, target, targetPublic, err := r.nativeMigrationPeers(c, q, intent, now)
		if err != nil {
			return err
		}
		cutover := sealedtree.NativeMigrationCutover{Unit: unit.intent.Unit, MasterID: intent.MasterID, TargetOwnerID: target.ID, TargetRelationshipID: intent.TargetRelationshipID}
		bytes, err := mutation.CutoverNativeMigrationUnitTx(c, q, cutover, func(c context.Context, object sealedtree.NativeMigrationObject) (sealedtree.NativeMigrationPublication, error) {
			return r.nativeMigrationPublicationForCutover(c, q, key, taskIndex, unitIndex, targetPublic, intent, unit.intent, object, now)
		})
		if err != nil {
			return err
		}
		if bytes != unit.intent.Bytes {
			return store.ErrMigrationState
		}
		if _, err := r.checkMigrationLease(c, q, lease); err != nil {
			return err
		}
		now = time.Now().Unix()
		if err := r.settleMigrationCapacityTx(c, q, task.ID, source, target, bytes, now); err != nil {
			return err
		}
		unit.intent.CommittedAt, unit.intent.CleanupAfter = now, now+nativeMigrationCleanupGrace
		enc, sealed, err := sealNativeMigrationUnit(key, unit.intent)
		if err != nil {
			return err
		}
		result, err := q.ExecContext(c, `UPDATE opaque_migration_units SET state='cleanup_pending',committed_at=?,cleanup_after=?,encryption_id=?,sealed=?
			WHERE task_id=? AND unit_id=? AND state='publishing' AND committed_at=0 AND cleanup_after=0 AND encryption_id=?`,
			now, now+nativeMigrationCleanupGrace, enc, sealed, task.ID, unitIndex, unit.encryptionID)
		if err := nativeMigrationChangedOne(result, err); err != nil {
			return err
		}
		unit.state, unit.committedAt, unit.cleanupAfter = "cleanup_pending", now, now+nativeMigrationCleanupGrace
		if err := checkNativeMigrationCommittedUnit(c, q, task.ID, unitIndex, unit); err != nil {
			return err
		}
		return r.advanceNativeMigrationCommit(c, q, task, unitIndex, unit, bytes, now, audit)
	})
}

func (r *Repository) loadNativeMigrationTask(ctx context.Context, q queryer, key []byte, taskIndex string, task store.MigrationTask) (nativeMigrationTaskRecord, error) {
	var id string
	var sealed []byte
	if err := q.QueryRowContext(ctx, `SELECT intent_encryption_id,intent_sealed FROM opaque_migration_tasks WHERE task_id=?`+r.lock(), task.ID).Scan(&id, &sealed); err != nil {
		return nativeMigrationTaskRecord{}, err
	}
	intent, err := openNativeMigrationTask(key, taskIndex, id, sealed)
	if err != nil || intent.TaskID != task.ID || intent.MasterID != task.MasterID || intent.SourceOwnerID != task.SourceID || intent.TargetOwnerID != task.TargetID ||
		intent.PlanSHA != task.PlanSHA || intent.ObjectCount != task.ObjectCount || intent.Bytes != task.TotalBytes {
		return nativeMigrationTaskRecord{}, store.ErrMigrationState
	}
	return intent, nil
}

func (r *Repository) loadNativeMigrationUnit(ctx context.Context, q queryer, key []byte, taskIndex, unitIndex string, task nativeMigrationTaskRecord) (nativeMigrationUnitState, error) {
	var state nativeMigrationUnitState
	var parentIndex string
	var count, total int64
	var sealed []byte
	err := q.QueryRowContext(ctx, `SELECT parent_index,active_parent_index,state,object_count,total_bytes,committed_at,cleanup_after,encryption_id,sealed
		FROM opaque_migration_units WHERE task_id=? AND unit_id=?`+r.lock(), task.TaskID, unitIndex).
		Scan(&parentIndex, &state.activeParent, &state.state, &count, &total, &state.committedAt, &state.cleanupAfter, &state.encryptionID, &sealed)
	if err != nil {
		return nativeMigrationUnitState{}, err
	}
	state.intent, err = openNativeMigrationUnit(key, taskIndex, unitIndex, state.encryptionID, sealed)
	if err != nil || state.intent.TaskID != task.TaskID || state.intent.Unit.SourceOwnerID != task.SourceOwnerID ||
		state.intent.Unit.ObjectCount != count || state.intent.Bytes != total || parentIndex != nativeMigrationParentIndex(key, state.intent.Unit.ParentID) ||
		state.intent.CommittedAt != state.committedAt || state.intent.CleanupAfter != state.cleanupAfter ||
		state.activeParent.Valid && state.activeParent.String != parentIndex {
		return nativeMigrationUnitState{}, store.ErrMigrationState
	}
	return state, nil
}

func checkNativeMigrationTotals(ctx context.Context, q queryer, intent nativeMigrationTaskRecord, committedBytes int64) error {
	var units, objects, total, committed int64
	err := q.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(object_count),0),COALESCE(SUM(total_bytes),0),
		COALESCE(SUM(CASE WHEN committed_at>0 THEN total_bytes ELSE 0 END),0) FROM opaque_migration_units WHERE task_id=?`, intent.TaskID).
		Scan(&units, &objects, &total, &committed)
	if err != nil {
		return err
	}
	if units != intent.UnitCount || objects != intent.ObjectCount || total != intent.Bytes || committed != committedBytes {
		return store.ErrMigrationState
	}
	return nil
}

func checkNativeMigrationCommittedUnit(ctx context.Context, q queryer, taskID, unitIndex string, unit nativeMigrationUnitState) error {
	if unit.committedAt <= 0 || unit.cleanupAfter < unit.committedAt || unit.cleanupAfter-unit.committedAt < nativeMigrationCleanupGrace ||
		(unit.state == "cleanup_pending") != unit.activeParent.Valid {
		return store.ErrMigrationState
	}
	var count, total int64
	var incomplete bool
	err := q.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(expected_bytes),0),COALESCE(MAX(CASE WHEN state NOT IN ('cleanup_pending','cleaned')
		OR (?='cleaned' AND state<>'cleaned') OR retired_alias_index IS NULL OR receipt_sealed IS NULL OR expected_bytes<>verified_bytes THEN 1 ELSE 0 END),0)
		FROM opaque_migration_objects WHERE task_id=? AND unit_id=?`, unit.state, taskID, unitIndex).Scan(&count, &total, &incomplete)
	if err != nil {
		return err
	}
	if incomplete || count != unit.intent.Unit.ObjectCount || total != unit.intent.Bytes {
		return store.ErrMigrationState
	}
	return nil
}

func (r *Repository) nativeMigrationPeers(ctx context.Context, q queryer, intent nativeMigrationTaskRecord, now int64) (source, target store.StorageMember, targetPublic string, err error) {
	type peer struct {
		id, relationship, binding string
		member                    *store.StorageMember
	}
	peers := []peer{{intent.SourceOwnerID, intent.SourceRelationshipID, intent.SourceRelationshipBinding, &source},
		{intent.TargetOwnerID, intent.TargetRelationshipID, intent.TargetRelationshipBinding, &target}}
	if peers[0].id > peers[1].id {
		peers[0], peers[1] = peers[1], peers[0]
	}
	for _, expected := range peers {
		member, err := scanMember(q.QueryRowContext(ctx, `SELECT `+memberColumns+` FROM cluster_storage_members WHERE member_id=?`+r.lock(), expected.id))
		if err != nil {
			return source, target, "", err
		}
		if member.Kind != "Follower" || member.Health != "online" || member.RelationshipID == nil || *member.RelationshipID != expected.relationship ||
			member.Transport != "Direct" && member.Transport != "Relay" {
			return source, target, "", store.ErrMigrationState
		}
		rel, err := scanRelation(q.QueryRowContext(ctx, `SELECT `+relationColumns+` FROM node_relationships WHERE relationship_id=?`+r.lock(), expected.relationship))
		if err != nil {
			return source, target, "", err
		}
		binding, err := migrationBinding(rel)
		caps, capsErr := protocol.ReadCapabilities(rel.Summary)
		if err != nil || binding != expected.binding || capsErr != nil || !slices.Contains(caps, store.OpaqueMigrationCapability) ||
			rel.PeerID != expected.id || rel.State != "active" || rel.Direction != "downstream" || rel.Protocol != protocol.Version ||
			rel.Mode != member.Transport || rel.Status != "online" || rel.LastHeartbeat < now-119 || rel.LastHeartbeat > now+30 {
			return source, target, "", store.ErrMigrationState
		}
		*expected.member = member
		if expected.id == intent.TargetOwnerID {
			targetPublic = rel.PublicKey
		}
	}
	var sourceDrain, targetDrain bool
	err = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM migration_drains WHERE member_id=? AND owner_id=? AND reason='migration'),
		EXISTS(SELECT 1 FROM migration_drains WHERE member_id=?)`, source.ID, intent.TaskID, target.ID).Scan(&sourceDrain, &targetDrain)
	if err == nil && (!sourceDrain || targetDrain) {
		err = store.ErrMigrationState
	}
	return source, target, targetPublic, err
}

func (r *Repository) nativeMigrationPublicationForCutover(ctx context.Context, q queryer, key []byte, taskIndex, unitIndex, targetPublic string, task nativeMigrationTaskRecord, unit nativeMigrationUnitRecord, object sealedtree.NativeMigrationObject, now int64) (sealedtree.NativeMigrationPublication, error) {
	var empty sealedtree.NativeMigrationPublication
	index := nativeMigrationObjectIndex(key, task.TaskID, unit.UnitID, object.ObjectID)
	state, err := r.loadNativeMigrationObject(ctx, q, key, taskIndex, unitIndex, index, task, unit)
	if err != nil {
		return empty, err
	}
	if state.state != "published" || state.intent.Object != object || state.verified != object.Bytes || state.retiredAlias.Valid || !state.receiptID.Valid {
		return empty, store.ErrMigrationState
	}
	receipt, err := openNativeMigrationReceipt(key, taskIndex, unitIndex, index, state.receiptID.String, state.signed)
	if err != nil || receipt.AcceptedAt > now || verifyNativeMigrationReceipt(state.intent, receipt, targetPublic) != nil {
		return empty, store.ErrMigrationState
	}
	aliasIndex := nativeMigrationRetiredAliasIndex(key, task.SourceOwnerID, object.ReadAlias)
	result, err := q.ExecContext(ctx, `UPDATE opaque_migration_objects SET state='cleanup_pending',retired_alias_index=?,updated_at=?
		WHERE task_id=? AND unit_id=? AND object_index=? AND state='published' AND retired_alias_index IS NULL`, aliasIndex, now, task.TaskID, unitIndex, index)
	if err := nativeMigrationChangedOne(result, err); err != nil {
		return empty, err
	}
	return sealedtree.NativeMigrationPublication{SourceOperationID: state.intent.SourceOperationID, OperationID: receipt.Receipt.PublicationOperation, Binding: receipt.Receipt.Target}, nil
}

func (r *Repository) loadNativeMigrationObject(ctx context.Context, q queryer, key []byte, taskIndex, unitIndex, index string, task nativeMigrationTaskRecord, unit nativeMigrationUnitRecord) (nativeMigrationObjectState, error) {
	var state nativeMigrationObjectState
	var id string
	var expectedBytes int64
	var sealed []byte
	err := q.QueryRowContext(ctx, `SELECT state,expected_bytes,verified_bytes,retired_alias_index,encryption_id,sealed,receipt_encryption_id,receipt_sealed
		FROM opaque_migration_objects WHERE task_id=? AND unit_id=? AND object_index=?`+r.lock(), task.TaskID, unitIndex, index).
		Scan(&state.state, &expectedBytes, &state.verified, &state.retiredAlias, &id, &sealed, &state.receiptID, &state.signed)
	if err != nil {
		return nativeMigrationObjectState{}, err
	}
	intent, err := openNativeMigrationObject(key, taskIndex, unitIndex, index, id, sealed)
	if err != nil || intent.TaskID != task.TaskID || intent.UnitID != unit.UnitID || intent.Object.Bytes != expectedBytes ||
		intent.Expected.Source.MasterID != task.MasterID || intent.Expected.Source.OwnerID != task.SourceOwnerID || intent.Expected.Source.RelationshipID != task.SourceRelationshipID ||
		intent.Expected.Target.OwnerID != task.TargetOwnerID || intent.Expected.Target.RelationshipID != task.TargetRelationshipID ||
		intent.Expected.SourceRelationshipBinding != task.SourceRelationshipBinding || intent.Expected.TargetRelationshipBinding != task.TargetRelationshipBinding {
		return nativeMigrationObjectState{}, store.ErrMigrationState
	}
	state.intent = intent
	return state, nil
}

func (r *Repository) advanceNativeMigrationCommit(ctx context.Context, q queryer, task store.MigrationTask, unitIndex string, unit nativeMigrationUnitState, bytes, now int64, audit store.NodeAudit) error {
	state := task.State
	var unfinished bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM opaque_migration_units WHERE task_id=? AND state NOT IN ('cleanup_pending','cleaned'))`, task.ID).Scan(&unfinished); err != nil {
		return err
	}
	if !unfinished {
		if task.CommittedBytes+bytes != task.TotalBytes {
			return store.ErrMigrationState
		}
		state = "cleanup_pending"
	}
	result, err := q.ExecContext(ctx, `UPDATE migration_tasks SET state=?,committed_bytes=?,revision=revision+1,updated_at=? WHERE task_id=? AND revision=?`,
		state, task.CommittedBytes+bytes, now, task.ID, task.Revision)
	if err := nativeMigrationChangedOne(result, err); err != nil {
		return err
	}
	return r.nodeAudit(ctx, q, "resource-migration-opaque-unit-committed", "", map[string]any{
		"task_id": task.ID, "unit_id": unitIndex, "source_id": task.SourceID, "target_id": task.TargetID,
		"objects": unit.intent.Unit.ObjectCount, "bytes": bytes,
	}, audit)
}

func nativeMigrationChangedOne(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return store.ErrMigrationState
	}
	return nil
}
