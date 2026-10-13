package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RetirementMigration reads bounded archived bindings without acquiring a
// runner lease or making a terminal task executable again.
func (r *Repository) RetirementMigration(ctx context.Context, relationship, member, master, task, logical string) (v store.MigrationPeerObject, e error) {
	if !nodeIDPattern.MatchString(task) || (!nodeIDPattern.MatchString(logical) && !nodeHashPattern.MatchString(logical)) {
		return v, store.ErrMigrationState
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	if e = inventoryIdentity(ctx, tx, relationship, member, master); e != nil {
		return v, e
	}
	var plan, binding, bindingSHA, state, unit, unitState, unitResource, unitVersion, unitParent, sourceRel, planSHA string
	var journalMaster, source, target, object, resource, physical, version, sha string
	var planLength, bindingLength, bytes, count, total, committed, cleanup int64
	e = tx.QueryRowContext(ctx, `SELECT SUBSTR(t.plan,1,8193),LENGTH(t.plan),t.state,t.object_count,t.total_bytes,t.source_relationship,t.plan_sha256,
 SUBSTR(b.binding_json,1,16385),LENGTH(b.binding_json),SUBSTR(b.binding_sha256,1,65),
 j.master_id,j.source_id,j.target_id,j.object_id,j.resource_kind,j.physical_path,j.source_version,j.sha256,j.expected_bytes,j.state,j.unit_id,
 u.state,u.resource_kind,u.source_version,u.committed_at,u.cleanup_after,u.parent_path
 FROM migration_tasks t JOIN migration_storage_journal j ON j.task_id=t.task_id
 JOIN migration_peer_bindings b ON b.task_id=j.task_id AND b.logical_id=j.logical_id
 JOIN migration_units u ON u.task_id=j.task_id AND u.unit_id=j.unit_id
 WHERE t.task_id=? AND j.logical_id=? AND t.master_id=j.master_id AND t.source_id=j.source_id AND t.target_id=j.target_id AND t.target_relationship=?`, task, logical, relationship).Scan(&plan, &planLength, &state, &count, &total, &sourceRel, &planSHA, &binding, &bindingLength, &bindingSHA, &journalMaster, &source, &target, &object, &resource, &physical, &version, &sha, &bytes, &v.State, &unit, &unitState, &unitResource, &unitVersion, &committed, &cleanup, &unitParent)
	if e != nil {
		return v, e
	}
	if planLength > 8192 || bindingLength > peerBindingLimit || !nodeHashPattern.MatchString(bindingSHA) || !nodeHashPattern.MatchString(unitVersion) || state != "completed" && state != "cancelled" {
		return v, store.ErrMigrationState
	}
	decode := func(raw string, value any) bool {
		d := json.NewDecoder(strings.NewReader(raw))
		d.DisallowUnknownFields()
		return d.Decode(value) == nil && d.Decode(new(any)) == io.EOF
	}
	var record peerMigrationRecord
	if !decode(plan, &record) || !decode(binding, &v.Object) {
		return v, store.ErrMigrationState
	}
	v.Header = record.MigrationPeerHeader
	h, o := v.Header, v.Object
	v.Proof = store.MigrationDiskProof{ID: logical, Version: version, Bytes: bytes, SHA256: sha}
	actual, e := store.MigrationDigest(o)
	if e != nil {
		return v, e
	}
	if !validPeerHeader(h) || !validPeerObject(h, v) || h.TaskID != task || h.MasterID != master || h.TargetID != member || h.TargetRelationship != relationship || h.SourceRelationship != sourceRel || h.PlanSHA != planSHA || h.ObjectCount != count || h.Bytes != total || actual != bindingSHA || o.ID != logical || o.ObjectID != object || o.Version != version || o.Bytes != bytes || o.Resource != resource || o.TargetPath != physical || unit != migrationUnit(o) || unitResource != resource || unitParent != o.Parent || journalMaster != master || source != h.SourceID || target != h.TargetID {
		return v, store.ErrMigrationState
	}
	now := time.Now().Unix()
	cleaned := unitState == "cleaned" && committed > 0 && cleanup >= committed+3600 && cleanup <= now && (v.State == "published" || v.State == "deleted")
	cancelled := state == "cancelled" && unitState == "cancelled" && committed == 0 && cleanup == 0 && (v.State == "aborted" || v.State == "deleted")
	if record.CancellationOnly && (!cancelled || v.State != "aborted") {
		return v, store.ErrMigrationState
	}
	if !cleaned && !cancelled {
		return v, store.ErrMigrationState
	}
	var running int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_runners WHERE task_id=? AND expires_at>?", task, now).Scan(&running); e != nil {
		return v, e
	}
	if running != 0 {
		return v, store.ErrMigrationState
	}
	e = tx.Commit()
	return v, e
}
