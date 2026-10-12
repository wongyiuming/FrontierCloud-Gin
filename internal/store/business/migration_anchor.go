package business

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Only the active upstream Master grants retirement after its source-deletion
// receipt. Local target publication/bytes/binding must still match that grant.
func (r *Repository) ValidatePeerAnchorRetirement(ctx context.Context, relationship string, l store.MigrationLease, g store.MigrationCleanupGrant, fresh bool) error {
	now := time.Now().Unix()
	if !g.SourceCopyDeleted || g.TaskID != l.TaskID || !nodeHashPattern.MatchString(g.UnitVersion) || g.CommittedAt <= 0 || g.CleanupAfter < g.CommittedAt+3600 || g.CleanupAfter > now || g.TargetVerifiedAt < g.CommittedAt || fresh && (g.TargetVerifiedAt < now-30 || g.TargetVerifiedAt > now+30) {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		h, n, state, e := r.checkPeerLease(ctx, q, relationship, l)
		if e != nil {
			return e
		}
		if n.ID != h.TargetID || state == "cancelling" || g.MasterID != h.MasterID || g.SourceID != h.SourceID || g.TargetID != h.TargetID || g.PlanSHA != h.PlanSHA {
			return store.ErrMigrationState
		}
		o, e := r.peerObjectBinding(ctx, q, l.TaskID, g.Object.ID)
		if e != nil {
			return e
		}
		expected, e := store.MigrationDigest(o)
		if e != nil {
			return e
		}
		actual, e := store.MigrationDigest(g.Object)
		if e != nil || expected != actual || g.UnitID != migrationUnit(o) {
			return store.ErrMigrationState
		}
		var phase, sha, version string
		var bytes int64
		if e = q.QueryRowContext(ctx, "SELECT state,sha256,source_version,expected_bytes FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, o.ID).Scan(&phase, &sha, &version, &bytes); e != nil {
			return e
		}
		if phase != "published" || sha != g.SHA256 || version != o.Version || bytes != o.Bytes {
			return store.ErrMigrationState
		}
		return nil
	})
}
