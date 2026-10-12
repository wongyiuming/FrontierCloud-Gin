package business

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// No admin endpoint accepts a caller-supplied source proof. The bounded
// authenticated source verifier calls this after inspecting actual bytes.
func (r *Repository) AuthorizeMigrationShadowDeletion(ctx context.Context, l store.MigrationLease, id string, proof store.MigrationCleanupProof) (g store.MigrationShadowGrant, e error) {
	e = r.write(ctx, func(q queryer) error {
		t, e := r.checkMigrationLease(ctx, q, l)
		if e != nil {
			return e
		}
		now := time.Now().Unix()
		if t.State != "cancelling" || proof.ID != id || proof.VerifiedAt < now-30 || proof.VerifiedAt > now+30 {
			return store.ErrMigrationState
		}
		w, e := r.migrationWork(ctx, q, l.TaskID)
		if e != nil {
			return e
		}
		found := false
		for _, cp := range w.Objects {
			if cp.Object.ID != id {
				continue
			}
			if cp.State == "cancelled" || cp.State == "cleanup_pending" || cp.State == "cleaned" || cp.SourceSHA != proof.SHA256 || cp.Object.Version != proof.Version || cp.Object.Bytes != proof.Bytes {
				return store.ErrMigrationState
			}
			unit, e := r.migrationUnitCancelGrant(ctx, q, l, cp.UnitID)
			if e != nil {
				return e
			}
			g = store.MigrationShadowGrant{Unit: unit, Object: cp.Object, SourceProof: proof}
			found = true
			break
		}
		if !found {
			return store.ErrMigrationState
		}
		return nil
	})
	return
}
