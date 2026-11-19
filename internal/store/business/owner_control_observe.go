package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// VerifyOwnerControlBinding observes only the repository's durable marker.
// It does not acquire a lock, establish that the supplied digest came from a
// lease, authenticate a relationship, or authorize a write. The trusted caller
// must itself hold and recheck the real exclusive owner fence around this call
// and all subsequent identity checks and acknowledgements.
func (r *Repository) VerifyOwnerControlBinding(ctx context.Context, binding string) error {
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil || !nodeHashPattern.MatchString(binding) {
		return store.ErrNodeState
	}
	r.ownerControlMu.RLock()
	configured := r.ownerControlAcquire != nil
	r.ownerControlMu.RUnlock()
	if !configured || r.verifyOwnerFenceEngine(ctx, r.db) != nil {
		return store.ErrNodeState
	}
	var tag string
	if err := r.db.QueryRowContext(ctx, `SELECT fence_tag FROM sealed_tree_owner_fence WHERE singleton=1`).Scan(&tag); err != nil || tag != binding || ctx.Err() != nil {
		return store.ErrNodeState
	}
	return nil
}
