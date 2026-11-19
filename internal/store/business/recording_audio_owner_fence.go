package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// CheckRecordingOwnerExclusive accepts only this repository's live,
// unforgeable Owner-exclusive context. It grants no deletion authorization.
func (r *Repository) CheckRecordingOwnerExclusive(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	held, ok := ctx.Value(ownerControlContextKey{}).(*ownerControlContext)
	if !ok || held == nil || held.repository != r {
		return store.ErrNodeState
	}
	held.mu.RLock()
	defer held.mu.RUnlock()
	if held.closed || !validOwnerControlLease(held.lease) || held.lease.Check(ctx) != nil || r.checkOwnerControlMarker(ctx, r.db, held.lease) != nil {
		return store.ErrNodeState
	}
	return ctx.Err()
}
