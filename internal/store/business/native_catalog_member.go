package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// NativeCatalogMember reads only the named native member. The trusted caller
// must hold the owner and ingress fences while comparing this observation.
// It does not verify a relationship or authorize use of an object.
func (r *Repository) NativeCatalogMember(ctx context.Context, id string) (store.StorageMember, error) {
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil || !nodeIDPattern.MatchString(id) {
		return store.StorageMember{}, store.ErrNodeState
	}
	member, err := scanMember(r.db.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?", id))
	if err != nil || member.ID != id || member.Kind != "MasterLocal" && member.Kind != "Follower" {
		return store.StorageMember{}, store.ErrNodeState
	}
	return member, nil
}
