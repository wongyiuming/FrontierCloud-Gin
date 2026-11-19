//go:build linux

package media

import (
	"context"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func sameLegacyRepository(a, b any) bool {
	x, y := reflect.ValueOf(a), reflect.ValueOf(b)
	return x.IsValid() && y.IsValid() && x.Kind() == reflect.Pointer && y.Kind() == reflect.Pointer && !x.IsNil() && !y.IsNil() && x.Type() == y.Type() && x.Pointer() == y.Pointer()
}

// VerifyLegacyOwnerVolume prevents a guarded control from opening another
// volume or another repository. The same local directory and vault must be
// used by media, owner control and the fence for every admission.
func (s *Service) VerifyLegacyOwnerVolume(ctx context.Context, repo store.NodeRepository, identity *node.Identity, fence *ownerfence.Fence) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.root == nil || s.identity == nil || identity == nil || fence == nil || !sameLegacyRepository(s.repository, repo) || !sameLegacyRepository(s.nodes, repo) || !sameLegacyRepository(s.owned, repo) || !fence.MatchesRootAndCodec(s.root, s.identity) || !fence.MatchesRootAndCodec(s.root, identity) {
		return store.ErrNodeState
	}
	return nil
}
