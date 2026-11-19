package node

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// CheckLegacySelectedUploadRelationship catches an unusable credential before
// reserving capacity. It makes no network request and grants no authority.
// The reservation still checks current SQL policy and issuance rechecks the
// relationship because it can change after this observation.
func (s *Service) CheckLegacySelectedUploadRelationship(ctx context.Context, member store.StorageMember) error {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || member.Kind != "Follower" {
		return store.ErrNodeState
	}
	relation, err := s.storageRelation(ctx, store.UploadReservation{MemberID: member.ID, Member: member})
	if err != nil || relation.Protocol != protocol.Version || relation.Mode != member.Transport {
		return store.ErrNodeState
	}
	canonical, err := Endpoint(relation.Endpoint)
	if err != nil || canonical != relation.Endpoint {
		return store.ErrNodeState
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return store.ErrNodeState
	}
	key, err := protocol.Decode(credential)
	defer clear(key)
	if err != nil || len(key) != 48 {
		return store.ErrNodeState
	}
	return nil
}
