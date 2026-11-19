package node

import (
	"context"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// AdmitSelectedDirectUpload verifies a short-lived Master capability against
// the actual paired credential and holds the locally applied Direct policy
// fence. This is not an HTTP route, does not itself issue the grant, establish
// a Master reservation, transfer bytes, or commit a placement. The caller
// owns the returned lease and must retain it through the synchronous operation.
// An already admitted stream may drain after the capability expires, but new
// requests must present a fresh capability. Admission has a bounded wait.
func (s *Service) AdmitSelectedDirectUpload(ctx context.Context, token string) (protocol.SelectedStorageUpload, store.OwnerControlLease, error) {
	return s.admitSelected(ctx, token, false, "Direct", "")
}

// Cleanup has a separate signed capability and cannot be authorized by an
// ordinary upload ticket. The Master must durably mark cancellation first.
func (s *Service) admitSelectedDirectCleanup(ctx context.Context, token string) (protocol.SelectedStorageUpload, store.OwnerControlLease, error) {
	return s.admitSelected(ctx, token, true, "Direct", "")
}

func (s *Service) admitSelected(ctx context.Context, token string, cleanup bool, policy, authenticatedRelation string) (protocol.SelectedStorageUpload, store.OwnerControlLease, error) {
	verify := protocol.VerifySelectedStorageUpload
	if cleanup {
		verify = protocol.VerifySelectedStorageCleanup
	}
	return s.admitSelectedCapability(ctx, token, policy, authenticatedRelation, verify)
}

func (s *Service) admitSelectedCapability(ctx context.Context, token, policy, authenticatedRelation string, verify func(string, string, int64) (protocol.SelectedStorageUpload, error)) (protocol.SelectedStorageUpload, store.OwnerControlLease, error) {
	var zero protocol.SelectedStorageUpload
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || ctx == nil || ctx.Err() != nil {
		return zero, nil, ErrCapability
	}
	if _, ok := ctx.Deadline(); !ok {
		return zero, nil, ErrCapability
	}
	id, err := capabilityHint(token)
	if err != nil {
		return zero, nil, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" {
		return zero, nil, ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, id)
	if err != nil || relation.ID != id || relation.Direction != "upstream" || relation.State != "active" || relation.Protocol != protocol.Version {
		return zero, nil, ErrCapability
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return zero, nil, ErrCapability
	}
	claim, err := verify(credential, token, time.Now().Unix())
	if err != nil || claim.Encryption == nil || claim.Relationship != id || claim.Master != relation.PeerID || claim.Owner != identity.ID || claim.Policy != policy || (authenticatedRelation != "" && claim.Relationship != authenticatedRelation) {
		return zero, nil, ErrCapability
	}
	policies, ok := s.repo.(store.SelectedUploadOwnerPolicyRepository)
	if !ok {
		return zero, nil, ErrCapability
	}
	lease, err := policies.AcquireSelectedUploadOwnerPolicy(ctx, store.SelectedUploadPolicy{RelationshipID: id, MasterID: claim.Master, OwnerID: claim.Owner, Transport: claim.Policy, Revision: claim.Revision, ResourceOrigin: claim.ResourceOrigin})
	if err != nil || lease == nil {
		return zero, nil, ErrCapability
	}
	accepted := false
	defer func() {
		if !accepted {
			lease.Release()
		}
	}()
	// A credential or identity may have changed between preliminary signature
	// verification and acquiring the fence. Re-read under that fence, and do
	// not accept a token that expired while waiting for admission.
	currentIdentity, err := s.repo.ReadIdentity(ctx)
	if err != nil || currentIdentity.ID != identity.ID || currentIdentity.Role != "Follower" {
		return zero, nil, ErrCapability
	}
	current, err := s.repo.Relationship(ctx, id)
	if err != nil || current.ID != relation.ID || current.PeerID != relation.PeerID || current.Direction != "upstream" || current.State != "active" || current.Protocol != protocol.Version || current.Credential != relation.Credential || current.CreatedAt != relation.CreatedAt || current.PublicKey != relation.PublicKey {
		return zero, nil, ErrCapability
	}
	confirmed, err := verify(credential, token, time.Now().Unix())
	if err != nil || !reflect.DeepEqual(confirmed, claim) || lease.Check(ctx) != nil {
		return zero, nil, ErrCapability
	}
	accepted = true
	return claim, lease, nil
}
