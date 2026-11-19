package node

import (
	"bytes"
	"context"
	"net/http"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ConfigureOpaqueOwnerRequestReadiness is startup-only. The lease must use the
// same durable local fence as all owner relationship and identity mutations,
// remaining held through the filesystem operation and receipt signing. No
// production implementation is installed while that contract is incomplete.
func (s *Service) ConfigureOpaqueOwnerRequestReadiness(acquire func(context.Context) (IngressPrerequisiteLease, error)) {
	if s != nil {
		s.opaqueOwnerRequestReady = acquire
	}
}

func (s *Service) AcquireOpaqueOwnerRequestFence(ctx context.Context) (IngressPrerequisiteLease, error) {
	if s == nil || ctx == nil || s.opaqueOwnerRequestReady == nil {
		return nil, ErrCapability
	}
	lease, err := s.opaqueOwnerRequestReady(ctx)
	if err != nil || !validPrerequisiteLease(lease) {
		if validPrerequisiteLease(lease) {
			lease.Release()
		}
		return nil, ErrCapability
	}
	if lease.Check(ctx) != nil {
		lease.Release()
		return nil, ErrCapability
	}
	return lease, nil
}

func opaqueRelationshipBinding(r store.Relationship) string {
	return store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: r.PeerID, RelationshipID: r.ID, PublicKey: r.PublicKey, ControlEndpoint: r.Endpoint, CredentialDigest: store.PeerCredentialDigest(r.Credential), CreatedAt: r.CreatedAt})
}

// The shared ingress lease is also the repository's relationship mutation
// fence. Release it before the tree ACK transaction; that transaction rechecks
// the persisted relationship binding under its own exclusive tree fence.
func (s *Service) acquireOpaqueRelationshipFence(ctx context.Context) (store.PublicIngressLease, error) {
	repository, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return nil, ErrCapability
	}
	_, lease, err := repository.AcquireCurrentIngress(ctx)
	if err != nil || !validIngressLease(lease) {
		if validIngressLease(lease) {
			lease.Release()
		}
		return nil, ErrCapability
	}
	return lease, nil
}

// SignOpaqueRevocationReceipt is called only after the owner has synced the
// permanent tombstone. It rechecks the exact active relationship before sign.
func (s *Service) SignOpaqueRevocationReceipt(ctx context.Context, relation store.Relationship, receipt protocol.OpaqueRevocationReceipt) (Envelope, error) {
	if s == nil || s.repo == nil || s.identity == nil {
		return Envelope{}, ErrCapability
	}
	payload, err := receipt.Payload()
	if err != nil {
		return Envelope{}, ErrCapability
	}
	return s.signOpaqueOwnerReceipt(ctx, relation, receipt.MasterID, receipt.OwnerID, receipt.RelationshipID, payload)
}

func (s *Service) SignOpaqueDeletionReceipt(ctx context.Context, relation store.Relationship, receipt protocol.OpaqueDeletionReceipt) (Envelope, error) {
	payload, err := receipt.Payload()
	if err != nil {
		return Envelope{}, ErrCapability
	}
	return s.signOpaqueOwnerReceipt(ctx, relation, receipt.MasterID, receipt.OwnerID, receipt.RelationshipID, payload)
}

func (s *Service) signOpaqueOwnerReceipt(ctx context.Context, relation store.Relationship, masterID, ownerID, relationshipID string, payload map[string]any) (Envelope, error) {
	if s == nil || s.repo == nil || s.identity == nil {
		return Envelope{}, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" || identity.ID != ownerID || relation.PeerID != masterID || relation.ID != relationshipID {
		return Envelope{}, ErrCapability
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "upstream" || current.Protocol != protocol.Version || current.PeerID != relation.PeerID || current.Credential != relation.Credential || current.PublicKey != relation.PublicKey || current.CreatedAt != relation.CreatedAt || ctx.Err() != nil {
		return Envelope{}, ErrCapability
	}
	return s.identity.signed(identity, payload)
}

// RequestOpaqueOwnerDeletionReceipt is only for an already-revoked pending
// delete. Its signed result proves durable unlink, not physical erasure.
func (s *Service) RequestOpaqueOwnerDeletionReceipt(ctx context.Context, receipt protocol.OpaqueDeletionReceipt, expectedBinding string) (Envelope, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || s.transport == nil {
		return Envelope{}, ErrCapability
	}
	lease, ok := store.OpaqueControlAuthorityFromContext(ctx, expectedBinding)
	if !ok || lease.Check(ctx) != nil {
		return Envelope{}, ErrCapability
	}
	relationshipFence, err := s.acquireOpaqueRelationshipFence(ctx)
	if err != nil {
		return Envelope{}, err
	}
	defer relationshipFence.Release()
	payload, err := receipt.Payload()
	if err != nil {
		return Envelope{}, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != receipt.MasterID {
		return Envelope{}, ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, receipt.RelationshipID)
	if err != nil || !resourceIdentifier.MatchString(expectedBinding) || opaqueRelationshipBinding(relation) != expectedBinding || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version || relation.PeerID != receipt.OwnerID {
		return Envelope{}, ErrCapability
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	response, err := s.transport.Request(ctx, relation.Endpoint, protocol.OpaqueDeletePath, http.MethodPost, payload, relation.ID, credential)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	signed, err := envelope(response)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	got, err := protocol.Canonical(signed.Payload)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	want, err := protocol.Canonical(payload)
	if err != nil || !bytes.Equal(got, want) || protocol.Verify(relation.PublicKey, signed.Payload, signed.Signature) != nil || ctx.Err() != nil {
		return Envelope{}, ErrCapability
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || lease.Check(ctx) != nil || opaqueRelationshipBinding(current) != expectedBinding || current.State != "active" || current.Direction != "downstream" || current.Protocol != relation.Protocol || current.PeerID != relation.PeerID || current.Endpoint != relation.Endpoint || current.PublicKey != relation.PublicKey || current.Credential != relation.Credential || current.CreatedAt != relation.CreatedAt {
		return Envelope{}, ErrCapability
	}
	if ctx.Err() != nil || lease.Check(ctx) != nil || relationshipFence.Commit() != nil {
		return Envelope{}, ErrCapability
	}
	return signed, nil
}

// RequestOpaqueOwnerRevocation returns only an owner-signed, exact-match ACK.
// The caller must first persist an encrypted Master intent that blocks new
// authorizations, and must separately commit it after verifying this result.
// A network failure is never a successful revocation.
func (s *Service) RequestOpaqueOwnerRevocation(ctx context.Context, request protocol.OpaqueRevocationRequest, expectedBinding string) (Envelope, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || s.transport == nil {
		return Envelope{}, ErrCapability
	}
	receipt, err := request.Receipt()
	if err != nil {
		return Envelope{}, ErrCapability
	}
	return s.RequestOpaqueOwnerRevocationReceipt(ctx, receipt, expectedBinding)
}

func (s *Service) RequestOpaqueOwnerRevocationReceipt(ctx context.Context, receipt protocol.OpaqueRevocationReceipt, expectedBinding string) (Envelope, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || s.transport == nil {
		return Envelope{}, ErrCapability
	}
	lease, ok := store.OpaqueControlAuthorityFromContext(ctx, expectedBinding)
	if !ok || lease.Check(ctx) != nil {
		return Envelope{}, ErrCapability
	}
	relationshipFence, err := s.acquireOpaqueRelationshipFence(ctx)
	if err != nil {
		return Envelope{}, err
	}
	defer relationshipFence.Release()
	requestPayload, err := receipt.Payload()
	if err != nil {
		return Envelope{}, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != receipt.MasterID {
		return Envelope{}, ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, receipt.RelationshipID)
	if err != nil || !resourceIdentifier.MatchString(expectedBinding) || opaqueRelationshipBinding(relation) != expectedBinding || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version || relation.PeerID != receipt.OwnerID {
		return Envelope{}, ErrCapability
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	response, err := s.transport.Request(ctx, relation.Endpoint, protocol.OpaqueRevokePath, http.MethodPost, requestPayload, relation.ID, credential)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	signed, err := envelope(response)
	if err != nil || s.VerifyOpaqueRevocationReceipt(ctx, relation.ID, receipt, signed) != nil {
		return Envelope{}, ErrCapability
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || lease.Check(ctx) != nil || opaqueRelationshipBinding(current) != expectedBinding || current.State != "active" || current.Direction != "downstream" || current.Protocol != relation.Protocol || current.PeerID != relation.PeerID || current.Endpoint != relation.Endpoint || current.PublicKey != relation.PublicKey || current.Credential != relation.Credential || current.CreatedAt != relation.CreatedAt {
		return Envelope{}, ErrCapability
	}
	if ctx.Err() != nil || lease.Check(ctx) != nil || relationshipFence.Commit() != nil {
		return Envelope{}, ErrCapability
	}
	return signed, nil
}

// VerifyOpaqueRevocationReceipt checks the current paired owner's signature
// and every field of the exact pending operation; it does not commit the tree.
func (s *Service) VerifyOpaqueRevocationReceipt(ctx context.Context, relationID string, receipt protocol.OpaqueRevocationReceipt, signed Envelope) error {
	if s == nil || s.repo == nil || relationID != receipt.RelationshipID {
		return ErrCapability
	}
	expected, err := receipt.Payload()
	if err != nil {
		return ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != receipt.MasterID {
		return ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, relationID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version || relation.PeerID != receipt.OwnerID {
		return ErrCapability
	}
	got, err := protocol.Canonical(signed.Payload)
	if err != nil {
		return ErrCapability
	}
	want, err := protocol.Canonical(expected)
	if err != nil || !bytes.Equal(got, want) || protocol.Verify(relation.PublicKey, signed.Payload, signed.Signature) != nil || ctx.Err() != nil {
		return ErrCapability
	}
	return nil
}
