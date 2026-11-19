package node

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// OpaqueAdminDownloadGrant issues a narrow, Admin-origin credential after the
// caller verifies the exact encrypted placement under its Admin read lease.
func (s *Service) OpaqueAdminDownloadGrant(ctx context.Context, policy store.SelectedUploadPolicy, object protocol.OpaqueOwnerBinding, meta *mediacrypto.Metadata, probe bool) (string, string, int64, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || ctx == nil ||
		s.masterAdminOrigin == "" || policy.OwnerID != object.OwnerID || policy.RelationshipID != object.RelationshipID || policy.MasterID != object.MasterID {
		return "", "", 0, ErrCapability
	}
	authority := mediacrypto.DirectSessionFromContext(ctx)
	binding, session, sessionDeadline, ok := authority.Values()
	if !ok || !strings.HasPrefix(binding, "admin:") || (policy.Transport != "Direct" && policy.Transport != "Relay") {
		return "", "", 0, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != object.MasterID {
		return "", "", 0, ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, policy.RelationshipID)
	if err != nil || relation.PeerID != object.OwnerID || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version {
		return "", "", 0, ErrCapability
	}
	routing, ok := s.repo.(interface {
		ExistingNativeTransport(context.Context, string) (store.NativeTransportPolicy, error)
	})
	if !ok {
		return "", "", 0, ErrCapability
	}
	check := func() bool {
		current, err := routing.ExistingNativeTransport(ctx, object.OwnerID)
		return err == nil && current.MemberID == object.OwnerID && current.Revision == policy.Revision &&
			current.ConfiguredTransport == policy.Transport && current.AppliedTransport == policy.Transport &&
			current.AppliedOrigin == policy.ResourceOrigin && (current.State == "applied" || current.State == "retained" && policy.Transport == "Direct")
	}
	if !check() || probe && (s.nativeTransportReady == nil || s.nativeTransportReady(ctx, relation, policy.Transport) != nil) {
		return "", "", 0, ErrCapability
	}
	origin := relation.Endpoint
	if policy.Transport == "Direct" {
		origin = policy.ResourceOrigin
		if probe {
			confirmed, err := s.VerifyFollowerResourceIdentity(ctx, relation.ID)
			if err != nil || confirmed != origin {
				return "", "", 0, ErrCapability
			}
		}
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return "", "", 0, ErrCapability
	}
	now := time.Now().Unix()
	lifetime := int64(protocol.TokenSeconds)
	if policy.Transport == "Relay" {
		lifetime = 30
	}
	expires := min(sessionDeadline, now+lifetime)
	token, err := protocol.OpaqueAdminDownloadToken(credential, relation.ID, identity.ID, object.OwnerID, object.Alias, s.masterAdminOrigin,
		session, object.Blob, policy.Transport, policy.ResourceOrigin, policy.Revision, now, expires, object.Size, object.Digest, meta)
	if _, _, _, alive := authority.Values(); err != nil || !alive || ctx.Err() != nil || !check() {
		return "", "", 0, ErrCapability
	}
	return origin, token, expires, nil
}

// OpenOpaqueAdminRelayDownload reads one authenticated ciphertext range over
// the existing pinned Owner transport. It is used only for explicit Relay.
func (s *Service) OpenOpaqueAdminRelayDownload(ctx context.Context, policy store.SelectedUploadPolicy, object protocol.OpaqueOwnerBinding, meta *mediacrypto.Metadata, byteRange string) (FollowerRelayResponse, error) {
	if policy.Transport != "Relay" || byteRange == "" {
		return FollowerRelayResponse{}, ErrCapability
	}
	origin, token, _, err := s.OpaqueAdminDownloadGrant(ctx, policy, object, meta, false)
	if err != nil {
		return FollowerRelayResponse{}, err
	}
	client, ok := s.transport.(opaqueFollowerRelayReadClient)
	if !ok {
		return FollowerRelayResponse{}, ErrCapability
	}
	return client.MediaOpaqueRelayRead(ctx, origin, object.Alias, token, http.MethodGet, byteRange, object.Size)
}

func (s *Service) AcquireOpaqueAdminDownloadOwnerPolicy(ctx context.Context, relation store.Relationship, claims map[string]any) (store.OwnerControlLease, error) {
	policies, ok := s.repo.(store.SelectedUploadOwnerPolicyRepository)
	revision, revisionOK := claims["generation"].(json.Number)
	if !ok || !revisionOK {
		return nil, ErrCapability
	}
	value, err := revision.Int64()
	if err != nil {
		return nil, ErrCapability
	}
	return policies.AcquireSelectedUploadOwnerPolicy(ctx, store.SelectedUploadPolicy{RelationshipID: relation.ID,
		MasterID: textField(claims, "m"), OwnerID: textField(claims, "o"), Transport: textField(claims, "transport"),
		Revision: value, ResourceOrigin: textField(claims, "target_origin")})
}
