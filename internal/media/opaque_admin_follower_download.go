package media

import (
	"context"
	"encoding/json"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (s *Service) opaqueAdminDownloadOwner(ctx context.Context, masterID string, p sealedtree.Placement) (store.SelectedUploadPolicy, error) {
	var empty store.SelectedUploadPolicy
	relation, err := s.opaqueFollowerRelationship(ctx, p)
	routing, ok := s.nodes.(interface {
		ExistingNativeTransport(context.Context, string) (store.NativeTransportPolicy, error)
	})
	if err != nil || !ok {
		return empty, ErrOpaqueAdminDownloadOwner
	}
	policy, err := routing.ExistingNativeTransport(ctx, p.OwnerID)
	if err != nil || policy.MemberID != p.OwnerID || policy.Revision < 1 || policy.ConfiguredTransport != policy.AppliedTransport ||
		(policy.State != "applied" && !(policy.State == "retained" && policy.AppliedTransport == "Direct")) ||
		(policy.AppliedTransport != "Direct" && policy.AppliedTransport != "Relay") {
		return empty, ErrOpaqueAdminDownloadOwner
	}
	return store.SelectedUploadPolicy{RelationshipID: relation.ID, MasterID: masterID, OwnerID: p.OwnerID,
		Transport: policy.AppliedTransport, Revision: policy.Revision, ResourceOrigin: policy.AppliedOrigin}, nil
}

func opaqueAdminDownloadRevision(revision, objectID string, policy store.SelectedUploadPolicy) string {
	data, _ := json.Marshal([]any{revision, objectID, policy})
	return string(data)
}

func opaqueAdminDownloadBinding(item OpaqueAdminDownloadEntry) (protocol.OpaqueOwnerBinding, error) {
	p := item.placement
	if p.ObjectID != item.ResourceID || p.OwnerID != item.policy.OwnerID || item.Transport != item.policy.Transport || item.Snapshot == "" {
		return protocol.OpaqueOwnerBinding{}, ErrUnavailable
	}
	revision, err := opaqueSourceRevision(p)
	descriptor, descErr := protocol.IngressMediaDescriptor(p.Bytes, p.Encryption)
	if err != nil || descErr != nil {
		return protocol.OpaqueOwnerBinding{}, ErrUnavailable
	}
	return protocol.OpaqueOwnerBinding{MasterID: item.policy.MasterID, OwnerID: p.OwnerID, RelationshipID: item.policy.RelationshipID,
		Alias: p.ReadAlias, Blob: p.BlobID, Digest: p.SHA256, Size: p.Bytes, Revision: revision, Descriptor: descriptor}, nil
}

func (s *Service) OpaqueAdminFollowerDownloadGrant(ctx context.Context, item OpaqueAdminDownloadEntry) (OpaqueSourceDetails, int64, error) {
	var empty OpaqueSourceDetails
	if s == nil || s.control == nil || item.Transport != "Direct" && item.Transport != "Relay" {
		return empty, 0, ErrUnavailable
	}
	binding, err := opaqueAdminDownloadBinding(item)
	if err != nil {
		return empty, 0, err
	}
	origin, token, expiry, err := s.control.OpaqueAdminDownloadGrant(ctx, item.policy, binding, &item.Encryption, true)
	if err != nil {
		return empty, 0, ErrUnavailable
	}
	return OpaqueSourceDetails{Source: origin + "/internal/v1/opaque-media/" + binding.Alias, Origin: origin,
		Token: token, Revision: binding.Revision, Transport: item.Transport, SourceObjectID: binding.Alias,
		OwnerID: binding.OwnerID, Size: binding.Size}, expiry, nil
}

func (s *Service) OpenOpaqueAdminRelayDownload(ctx context.Context, item OpaqueAdminDownloadEntry, rangeValue string) (node.FollowerRelayResponse, error) {
	if s == nil || s.control == nil || item.Transport != "Relay" {
		return node.FollowerRelayResponse{}, ErrUnavailable
	}
	binding, err := opaqueAdminDownloadBinding(item)
	if err != nil {
		return node.FollowerRelayResponse{}, err
	}
	return s.control.OpenOpaqueAdminRelayDownload(ctx, item.policy, binding, &item.Encryption, rangeValue)
}
