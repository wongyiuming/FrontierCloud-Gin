package media

import (
	"context"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// OpaqueMasterPeerMedia issues a Master-owned audio/video source while the
// authenticated peer ingress and tree admission are held. The existing node
// grant verifies the explicitly applied Direct or Relay policy.
func (s *Service) OpaqueMasterPeerMedia(ctx context.Context, tree *sealedtree.SQLStore, expected store.MediaObject, objectID, mode, directOrigin string) (OpaqueSourceDetails, error) {
	var empty OpaqueSourceDetails
	if s == nil || s.control == nil || tree == nil || ctx == nil || objectID == "" || (mode != "Direct" && mode != "Relay") {
		return empty, ErrUnavailable
	}
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	lease, leased := ingressTreeAuthority(ctx)
	if !ok || !leased || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		return empty, ErrUnavailable
	}
	visible, err := lease.ReadListingObject(ctx, tree, expected.ID, true)
	if err != nil || visible.Path != expected.Path || visible.Entry.ObjectID != expected.ID || visible.Entry.Kind != expected.Kind || !reflect.DeepEqual(visible.Placement.Encryption, expected.Encryption) || objectID != visible.Placement.NativeObjectID {
		return empty, ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return empty, ErrUnavailable
	}
	err = s.opaqueLocalMediaTreeLocked(ctx, visible)
	release()
	if err != nil {
		return empty, ErrUnavailable
	}
	reader, err := s.openOpaqueBlob(ctx, visible.Placement.BlobID, visible.Placement.SHA256, visible.Placement.Bytes, true, nil, false)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer reader.Close()
	revision, err := opaqueSourceRevision(visible.Placement)
	if err != nil {
		return empty, ErrUnavailable
	}
	descriptor, err := protocol.IngressMediaDescriptor(visible.Placement.Bytes, visible.Placement.Encryption)
	if err != nil {
		return empty, ErrUnavailable
	}
	alias := visible.Placement.ReadAlias
	var token, origin, route string
	if mode == "Direct" {
		origin, route = directOrigin, "/api/v1/media/master-direct/"
		token, err = s.control.IssueMasterDirectCapability(ctx, origin, alias, alias, revision, descriptor)
	} else {
		origin, route = assertion.PublicOrigin, "/api/v1/media/master-relay/"
		token, err = s.control.IssueMasterRelayCapability(ctx, alias, alias, revision, descriptor)
	}
	if _, _, _, alive := mediacrypto.DirectSessionFromContext(ctx).Values(); err != nil || !alive || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) || s.opaqueLocalMediaTreeLocked(ctx, visible) != nil {
		return empty, ErrUnavailable
	}
	return OpaqueSourceDetails{Source: origin + route + alias, Origin: origin, Token: token, Revision: revision, Transport: mode, SourceObjectID: alias, OwnerID: visible.Placement.OwnerID, Size: visible.Placement.Bytes}, nil
}

// openOpaqueMasterPeerMedia revalidates the signed alias, revision and tree
// state under the given real tree authority. It never consults legacy
// catalog tables. The returned stream retains its volume read fence.
func (s *Service) openOpaqueMasterPeerMedia(ctx context.Context, tree *sealedtree.SQLStore, sessions *mediacrypto.Manager, reader ingressTreeReader, alias, revision, descriptor, sessionID string, expiry int64, browserCipherRange func(int64) bool) (*OpaqueBlob, error) {
	if s == nil || tree == nil || sessions == nil || reader == nil || reader.Check(ctx) != nil || !sessions.CheckDirectSession(sessionID) || time.Now().Unix() >= expiry {
		return nil, ErrUnavailable
	}
	visible, err := reader.ReadListingObjectByAlias(ctx, tree, alias, true)
	if err != nil || visible.Placement.ReadAlias != alias {
		return nil, ErrUnavailable
	}
	wantRevision, e1 := opaqueSourceRevision(visible.Placement)
	wantDescriptor, e2 := protocol.IngressMediaDescriptor(visible.Placement.Bytes, visible.Placement.Encryption)
	if e1 != nil || e2 != nil || wantRevision != revision || wantDescriptor != descriptor {
		return nil, ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return nil, ErrUnavailable
	}
	err = s.opaqueLocalMediaTreeLocked(ctx, visible)
	release()
	if err != nil || reader.Check(ctx) != nil || !sessions.CheckDirectSession(sessionID) || time.Now().Unix() >= expiry {
		return nil, ErrUnavailable
	}
	fast := visible.Placement.Encryption != nil && browserCipherRange != nil && browserCipherRange(visible.Placement.Bytes)
	stream, err := s.openOpaqueBlob(ctx, visible.Placement.BlobID, visible.Placement.SHA256, visible.Placement.Bytes, true, nil, !fast)
	if err != nil {
		return nil, ErrUnavailable
	}
	if s.opaqueLocalMediaTreeLocked(ctx, visible) != nil || reader.Check(ctx) != nil || !sessions.CheckDirectSession(sessionID) || time.Now().Unix() >= expiry {
		stream.Close()
		return nil, ErrUnavailable
	}
	return stream, nil
}

func (s *Service) OpenOpaqueMasterDirectMedia(ctx context.Context, tree *sealedtree.SQLStore, sessions *mediacrypto.Manager, token, origin, alias string, browserCipherRange func(int64) bool) (*OpaqueBlob, error) {
	if s == nil || s.control == nil || tree == nil {
		return nil, ErrUnavailable
	}
	owner, ok := s.nodes.(interface {
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if !ok {
		return nil, ErrUnavailable
	}
	fence, err := owner.AcquireOwnerControlShared(ctx)
	validFence := fence != nil
	if validFence {
		value := reflect.ValueOf(fence)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			validFence = !value.IsNil()
		}
	}
	if err != nil || !validFence {
		if validFence {
			fence.Release()
		}
		return nil, ErrUnavailable
	}
	defer fence.Release()
	if fence.Check(ctx) != nil {
		return nil, ErrUnavailable
	}
	claim, err := s.control.VerifyMasterDirectCapability(ctx, token, origin, alias)
	if err != nil || claim.ResourceID != claim.ObjectID {
		return nil, ErrUnavailable
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer lease.Release()
	stream, err := s.openOpaqueMasterPeerMedia(ctx, tree, sessions, legacyTreeReader{lease}, alias, claim.Revision, claim.Descriptor, claim.SessionID, claim.ExpiresAt, browserCipherRange)
	if err != nil {
		return nil, err
	}
	if fence.Check(ctx) != nil {
		stream.Close()
		return nil, ErrUnavailable
	}
	return stream, nil
}

func (s *Service) OpenOpaqueMasterRelayMedia(ctx context.Context, tree *sealedtree.SQLStore, sessions *mediacrypto.Manager, token, alias string, browserCipherRange func(int64) bool) (*OpaqueBlob, error) {
	if s == nil || s.control == nil || tree == nil {
		return nil, ErrUnavailable
	}
	claim, err := s.control.VerifyMasterRelayCapability(ctx, token, alias)
	if err != nil || claim.ResourceID != claim.ObjectID {
		return nil, ErrUnavailable
	}
	lease, ok := ingressTreeAuthority(ctx)
	if !ok {
		return nil, ErrUnavailable
	}
	return s.openOpaqueMasterPeerMedia(ctx, tree, sessions, lease, alias, claim.Revision, claim.Descriptor, claim.SessionID, claim.ExpiresAt, browserCipherRange)
}
