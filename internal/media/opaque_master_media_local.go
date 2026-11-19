package media

import (
	"context"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// opaqueLocalMediaTreeLocked checks an authenticated new-tree placement
// against the current Master identity; callers hold tree/volume admission and
// separately verify the actual blob, session and access grant.
func (s *Service) opaqueLocalMediaTreeLocked(ctx context.Context, visible sealedtree.ListingObject) error {
	if s == nil || s.nodes == nil || visible.Entry.Kind != "audio" && visible.Entry.Kind != "video" {
		return ErrUnavailable
	}
	identity, err := s.IdentityState(ctx)
	p := visible.Placement
	if err != nil || identity.Role != "Master" || p.OwnerID != identity.ID || p.ObjectID != visible.Entry.ObjectID || p.NativeObjectID != visible.Entry.ObjectID || p.State != "active" || p.Bytes <= 0 || p.Encryption == nil || p.Encryption.Validate() != nil || p.Encryption.CiphertextSize != p.Bytes {
		return ErrUnavailable
	}
	return nil
}

// OpaqueMasterLocalResource is an isolated adapter: it requires the real
// Master-local admission and tree lease and never performs network loopback.
func (s *Service) OpaqueMasterLocalResource(ctx context.Context, tree *sealedtree.SQLStore, expected store.MediaObject, objectID string, maxExpiry int64) (OpaqueSourceDetails, error) {
	var empty OpaqueSourceDetails
	if s == nil || s.control == nil || tree == nil || ctx == nil {
		return empty, ErrUnavailable
	}
	local, ok := network.LocalPublicIngressFromContext(ctx)
	lease, okLease := ingressTreeAuthority(ctx)
	if !ok || !okLease || lease.Check(ctx) != nil {
		return empty, ErrUnavailable
	}
	visible, err := lease.ReadListingObject(ctx, tree, expected.ID, true)
	if err != nil || visible.Path != expected.Path || visible.Entry.ObjectID != expected.ID || visible.Entry.Kind != expected.Kind || !reflect.DeepEqual(visible.Placement.Encryption, expected.Encryption) || objectID != "" && objectID != visible.Placement.NativeObjectID {
		return empty, ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return empty, ErrUnavailable
	}
	err = s.opaqueLocalMediaTreeLocked(ctx, visible)
	release()
	if _, _, _, valid := mediacrypto.DirectSessionFromContext(ctx).Values(); err != nil || !valid || lease.Check(ctx) != nil {
		return empty, ErrUnavailable
	}
	descriptor, err := protocol.IngressMediaDescriptor(visible.Placement.Bytes, visible.Placement.Encryption)
	if err != nil {
		return empty, ErrUnavailable
	}
	// Issuance reads no content. For an encrypted browser object, check the
	// pinned file and size without scanning it; the browser authenticates each
	// ciphertext chunk before releasing plaintext. Plain content retains the
	// existing complete verification path.
	reader, err := s.openOpaqueBlob(ctx, visible.Placement.BlobID, visible.Placement.SHA256, visible.Placement.Bytes, true, nil, visible.Placement.Encryption == nil)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer reader.Close()
	if s.opaqueLocalMediaTreeLocked(ctx, visible) != nil {
		return empty, ErrUnavailable
	}
	revision, err := opaqueSourceRevision(visible.Placement)
	if err != nil {
		return empty, ErrUnavailable
	}
	token, err := s.control.IssueMasterLocalMediaCapability(ctx, visible.Placement.ReadAlias, revision, descriptor, maxExpiry)
	if err != nil || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		return empty, ErrUnavailable
	}
	if _, _, _, valid := mediacrypto.DirectSessionFromContext(ctx).Values(); !valid {
		return empty, ErrUnavailable
	}
	return OpaqueSourceDetails{Source: local.PublicOrigin + "/api/v1/media/master-local/" + visible.Placement.ReadAlias, Token: token, Revision: revision, Transport: "Local", SourceObjectID: visible.Placement.ReadAlias, OwnerID: visible.Placement.OwnerID, Size: visible.Placement.Bytes}, nil
}

// OpenOpaqueMasterLocalMedia must be called while holding a fresh local
// admission/tree lease. The reader retains its volume fence after ingress
// commit so the already-admitted byte stream can drain. The optional predicate
// is evaluated against the current signed placement size, and must admit only
// a bounded browser ciphertext range; other reads retain full verification.
func (s *Service) OpenOpaqueMasterLocalMedia(ctx context.Context, tree *sealedtree.SQLStore, sessions *mediacrypto.Manager, token, alias string, browserCipherRange func(int64) bool) (*OpaqueBlob, node.MasterLocalMediaClaim, error) {
	var empty node.MasterLocalMediaClaim
	if s == nil || s.control == nil || tree == nil || sessions == nil || ctx == nil {
		return nil, empty, ErrUnavailable
	}
	lease, okLease := ingressTreeAuthority(ctx)
	if !okLease || lease.Check(ctx) != nil {
		return nil, empty, ErrUnavailable
	}
	claim, err := s.control.VerifyMasterLocalMediaCapability(ctx, token, alias)
	if err != nil || !sessions.CheckDirectSession(claim.SessionID) {
		return nil, empty, ErrUnavailable
	}
	visible, err := lease.ReadListingObjectByAlias(ctx, tree, alias, true)
	if err != nil || visible.Placement.ReadAlias != alias {
		return nil, empty, ErrUnavailable
	}
	revision, revErr := opaqueSourceRevision(visible.Placement)
	descriptor, descErr := protocol.IngressMediaDescriptor(visible.Placement.Bytes, visible.Placement.Encryption)
	if revErr != nil || descErr != nil || revision != claim.Revision || descriptor != claim.Descriptor {
		return nil, empty, ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return nil, empty, ErrUnavailable
	}
	err = s.opaqueLocalMediaTreeLocked(ctx, visible)
	release()
	if err != nil || lease.Check(ctx) != nil || !sessions.CheckDirectSession(claim.SessionID) || time.Now().Unix() >= claim.ExpiresAt {
		return nil, empty, ErrUnavailable
	}
	fastCipher := visible.Placement.Encryption != nil && browserCipherRange != nil && browserCipherRange(visible.Placement.Bytes)
	reader, err := s.openOpaqueBlob(ctx, visible.Placement.BlobID, visible.Placement.SHA256, visible.Placement.Bytes, true, nil, !fastCipher)
	if err != nil {
		return nil, empty, ErrUnavailable
	}
	if s.opaqueLocalMediaTreeLocked(ctx, visible) != nil || lease.Check(ctx) != nil || !sessions.CheckDirectSession(claim.SessionID) || !network.HasActivePublicAdmission(ctx) || time.Now().Unix() >= claim.ExpiresAt {
		reader.Close()
		return nil, empty, ErrUnavailable
	}
	return reader, claim, nil
}
