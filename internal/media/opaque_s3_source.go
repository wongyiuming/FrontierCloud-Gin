package media

import (
	"context"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// OpaqueS3ReadGate is installed only by the actual Master lifecycle. Authorize
// must establish the grant deadline before signing while the caller already
// holds public Owner/ingress/tree admission. Every configuration change and
// object deletion must exclude new admissions and drain existing grants,
// including a conservative maximum-grant wait after an unclean restart.
// Implementations must not reacquire the caller's Owner or tree lease.
type OpaqueS3ReadGate interface {
	AuthorizeSelectedS3Read(context.Context, *sealedtree.SQLStore, store.S3Member, int64) error
	CheckSelectedS3Read(context.Context, *sealedtree.SQLStore, store.S3Member, int64) error
	CheckSelectedS3PublicOrigin(context.Context, *sealedtree.SQLStore, store.S3Member, string) error
}

// ConfigureOpaqueS3Read is startup-only; a nil or absent gate leaves reads
// closed. The caller owns the gate lifecycle and must bind it to this tree.
func (s *Service) ConfigureOpaqueS3Read(tree *sealedtree.SQLStore, gate OpaqueS3ReadGate) error {
	if s == nil || tree == nil || gate == nil || s.opaqueS3ReadGate != nil {
		return ErrUnavailable
	}
	value := reflect.ValueOf(gate)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return ErrUnavailable
		}
	}
	s.opaqueS3ReadTree, s.opaqueS3ReadGate = tree, gate
	return nil
}

type ingressS3TreeReader interface {
	ReadS3ListingObject(context.Context, *sealedtree.SQLStore, string, bool) (sealedtree.S3ListingObject, error)
}

// OpaquePublicS3Media authenticates an S3 tree record under the same
// public admission as the request. The returned placement is Master-only and
// is not itself an S3 read grant; provider credentials and grant lifetime must
// be checked under the separate S3 configuration and recovery fence.
func (s *Service) OpaquePublicS3Media(ctx context.Context, tree *sealedtree.SQLStore, name, resourceID, objectID string) (store.MediaObject, sealedtree.S3Placement, error) {
	var object store.MediaObject
	var placement sealedtree.S3Placement
	lease, ok := ingressTreeAuthority(ctx)
	if !ok || !network.HasActivePublicAdmission(ctx) || lease.Check(ctx) != nil || tree == nil || name == "" || resourceID == "" || objectID == "" {
		return object, placement, ErrUnavailable
	}
	reader, ok := lease.(ingressS3TreeReader)
	if !ok {
		return object, placement, ErrUnavailable
	}
	visible, err := reader.ReadS3ListingObject(ctx, tree, resourceID, true)
	placement = visible.Placement
	if err != nil || visible.Path != name || visible.Entry.ObjectID != resourceID || visible.Entry.Kind != "audio" && visible.Entry.Kind != "video" || placement.ObjectID != resourceID || placement.Proof.ObjectID != objectID || placement.Encryption == nil || placement.Encryption.Validate() != nil || placement.Encryption.CiphertextSize != placement.Proof.Bytes || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		return store.MediaObject{}, sealedtree.S3Placement{}, ErrUnavailable
	}
	return store.MediaObject{ID: resourceID, Path: visible.Path, Kind: visible.Entry.Kind, Encryption: placement.Encryption}, placement, nil
}

// OpaqueS3ReadSource issues no grant without the lifecycle-installed gate and
// the public admission's final recheck. The placement is an internal snapshot
// previously obtained using OpaquePublicS3Media, never client supplied.
func (s *Service) OpaqueS3ReadSource(ctx context.Context, tree *sealedtree.SQLStore, placement sealedtree.S3Placement, deadline int64) (s3media.SourceGrant, error) {
	var empty s3media.SourceGrant
	lease, ok := ingressTreeAuthority(ctx)
	if s == nil || !ok || tree == nil || s.opaqueS3ReadTree != tree || s.opaqueS3ReadGate == nil || !network.HasActivePublicAdmission(ctx) || lease.Check(ctx) != nil || deadline <= time.Now().Unix() || deadline > time.Now().Unix()+store.S3GrantSeconds {
		return empty, ErrUnavailable
	}
	public, _, admitted := network.PublicIngressIdentityFromContext(ctx)
	if !admitted {
		return empty, ErrUnavailable
	}
	reader, ok := lease.(ingressS3TreeReader)
	if !ok {
		return empty, ErrUnavailable
	}
	visible, err := reader.ReadS3ListingObject(ctx, tree, placement.ObjectID, true)
	if err != nil || !reflect.DeepEqual(visible.Placement, placement) || visible.Entry.Kind != "audio" && visible.Entry.Kind != "video" || placement.Encryption == nil {
		return empty, ErrUnavailable
	}
	repo, ok := s.pool.(interface {
		S3Member(context.Context, string) (store.S3Member, error)
	})
	if !ok {
		return empty, ErrUnavailable
	}
	signer, ok := s.s3.(interface {
		SelectedReadSource(context.Context, store.S3Member, store.S3ObjectProof, int64, func(context.Context) error) (s3media.SourceGrant, error)
	})
	if !ok {
		return empty, ErrUnavailable
	}
	member, err := repo.S3Member(ctx, placement.MemberID)
	location := s3store.Config{Endpoint: member.Location.Endpoint, Bucket: member.Location.Bucket, Region: member.Location.Region, Prefix: member.Location.Prefix, AddressStyle: member.Location.Style}
	if err != nil || !placement.MatchesCurrentMember(member.ID, location) || s.opaqueS3ReadGate.CheckSelectedS3PublicOrigin(ctx, tree, member, public.PublicOrigin) != nil || s.opaqueS3ReadGate.AuthorizeSelectedS3Read(ctx, tree, member, deadline) != nil {
		return empty, ErrUnavailable
	}
	check := func(c context.Context) error {
		current, e := repo.S3Member(c, member.ID)
		if e != nil || !reflect.DeepEqual(current, member) || s.opaqueS3ReadGate.CheckSelectedS3PublicOrigin(c, tree, member, public.PublicOrigin) != nil || s.opaqueS3ReadGate.CheckSelectedS3Read(c, tree, member, deadline) != nil {
			return ErrUnavailable
		}
		return c.Err()
	}
	// Provider DNS pinning occurs while the public admission is held. Bound
	// both signatures together so an unresponsive provider cannot retain the
	// shared Owner/tree fences for two separate provider timeouts.
	signCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	grant, err := signer.SelectedReadSource(signCtx, member, placement.Proof, deadline, func(c context.Context) error {
		if lease.Check(c) != nil || !network.HasActivePublicAdmission(c) {
			return ErrUnavailable
		}
		return check(c)
	})
	if err != nil || grant.ObjectID != placement.Proof.ObjectID || grant.SizeBytes != placement.Proof.Bytes {
		return empty, ErrUnavailable
	}
	registrar, ok := lease.(interface {
		RegisterPrecommitCheck(func(context.Context) error, time.Time) error
	})
	if !ok || registrar.RegisterPrecommitCheck(check, time.Unix(deadline, 0)) != nil {
		return empty, ErrUnavailable
	}
	return grant, nil
}
