package media

import (
	"context"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// OpaqueS3CatalogGate checks the current member under the same Owner lease as
// catalog admission. It must not acquire Owner or tree locks recursively.
// The actual startup gate also guarantees that all member configuration
// writers and recovery use that Owner fence.
type OpaqueS3CatalogGate interface {
	CheckSelectedS3Catalog(context.Context, *sealedtree.SQLStore, store.S3Member) error
}

type opaqueS3CatalogLease struct {
	inner   CatalogResourceLease
	service *Service
	tree    *sealedtree.SQLStore
	repo    catalogS3MemberRepository
	routing nativeCatalogRouting
	want    s3CatalogMemberView
	member  store.S3Member
	gate    OpaqueS3CatalogGate
}

func (l *opaqueS3CatalogLease) Check(ctx context.Context) error {
	if l == nil || l.inner == nil || l.inner.Check(ctx) != nil || l.service.opaqueS3ReadTree != l.tree || l.service.opaqueS3ReadGate == nil || l.gate.CheckSelectedS3Catalog(ctx, l.tree, l.member) != nil {
		return ErrUnavailable
	}
	current, err := l.repo.S3Member(ctx, l.member.ID)
	if err != nil || !reflect.DeepEqual(current, l.member) {
		return ErrUnavailable
	}
	view, err := l.service.s3CatalogMember(ctx, l.repo, l.routing, l.member.ID)
	if err != nil || view != l.want || l.inner.Check(ctx) != nil {
		return ErrUnavailable
	}
	return ctx.Err()
}

func (l *opaqueS3CatalogLease) Release() {
	if l != nil && l.inner != nil {
		l.inner.Release()
	}
}

// SealedCatalogOwnerResolver preserves native routing and admits S3 only after
// startup installs the same-tree S3 lifecycle gate. The final tree scope owns
// placement consistency; no legacy S3 object or encryption row is consulted.
func (s *Service) SealedCatalogOwnerResolver(tree *sealedtree.SQLStore) (CatalogOwnerResolver, error) {
	native, err := s.NativeCatalogOwnerResolver()
	if err != nil || tree == nil {
		return nil, ErrUnavailable
	}
	repo, ok := s.pool.(catalogS3MemberRepository)
	if !ok {
		return native, nil
	}
	owners, ok := s.pool.(nativeCatalogRepository)
	if !ok {
		return nil, ErrUnavailable
	}
	routing, ok := s.nodes.(nativeCatalogRouting)
	if !ok {
		return nil, ErrUnavailable
	}
	return func(ctx context.Context, id string) (CatalogOwnerSnapshot, error) {
		if result, e := native(ctx, id); e == nil {
			return result, nil
		}
		if ctx == nil || ctx.Err() != nil || s.opaqueS3ReadTree != tree || s.opaqueS3ReadGate == nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		gate, ok := s.opaqueS3ReadGate.(OpaqueS3CatalogGate)
		if !ok {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		owner, e := owners.AcquireOwnerControlShared(ctx)
		if e != nil || owner == nil {
			if owner != nil {
				owner.Release()
			}
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		defer owner.Release()
		binding, e := owner.Binding(ctx)
		if e != nil || binding == "" || owner.Check(ctx) != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		current, ingress, e := routing.AcquireExistingIngress(ctx)
		if e != nil || ingress == nil {
			if ingress != nil {
				ingress.Release()
			}
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		defer ingress.Release()
		view, e := s.s3CatalogMember(ctx, repo, routing, id)
		member, memberErr := repo.S3Member(ctx, id)
		if e != nil || memberErr != nil || view.ingress != current || gate.CheckSelectedS3Catalog(ctx, tree, member) != nil || owner.Check(ctx) != nil || ingress.Commit() != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		return CatalogOwnerSnapshot{Transport: "S3", CheckS3: func(p *sealedtree.S3Placement) error {
			if p == nil || p.Encryption == nil || p.Proof.MetadataFormat != store.S3OpaqueMetadata || !p.MatchesCurrentMember(view.id, view.location) {
				return ErrUnavailable
			}
			return nil
		}, Acquire: func(c context.Context, prerequisite store.IngressPrerequisite) (CatalogResourceLease, error) {
			inner, e := BorrowLocalCatalogOwnerSnapshot(binding)(c, prerequisite)
			if e != nil {
				return nil, ErrUnavailable
			}
			lease := &opaqueS3CatalogLease{inner: inner, service: s, tree: tree, repo: repo, routing: routing, want: view, member: member, gate: gate}
			if lease.Check(c) != nil {
				lease.Release()
				return nil, ErrUnavailable
			}
			return lease, nil
		}}, nil
	}, nil
}
