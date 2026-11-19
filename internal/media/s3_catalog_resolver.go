package media

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type catalogS3MemberRepository interface {
	S3Member(context.Context, string) (store.S3Member, error)
}

type catalogS3Repository interface {
	catalogS3MemberRepository
	S3Object(context.Context, string) (store.S3Object, error)
	Encryption(context.Context, string) (*mediacrypto.Metadata, error)
}

type s3CatalogMemberView struct {
	master                                              string
	ingress                                             store.PublicIngress
	id                                                  string
	location                                            s3store.Config
	credential                                          [32]byte
	credentialRevision, revision, expiry, probeRevision int64
	enabled                                             int
	probe                                               string
	cleanup                                             bool
}

func (s *Service) s3CatalogMember(ctx context.Context, repo catalogS3MemberRepository, routing nativeCatalogRouting, id string) (s3CatalogMemberView, error) {
	var out s3CatalogMemberView
	master, err := s.nodes.ReadIdentity(ctx)
	if err != nil || master.Role != "Master" {
		return out, ErrUnavailable
	}
	ingress, err := routing.ExistingPublicIngress(ctx)
	if err != nil {
		return out, ErrUnavailable
	}
	member, err := repo.S3Member(ctx, id)
	if err != nil || member.ID != id || member.Kind != "S3" || member.Transport != "S3" || member.RelationshipID != nil || member.CleanupOnly || member.SealedCredentials == "" || member.CredentialRevision < 1 || member.Revision < 1 || member.ProbeState != "ready" || member.ProbeRevision != member.Revision || member.CredentialExpiresAt != 0 && member.CredentialExpiresAt <= time.Now().Unix() {
		return out, ErrUnavailable
	}
	location := s3store.Config{Endpoint: member.Location.Endpoint, Bucket: member.Location.Bucket, Region: member.Location.Region, Prefix: member.Location.Prefix, AddressStyle: member.Location.Style}
	canonical, err := s3store.Normalize(location)
	if err != nil || canonical != location {
		return out, ErrUnavailable
	}
	return s3CatalogMemberView{master: master.ID, ingress: ingress, id: id, location: location, credential: sha256.Sum256([]byte(member.SealedCredentials)), credentialRevision: member.CredentialRevision, revision: member.Revision, expiry: member.CredentialExpiresAt, probeRevision: member.ProbeRevision, enabled: member.Enabled, probe: member.ProbeState, cleanup: member.CleanupOnly}, nil
}

type s3CatalogProof struct {
	proof     store.S3ObjectProof
	revision  int64
	encrypted bool
	metadata  mediacrypto.Metadata
}

type s3CatalogLease struct {
	inner   CatalogResourceLease
	service *Service
	repo    catalogS3Repository
	routing nativeCatalogRouting
	want    s3CatalogMemberView
	objects map[string]s3CatalogProof
}

func (l *s3CatalogLease) Check(ctx context.Context) error {
	if l == nil || l.inner == nil || l.inner.Check(ctx) != nil {
		return ErrUnavailable
	}
	current, err := l.service.s3CatalogMember(ctx, l.repo, l.routing, l.want.id)
	if err != nil || current != l.want {
		return ErrUnavailable
	}
	for id, expected := range l.objects {
		object, e := l.repo.S3Object(ctx, id)
		if e != nil || object.State != "active" || object.Media.State != "active" || object.Media.ID != id || object.Media.MemberID != l.want.id || object.Media.ObjectID != expected.proof.ObjectID || object.Media.Bytes != expected.proof.Bytes || object.Media.ETag != expected.proof.ETag || object.Proof != expected.proof || object.Revision != expected.revision || object.Encrypted != expected.encrypted {
			return ErrUnavailable
		}
		metadata, e := l.repo.Encryption(ctx, id)
		if e != nil || (metadata != nil) != expected.encrypted || metadata != nil && *metadata != expected.metadata {
			return ErrUnavailable
		}
	}
	if l.inner.Check(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
func (l *s3CatalogLease) Release() {
	if l != nil && l.inner != nil {
		l.inner.Release()
	}
}

// S3CatalogOwnerResolver verifies durable Master records only. It neither
// contacts the provider nor grants object access. The caller must still check
// source lyric evidence and hold the actual ingress and tree admission fences.
func (s *Service) S3CatalogOwnerResolver() (CatalogOwnerResolver, error) {
	if _, err := s.NativeCatalogOwnerResolver(); err != nil {
		return nil, ErrUnavailable
	}
	repo, ok := s.pool.(catalogS3Repository)
	if !ok {
		return nil, ErrUnavailable
	}
	owners := s.pool.(nativeCatalogRepository)
	routing := s.nodes.(nativeCatalogRouting)
	return func(ctx context.Context, id string) (CatalogOwnerSnapshot, error) {
		if ctx == nil || ctx.Err() != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		if _, err := routing.ExistingPublicIngress(ctx); err != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		owner, err := owners.AcquireOwnerControlShared(ctx)
		if err != nil || owner == nil {
			if owner != nil {
				owner.Release()
			}
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		defer owner.Release()
		binding, err := owner.Binding(ctx)
		if err != nil || binding == "" || owner.Check(ctx) != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		current, ingress, err := routing.AcquireExistingIngress(ctx)
		if err != nil || ingress == nil {
			if ingress != nil {
				ingress.Release()
			}
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		defer ingress.Release()
		view, err := s.s3CatalogMember(ctx, repo, routing, id)
		if err != nil || view.ingress != current || owner.Check(ctx) != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		if err := ingress.Commit(); err != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		var mu sync.Mutex
		proofs := make(map[string]s3CatalogProof)
		frozen := false
		return CatalogOwnerSnapshot{Transport: "S3", CheckS3: func(p *sealedtree.S3Placement) error {
			if p == nil || !p.MatchesCurrentMember(view.id, view.location) {
				return ErrUnavailable
			}
			value := s3CatalogProof{proof: p.Proof, revision: p.ObjectRevision, encrypted: p.Encryption != nil}
			if p.Encryption != nil {
				value.metadata = *p.Encryption
			}
			mu.Lock()
			defer mu.Unlock()
			previous, exists := proofs[p.ObjectID]
			if frozen || !exists && len(proofs) >= 4096 {
				return ErrUnavailable
			}
			if exists && previous != value {
				return ErrUnavailable
			}
			proofs[p.ObjectID] = value
			return nil
		}, Acquire: func(c context.Context, prerequisite store.IngressPrerequisite) (CatalogResourceLease, error) {
			// The legacy S3 writers do not take the Owner/ingress fences. They
			// become unavailable only after a durable tree marker exists in
			// the same database. Until that binding and all replacement S3
			// writers are proven, a point-in-time re-read cannot authorize
			// a stable catalog response.
			const sameTreeAndWriterFencesProven = false
			if !sameTreeAndWriterFencesProven {
				return nil, ErrUnavailable
			}
			inner, e := BorrowLocalCatalogOwnerSnapshot(binding)(c, prerequisite)
			if e != nil {
				return nil, ErrUnavailable
			}
			mu.Lock()
			frozen = true
			copied := make(map[string]s3CatalogProof, len(proofs))
			for k, v := range proofs {
				copied[k] = v
			}
			mu.Unlock()
			lease := &s3CatalogLease{inner: inner, service: s, repo: repo, routing: routing, want: view, objects: copied}
			if lease.Check(c) != nil {
				lease.Release()
				return nil, ErrUnavailable
			}
			return lease, nil
		}}, nil
	}, nil
}
