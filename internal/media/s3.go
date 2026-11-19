package media

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Ordinary media endpoints cannot express the signed headers required by S3.
// The browser must request a current source grant and send it directly.
var ErrBrowserSource = errors.New("media requires a browser source grant")

type s3Control interface {
	Generation() uint64
	Members(context.Context) ([]store.S3Member, error)
	Add(context.Context, s3media.Configuration, store.NodeAudit) (store.S3Member, error)
	Configure(context.Context, string, int64, s3media.Configuration, store.NodeAudit) (store.S3Member, error)
	Probe(context.Context, string, int64, string, store.NodeAudit) (store.S3Member, error)
	Remove(context.Context, string, int64, store.NodeAudit) error
	RecoveryCredentials(context.Context, string, int64, s3store.Credentials, store.NodeAudit) (store.S3Member, error)
	Begin(context.Context, string) (store.S3Upload, error)
	Status(context.Context, string, bool) (store.S3Upload, error)
	PartGrant(context.Context, string, int, int64, string) (s3store.Grant, error)
	ConfirmPart(context.Context, string, int) (store.S3Upload, error)
	Complete(context.Context, string, store.AdminAudit) (store.GlobalMedia, error)
	Cancel(context.Context, string, store.AdminAudit) (store.S3Upload, error)
	Delete(context.Context, string, store.AdminAudit) error
	ReadSource(context.Context, string, string) (s3media.SourceGrant, error)
	Reconcile(context.Context) error
}

// ConfigureS3 is startup-only. No provider credential or URL enters native node
// control, filesystem upload stages, ordinary ZIP construction or relay paths.
func (s *Service) ConfigureS3(service *s3media.Service) {
	if service == nil {
		s.s3 = nil
		return
	}
	s.s3 = service
}

// SelectedS3Provider returns the same Master-held provider adapter that was
// installed at startup. It does not install a selected S3 runtime or prove
// that pending operations and configuration have been reconciled.
func (s *Service) SelectedS3Provider() (interface {
	WithSelectedProvider(context.Context, store.S3Member, func(context.Context, s3store.Provider) error) error
}, error) {
	if s == nil || s.s3 == nil {
		return nil, ErrUnavailable
	}
	provider, ok := s.s3.(interface {
		WithSelectedProvider(context.Context, store.S3Member, func(context.Context, s3store.Provider) error) error
	})
	if !ok {
		return nil, ErrUnavailable
	}
	return provider, nil
}

func (s *Service) acquireS3(ctx context.Context) (func(), error) {
	// The legacy provider control path operates on plaintext catalog facts and
	// can issue upload grants or mutate provider state. It is not the sealed
	// tree S3 adapter and must stop before making any such request.
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return nil, err
	}
	if err := s.requireMaster(ctx); err != nil {
		return nil, err
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return nil, err
	}
	if err = s.ready(); err != nil {
		release()
		return nil, err
	}
	if s.s3 == nil {
		release()
		return nil, ErrUnavailable
	}
	return release, nil
}

func (s *Service) S3Members(ctx context.Context) ([]store.S3Member, error) {
	if s != nil && s.opaqueS3ReadTree != nil {
		if ctx == nil || ctx.Err() != nil || s.opaqueS3ReadGate == nil || s.s3 == nil {
			return nil, ErrUnavailable
		}
		var result []store.S3Member
		work := func(c context.Context) error {
			var e error
			result, e = s.s3.Members(c)
			return e
		}
		var err error
		if gate, ok := s.opaqueS3ReadGate.(interface {
			WithSelectedS3Listing(context.Context, *sealedtree.SQLStore, func(context.Context) error) error
		}); ok {
			err = gate.WithSelectedS3Listing(ctx, s.opaqueS3ReadTree, func(c context.Context) error {
				if e := s.requireMaster(c); e != nil {
					return e
				}
				return work(c)
			})
		} else {
			err = s.withSelectedS3ManagementRead(ctx, work)
		}
		if err != nil {
			return nil, err
		}
		return result, nil
	}
	release, err := s.acquireS3(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.s3.Members(ctx)
}
func (s *Service) S3AddMember(ctx context.Context, cfg s3media.Configuration, a store.NodeAudit) (store.S3Member, error) {
	if s != nil && s.opaqueS3ReadTree != nil {
		var result store.S3Member
		err := s.withSelectedS3ManagementRead(ctx, func(c context.Context) error {
			var e error
			result, e = s.s3.Add(c, cfg, a)
			return e
		})
		if err != nil {
			return store.S3Member{}, err
		}
		return result, nil
	}
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Member{}, err
	}
	defer release()
	return s.s3.Add(ctx, cfg, a)
}

func (s *Service) withSelectedS3ManagementRead(ctx context.Context, work func(context.Context) error) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.opaqueS3ReadTree == nil || s.opaqueS3ReadGate == nil || s.s3 == nil || work == nil {
		return ErrUnavailable
	}
	gate, ok := s.opaqueS3ReadGate.(interface {
		WithSelectedS3ManagementRead(context.Context, *sealedtree.SQLStore, func(context.Context) error) error
	})
	if !ok {
		return ErrUnavailable
	}
	return gate.WithSelectedS3ManagementRead(ctx, s.opaqueS3ReadTree, func(c context.Context) error {
		if err := s.requireMaster(c); err != nil {
			return err
		}
		return work(c)
	})
}
func (s *Service) S3ConfigureMember(ctx context.Context, id string, revision int64, cfg s3media.Configuration, a store.NodeAudit) (store.S3Member, error) {
	if s != nil && s.opaqueS3ReadTree != nil {
		if !cfg.Enabled {
			return s.disableUnusedSelectedS3Member(ctx, id, revision, cfg, a)
		}
		var result store.S3Member
		err := s.withSelectedS3ManagementRead(ctx, func(c context.Context) error {
			repo, ok := s.pool.(interface {
				S3Member(context.Context, string) (store.S3Member, error)
			})
			gate, ready := s.opaqueS3ReadGate.(interface {
				CheckSelectedS3Member(context.Context, *sealedtree.SQLStore, store.S3Member) error
			})
			if !ok || !ready || cfg.Credentials != nil {
				return ErrUnavailable
			}
			current, e := repo.S3Member(c, id)
			// Any revision change would invalidate already-admitted selected
			// intents. Until configuration draining and reconciliation are wired,
			// allow only the first enable of an independently verified member.
			if e != nil || current.Enabled != 0 || !cfg.Enabled || current.Revision != revision || cfg.Location != current.Location || gate.CheckSelectedS3Member(c, s.opaqueS3ReadTree, current) != nil {
				return ErrUnavailable
			}
			result, e = s.s3.Configure(c, id, revision, cfg, a)
			if e != nil {
				return e
			}
			return gate.CheckSelectedS3Member(c, s.opaqueS3ReadTree, result)
		})
		if err != nil {
			return store.S3Member{}, err
		}
		return result, nil
	}
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Member{}, err
	}
	defer release()
	return s.s3.Configure(ctx, id, revision, cfg, a)
}

// Only an unchanged, never-used member can be disabled without the longer
// provider-grant drain and selected-object recovery protocol.
func (s *Service) disableUnusedSelectedS3Member(ctx context.Context, id string, revision int64, cfg s3media.Configuration, audit store.NodeAudit) (store.S3Member, error) {
	var result store.S3Member
	gate, ok := s.opaqueS3ReadGate.(interface {
		WithSelectedS3Startup(context.Context, *sealedtree.SQLStore, func(context.Context) error) error
	})
	repo, verified := s.pool.(interface {
		S3Member(context.Context, string) (store.S3Member, error)
		CheckSelectedS3Startup(context.Context, *sealedtree.SQLStore, []byte) error
		CheckSelectedS3MemberNoHistory(context.Context, *sealedtree.SQLStore, []byte, string) error
	})
	if ctx == nil || !ok || !verified || s.s3 == nil || cfg.Credentials != nil {
		return result, ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := gate.WithSelectedS3Startup(bounded, s.opaqueS3ReadTree, func(c context.Context) error {
		if err := s.requireMaster(c); err != nil {
			return err
		}
		current, err := repo.S3Member(c, id)
		if err != nil || current.Enabled == 0 || current.Revision != revision || cfg.Location != current.Location || cfg.Name != current.Name || cfg.Quota != current.Allocation {
			return ErrUnavailable
		}
		key, err := s.opaqueS3ReadTree.CapacityKey()
		if err != nil {
			return err
		}
		defer clear(key)
		if err = repo.CheckSelectedS3Startup(c, s.opaqueS3ReadTree, key); err != nil {
			return err
		}
		if err = repo.CheckSelectedS3MemberNoHistory(c, s.opaqueS3ReadTree, key, id); err != nil {
			return err
		}
		result, err = s.s3.Configure(c, id, revision, cfg, audit)
		return err
	})
	return result, err
}

// S3ProbeSelected verifies both configured browser origins under the same
// cross-process S3 control gate. A successful process-local proof is required
// again after restart before selected S3 grants may be issued.
func (s *Service) S3ProbeSelected(ctx context.Context, id string, revision int64, adminOrigin string, a store.NodeAudit) (store.S3Member, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.opaqueS3ReadTree == nil || s.opaqueS3ReadGate == nil || s.s3 == nil {
		return store.S3Member{}, ErrUnavailable
	}
	gate, ok := s.opaqueS3ReadGate.(interface {
		WithSelectedS3Probe(context.Context, *sealedtree.SQLStore, string, string, string, func(context.Context) (store.S3Member, error)) (store.S3Member, error)
	})
	prober, probeOK := s.s3.(interface {
		ProbeSelected(context.Context, string, int64, string, string, store.NodeAudit) (store.S3Member, error)
	})
	if !ok || !probeOK {
		return store.S3Member{}, ErrUnavailable
	}
	routing, ok := s.nodes.(store.ExistingIngressRepository)
	if !ok {
		return store.S3Member{}, ErrUnavailable
	}
	ingress, err := routing.ExistingPublicIngress(ctx)
	if err != nil || ingress.NodeID == "" || ingress.Generation < 1 || ingress.PublicOrigin == "" {
		return store.S3Member{}, ErrUnavailable
	}
	publicOrigin := ingress.PublicOrigin
	return gate.WithSelectedS3Probe(ctx, s.opaqueS3ReadTree, id, adminOrigin, publicOrigin, func(c context.Context) (store.S3Member, error) {
		if err := s.requireMaster(c); err != nil {
			return store.S3Member{}, err
		}
		member, err := prober.ProbeSelected(c, id, revision, adminOrigin, publicOrigin, a)
		if err != nil {
			return store.S3Member{}, err
		}
		current, err := routing.ExistingPublicIngress(c)
		if err != nil || current != ingress {
			return store.S3Member{}, ErrUnavailable
		}
		return member, nil
	})
}
func (s *Service) S3ProbeMember(ctx context.Context, id string, revision int64, origin string, a store.NodeAudit) (store.S3Member, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Member{}, err
	}
	defer release()
	return s.s3.Probe(ctx, id, revision, origin, a)
}
func (s *Service) S3RemoveMember(ctx context.Context, id string, revision int64, a store.NodeAudit) error {
	if s != nil && s.opaqueS3ReadTree != nil {
		gate, ok := s.opaqueS3ReadGate.(interface {
			WithSelectedS3Startup(context.Context, *sealedtree.SQLStore, func(context.Context) error) error
		})
		repo, verified := s.pool.(interface {
			CheckSelectedS3Startup(context.Context, *sealedtree.SQLStore, []byte) error
			CheckSelectedS3MemberUnused(context.Context, *sealedtree.SQLStore, []byte, string) error
		})
		if ctx == nil || !ok || !verified || s.s3 == nil {
			return ErrUnavailable
		}
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return gate.WithSelectedS3Startup(bounded, s.opaqueS3ReadTree, func(c context.Context) error {
			if err := s.requireMaster(c); err != nil {
				return err
			}
			key, err := s.opaqueS3ReadTree.CapacityKey()
			if err != nil {
				return err
			}
			defer clear(key)
			if err = repo.CheckSelectedS3Startup(c, s.opaqueS3ReadTree, key); err != nil {
				return err
			}
			if err = repo.CheckSelectedS3MemberUnused(c, s.opaqueS3ReadTree, key, id); err != nil {
				return err
			}
			return s.s3.Remove(c, id, revision, a)
		})
	}
	release, err := s.acquireS3(ctx)
	if err != nil {
		return err
	}
	defer release()
	return s.s3.Remove(ctx, id, revision, a)
}
func (s *Service) S3RecoveryCredentials(ctx context.Context, id string, revision int64, credentials s3store.Credentials, a store.NodeAudit) (store.S3Member, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Member{}, err
	}
	defer release()
	return s.s3.RecoveryCredentials(ctx, id, revision, credentials, a)
}
func (s *Service) S3UploadStatus(ctx context.Context, id string, touch bool) (store.S3Upload, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	return s.s3.Status(ctx, id, touch)
}
func (s *Service) S3BeginUpload(ctx context.Context, id string) (store.S3Upload, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	return s.s3.Begin(ctx, id)
}
func (s *Service) S3PartGrant(ctx context.Context, id string, number int, size int64, checksum string) (s3store.Grant, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return s3store.Grant{}, err
	}
	defer release()
	return s.s3.PartGrant(ctx, id, number, size, checksum)
}
func (s *Service) S3ConfirmPart(ctx context.Context, id string, number int) (store.S3Upload, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	return s.s3.ConfirmPart(ctx, id, number)
}
func (s *Service) S3CompleteUpload(ctx context.Context, id string, a store.AdminAudit) (UploadResult, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return UploadResult{}, err
	}
	defer release()
	row, err := s.s3.Complete(ctx, id, a)
	s.invalidateCatalog()
	return UploadResult{Path: row.Path, MediaID: row.ID}, err
}
func (s *Service) S3CancelUpload(ctx context.Context, id string, a store.AdminAudit) (store.S3Upload, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	return s.s3.Cancel(ctx, id, a)
}
func (s *Service) ReconcileS3(ctx context.Context) error {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return err
	}
	defer release()
	before := s.s3.Generation()
	err = s.s3.Reconcile(ctx)
	if s.s3.Generation() != before {
		s.invalidateCatalog()
	}
	return err
}
func (s *Service) RunS3Recovery(ctx context.Context) {
	timer := time.NewTicker(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			role, err := s.role(ctx)
			if err != nil || role != "Master" || s.s3 == nil {
				continue
			}
			bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
			_ = s.ReconcileS3(bounded)
			cancel()
		}
	}
}

// ReadSource rechecks the path and immutable identity under the same shared
// mutation fence as source authorization. A native object returns an empty
// grant; S3 always requires an explicit immutable object ID.
func (s *Service) ReadSource(ctx context.Context, name, expectedObjectID string, admin bool) (s3media.SourceGrant, error) {
	release, err := s.acquire(ctx, false)
	if err != nil {
		return s3media.SourceGrant{}, err
	}
	defer release()
	return s.readSource(ctx, name, expectedObjectID, admin, false)
}
func (s *Service) PlaintextSource(ctx context.Context, name, expectedObjectID string, admin bool) (s3media.SourceGrant, error) {
	release, err := s.acquire(ctx, false)
	if err != nil {
		return s3media.SourceGrant{}, err
	}
	defer release()
	return s.readSource(ctx, name, expectedObjectID, admin, true)
}
func (s *Service) readSource(ctx context.Context, name, expectedObjectID string, admin, plainOnly bool) (s3media.SourceGrant, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return s3media.SourceGrant{}, err
	}
	object, err := s.cryptoObject(ctx, name, "", admin)
	if err != nil {
		return s3media.SourceGrant{}, err
	}
	if expectedObjectID != "" && expectedObjectID != object.ID {
		return s3media.SourceGrant{}, os.ErrNotExist
	}
	role, err := s.role(ctx)
	if err != nil {
		return s3media.SourceGrant{}, err
	}
	if role != "Master" || object.Kind == "lyric" {
		if plainOnly {
			return s3media.SourceGrant{}, ErrPath
		}
		return s3media.SourceGrant{}, nil
	}
	_, peer := network.AuthenticatedIngressFromContext(ctx)
	row, _, err := s.resolveGlobalFor(ctx, "", name, peer && !admin)
	if err != nil {
		return s3media.SourceGrant{}, err
	}
	if row.Transport != "S3" {
		if plainOnly {
			return s3media.SourceGrant{}, ErrPath
		}
		return s3media.SourceGrant{}, nil
	}
	if expectedObjectID == "" || row.ObjectID != expectedObjectID || row.ID != object.ID || plainOnly && object.Encryption != nil {
		return s3media.SourceGrant{}, ErrPath
	}
	if s.s3 == nil {
		return s3media.SourceGrant{}, ErrUnavailable
	}
	// The browser receives its display/download filename from the authenticated
	// Master response. Do not place that name in the provider's signed URL.
	return s.s3.ReadSource(ctx, row.ID, "")
}
