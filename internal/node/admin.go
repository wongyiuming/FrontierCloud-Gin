package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"reflect"
)

func validIngressLease(lease store.PublicIngressLease) bool {
	if lease == nil {
		return false
	}
	v := reflect.ValueOf(lease)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

func (s *Service) IdentityState(ctx context.Context) (store.NodeIdentity, error) {
	return s.repo.ReadIdentity(ctx)
}
func (s *Service) Wake() {
	select {
	case s.wakeup <- struct{}{}:
	default:
	}
}
func (s *Service) SetMode(ctx context.Context, id, mode string, a store.NodeAudit) error {
	relation, e := s.repo.Relationship(ctx, id)
	if e != nil {
		return e
	}
	identity, e := s.repo.ReadIdentity(ctx)
	if e != nil {
		return e
	}
	// The legacy operation updates the Master's route before the follower has
	// applied or acknowledged it.  A deployment profile alone cannot prove
	// that the requested route is usable.  Until the versioned application
	// protocol exists, only the idempotent current-mode request is safe.
	if identity.Role != "Master" || relation.Direction != "downstream" || relation.State != "active" || (mode != "Direct" && mode != "Relay") {
		return store.ErrNodeState
	}
	if mode != relation.Mode {
		return fmt.Errorf("%w: 资源传输策略切换需要节点应用确认，当前版本尚不支持", store.ErrNodeState)
	}
	return nil
}

// ConfigurePublicOrigin supplies the runtime's validated public address. It is
// separate from the node control Endpoint, and does not replace existing state.
func (s *Service) ConfigurePublicOrigin(origin string) error {
	repository, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return store.ErrNodeState
	}
	canonical, err := MasterEndpoint(origin)
	if err != nil {
		return err
	}
	if err := repository.ConfigurePublicOrigin(canonical); err != nil {
		return err
	}
	s.masterPublicOrigin = canonical
	return nil
}

// AcquireCurrentIngress is the authoritative lease used for proxy admission.
// The caller commits admission before exposing its authorized response.
func (s *Service) AcquireCurrentIngress(ctx context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	repository, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return store.PublicIngress{}, nil, store.ErrNodeState
	}
	var ready IngressPrerequisiteLease
	if s.ingressSelectionReady != nil {
		var err error
		ready, err = s.ingressSelectionReady(ctx)
		if err != nil || !validPrerequisiteLease(ready) {
			if validPrerequisiteLease(ready) {
				ready.Release()
			}
			return store.PublicIngress{}, nil, store.ErrNodeState
		}
		if ready.Check(ctx) != nil {
			ready.Release()
			return store.PublicIngress{}, nil, store.ErrNodeState
		}
		if _, composite := ready.(*CatalogPrerequisite); composite {
			// Drop the preliminary Owner/tree readiness check before taking
			// the final Owner -> ingress -> tree admission set.
			ingress, inner, ordered, err := s.acquireOrderedCatalogFromInitial(ctx, ready)
			if err != nil || ordered == nil || !validIngressLease(inner) {
				if validIngressLease(inner) {
					inner.Release()
				}
				if ordered != nil {
					ordered.Release()
				}
				return store.PublicIngress{}, nil, store.ErrNodeState
			}
			origin, err := MasterEndpoint(ingress.PublicOrigin)
			if err != nil || origin != ingress.PublicOrigin {
				inner.Release()
				ordered.Release()
				return store.PublicIngress{}, nil, store.ErrNodeState
			}
			return ingress, &readyIngressLease{ctx: ctx, inner: inner, ready: ordered}, nil
		}
		if s.opaqueIngressTree.Load() != nil {
			ready.Release()
			return store.PublicIngress{}, nil, store.ErrNodeState
		}
	}
	var ingress store.PublicIngress
	var release store.PublicIngressLease
	var err error
	if ready != nil {
		existing, ok := s.repo.(store.ExistingIngressRepository)
		if !ok {
			ready.Release()
			return store.PublicIngress{}, nil, store.ErrNodeState
		}
		ingress, release, err = existing.AcquireExistingIngress(ctx)
	} else {
		ingress, release, err = repository.AcquireCurrentIngress(ctx)
	}
	if err != nil {
		if validIngressLease(release) {
			release.Release()
		}
		if ready != nil {
			ready.Release()
		}
		return store.PublicIngress{}, nil, err
	}
	origin, err := MasterEndpoint(ingress.PublicOrigin)
	if err != nil || origin != ingress.PublicOrigin || !validIngressLease(release) {
		if validIngressLease(release) {
			release.Release()
		}
		if ready != nil {
			ready.Release()
		}
		return store.PublicIngress{}, nil, store.ErrNodeState
	}
	if ready != nil {
		return ingress, &readyIngressLease{ctx: ctx, inner: release, ready: ready}, nil
	}
	return ingress, release, nil
}

// CurrentPublicIngress reads Master-owned state for presentation. Proxy
// authorization instead requires an ingress lease and successful commit.
func (s *Service) CurrentPublicIngress(ctx context.Context) (store.PublicIngress, error) {
	repository, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return store.PublicIngress{}, store.ErrNodeState
	}
	ingress, err := repository.PublicIngress(ctx)
	if err != nil {
		return store.PublicIngress{}, err
	}
	origin, err := Endpoint(ingress.PublicOrigin)
	if err != nil || origin != ingress.PublicOrigin {
		return store.PublicIngress{}, store.ErrNodeState
	}
	return ingress, nil
}

// PublicRouting exposes the new model without presenting an unimplemented peer
// ingress or transport change as active.
func (s *Service) PublicRouting(ctx context.Context) (store.PublicIngress, []store.NativeTransportPolicy, error) {
	repository, ok := s.repo.(store.PublicRoutingRepository)
	if !ok || s.pool == nil {
		return store.PublicIngress{}, nil, store.ErrNodeState
	}
	ingress, err := repository.PublicIngress(ctx)
	if err != nil {
		return store.PublicIngress{}, nil, err
	}
	origin, err := Endpoint(ingress.PublicOrigin)
	if err != nil || origin != ingress.PublicOrigin {
		return store.PublicIngress{}, nil, store.ErrNodeState
	}
	members, err := s.pool.Members(ctx)
	if err != nil {
		return store.PublicIngress{}, nil, err
	}
	policies := make([]store.NativeTransportPolicy, 0, len(members))
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return store.PublicIngress{}, nil, err
	}
	for _, member := range members {
		if member.Kind == "S3" {
			continue
		}
		var policy store.NativeTransportPolicy
		if member.ID == identity.ID {
			policy, err = s.MasterNativePolicy(ctx)
		} else {
			policy, err = repository.NativeTransport(ctx, member.ID)
		}
		if err != nil {
			return store.PublicIngress{}, nil, err
		}
		policies = append(policies, policy)
	}
	return ingress, policies, nil
}

func (s *Service) ConfirmNativeTransport(ctx context.Context, member, desired string, revision int64, audit store.NodeAudit) (store.NativeTransportPolicy, error) {
	unlock := s.LockLogDestination()
	defer unlock()
	if desired == "Relay" && s.logArchiveProtect != nil && s.logArchiveProtect(ctx, member) {
		return store.NativeTransportPolicy{}, ErrLogArchiveNodePinned
	}
	repository, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	policy, err := repository.ConfirmNativeTransport(ctx, member, desired, revision, audit)
	if err == nil {
		s.Wake()
	}
	return policy, err
}
func (s *Service) Configure(ctx context.Context, id string, settings store.ResourceConfiguration, a store.NodeAudit) error {
	row, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return err
	}
	if row.Role != "Master" || s.pool == nil {
		return store.ErrNodeState
	}
	member := row.ID
	if id != row.ID {
		rel, err := s.repo.Relationship(ctx, id)
		if err != nil {
			return err
		}
		if rel.Direction != "downstream" || rel.State != "active" {
			return store.ErrNodeState
		}
		member = rel.PeerID
	}
	if err := s.pool.ConfigureMember(ctx, member, settings, a); err != nil {
		return err
	}
	s.Wake()
	return nil
}

func (s *Service) Reinitialize(ctx context.Context, confirmation string, a store.NodeAudit) (store.NodeIdentity, error) {
	if s.logArchiveProtect != nil && s.logArchiveProtect(ctx, "") {
		return store.NodeIdentity{}, ErrLogArchiveNodePinned
	}
	if s.volume == nil {
		return store.NodeIdentity{}, store.ErrNodeState
	}
	row, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return store.NodeIdentity{}, err
	}
	if row.ID != confirmation {
		return store.NodeIdentity{}, fmt.Errorf("%w: 请准确输入当前节点 ID 确认重新初始化", store.ErrNodeState)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return store.NodeIdentity{}, err
	}
	id, err := randomNodeID()
	if err != nil {
		return store.NodeIdentity{}, err
	}
	sealed, err := s.identity.vault.Seal(protocol.Encode(key.Seed()))
	if err != nil {
		return store.NodeIdentity{}, err
	}
	next := store.NodeIdentity{ID: id, Role: "Standalone", PrivateKey: sealed}
	var result store.NodeIdentity
	// Promotion and reset share the media writer lease. Unknown Follower files
	// and MasterLocal bytes cannot disappear from ownership via an identity reset.
	role := "Master"
	if row.Role == "Follower" {
		role = "Follower"
	}
	err = s.withOwnerControlExclusive(ctx, func(ctx context.Context) error {
		return s.volume.WithPromotion(ctx, role, func(p store.NodePromotion) error {
			if row.Role == "Master" && p.PhysicalUsed != 0 {
				return store.ErrNodeState
			}
			apply := func() error {
				var err error
				result, err = s.repo.ResetIdentity(ctx, confirmation, row.Role, next, a)
				return err
			}
			if row.Role != "Standalone" {
				return s.emptyRecordings(ctx, apply)
			}
			return apply()
		})
	})
	if err != nil {
		return store.NodeIdentity{}, err
	}
	s.Wake()
	return result, nil
}
