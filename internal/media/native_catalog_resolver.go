package media

import (
	"context"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type nativeCatalogRepository interface {
	NativeCatalogMember(context.Context, string) (store.StorageMember, error)
	AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
}
type nativeCatalogRouting interface {
	store.PublicRoutingRepository
	store.ExistingIngressRepository
	ExistingNativeTransport(context.Context, string) (store.NativeTransportPolicy, error)
}

// nativeCatalogView deliberately omits heartbeat, usage and health. An
// offline, still-paired owner remains displayable; identity and routing are
// nevertheless compared under both real admission fences.
type nativeCatalogView struct {
	master, owner, kind, relation, binding, mode string
	protocol                                     int
	ingress                                      store.PublicIngress
	policy                                       store.NativeTransportPolicy
	enabled                                      int
}

func (s *Service) nativeCatalogView(ctx context.Context, repo nativeCatalogRepository, routing nativeCatalogRouting, id string) (nativeCatalogView, error) {
	var out nativeCatalogView
	master, err := s.nodes.ReadIdentity(ctx)
	if err != nil || master.Role != "Master" || !node.ValidIdentifier(master.ID) || !node.ValidIdentifier(id) {
		return out, ErrUnavailable
	}
	ingress, err := routing.ExistingPublicIngress(ctx)
	if err != nil || !node.ValidIdentifier(ingress.NodeID) || ingress.Generation < 1 {
		return out, ErrUnavailable
	}
	member, err := repo.NativeCatalogMember(ctx, id)
	if err != nil || member.ID != id {
		return out, ErrUnavailable
	}
	out = nativeCatalogView{master: master.ID, owner: id, kind: member.Kind, ingress: ingress, enabled: member.Enabled}
	if id == master.ID {
		if member.Kind != "MasterLocal" || member.RelationshipID != nil {
			return nativeCatalogView{}, ErrUnavailable
		}
	} else {
		if member.Kind != "Follower" || member.RelationshipID == nil || !node.ValidIdentifier(*member.RelationshipID) {
			return nativeCatalogView{}, ErrUnavailable
		}
		relation, e := s.nodes.Relationship(ctx, *member.RelationshipID)
		if e != nil || relation.ID != *member.RelationshipID || relation.PeerID != id || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version || relation.PublicKey == "" || relation.Credential == "" || relation.Endpoint == "" || relation.CreatedAt < 1 {
			return nativeCatalogView{}, ErrUnavailable
		}
		out.relation, out.mode, out.protocol = relation.ID, relation.Mode, relation.Protocol
		out.binding = store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: id, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt})
		if out.binding == "" {
			return nativeCatalogView{}, ErrUnavailable
		}
	}
	var policy store.NativeTransportPolicy
	if id == master.ID && ingress.NodeID != master.ID {
		// The storage row has no non-ingress Master transport. Borrow the
		// runtime application bound to this exact held ingress instead.
		policy, err = s.control.ExistingMasterNativePolicy(ctx, ingress)
		if err != nil || policy.State != "applied" || policy.Revision < 1 || policy.ConfiguredTransport != policy.AppliedTransport || policy.AppliedTransport != policy.EffectiveTransport {
			return nativeCatalogView{}, ErrUnavailable
		}
		switch policy.AppliedTransport {
		case "Direct":
			if node.ValidateMasterResourceOrigin(policy.AppliedOrigin) != nil {
				return nativeCatalogView{}, ErrUnavailable
			}
		case "Relay":
			if policy.AppliedOrigin != "" {
				return nativeCatalogView{}, ErrUnavailable
			}
		default:
			return nativeCatalogView{}, ErrUnavailable
		}
	} else {
		policy, err = routing.ExistingNativeTransport(ctx, id)
	}
	if err != nil || policy.MemberID != id || policy.EffectiveTransport != "Local" && policy.EffectiveTransport != "Direct" && policy.EffectiveTransport != "Relay" {
		return nativeCatalogView{}, ErrUnavailable
	}
	// Health observations are transient; the saved/applied policy, origin,
	// revision and effective route are not. Empty routing never falls back.
	out.policy = store.NativeTransportPolicy{MemberID: policy.MemberID, ConfiguredTransport: policy.ConfiguredTransport, AppliedTransport: policy.AppliedTransport, AppliedOrigin: policy.AppliedOrigin, LegacyTransport: policy.LegacyTransport, EffectiveTransport: policy.EffectiveTransport, Revision: policy.Revision}
	return out, nil
}

type nativeCatalogLease struct {
	inner   CatalogResourceLease
	service *Service
	repo    nativeCatalogRepository
	routing nativeCatalogRouting
	want    nativeCatalogView
}

func (l *nativeCatalogLease) Check(ctx context.Context) error {
	if l == nil || l.inner == nil || l.inner.Check(ctx) != nil {
		return ErrUnavailable
	}
	current, err := l.service.nativeCatalogView(ctx, l.repo, l.routing, l.want.owner)
	if err != nil || current != l.want || l.inner.Check(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
func (l *nativeCatalogLease) Release() {
	if l != nil && l.inner != nil {
		l.inner.Release()
	}
}

// NativeCatalogOwnerResolver captures a real native member under Owner then
// ingress shared fences. Final checks only borrow the admission's Owner lease;
// they never acquire locks in reverse order. S3 and missing policies fail
// closed. This primitive does not install the catalog or enable ingress.
func (s *Service) NativeCatalogOwnerResolver() (CatalogOwnerResolver, error) {
	if s == nil || s.nodes == nil || s.pool == nil {
		return nil, ErrUnavailable
	}
	nodesValue, poolValue := reflect.ValueOf(s.nodes), reflect.ValueOf(s.pool)
	if nodesValue.Kind() != reflect.Pointer || poolValue.Kind() != reflect.Pointer || nodesValue.IsNil() || poolValue.IsNil() || nodesValue.Type() != poolValue.Type() || nodesValue.Pointer() != poolValue.Pointer() {
		return nil, ErrUnavailable
	}
	repo, ok := s.pool.(nativeCatalogRepository)
	if !ok {
		return nil, ErrUnavailable
	}
	routing, ok := s.nodes.(nativeCatalogRouting)
	if !ok {
		return nil, ErrUnavailable
	}
	return func(ctx context.Context, id string) (CatalogOwnerSnapshot, error) {
		if ctx == nil || ctx.Err() != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		// Never trigger lazy initialization: the caller itself may already hold
		// Owner shared. Startup must initialize explicitly before admission.
		if _, err := routing.ExistingPublicIngress(ctx); err != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		owner, err := repo.AcquireOwnerControlShared(ctx)
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
		view, err := s.nativeCatalogView(ctx, repo, routing, id)
		if err != nil || view.ingress != current || owner.Check(ctx) != nil || ctx.Err() != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		if err := ingress.Commit(); err != nil {
			return CatalogOwnerSnapshot{}, ErrUnavailable
		}
		return CatalogOwnerSnapshot{Transport: view.policy.EffectiveTransport, Acquire: func(c context.Context, prerequisite store.IngressPrerequisite) (CatalogResourceLease, error) {
			inner, e := BorrowLocalCatalogOwnerSnapshot(binding)(c, prerequisite)
			if e != nil {
				return nil, ErrUnavailable
			}
			result := &nativeCatalogLease{inner: inner, service: s, repo: repo, routing: routing, want: view}
			if result.Check(c) != nil {
				result.Release()
				return nil, ErrUnavailable
			}
			return result, nil
		}}, nil
	}, nil
}
