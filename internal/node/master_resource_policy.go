package node

import (
	"context"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type masterResourceApplication struct {
	ingress    store.PublicIngress
	revision   int64
	transport  string
	origin     string
	verifiedAt time.Time
}

const masterResourceApplicationTTL = 90 * time.Second

// ConfigureMasterResourceReadiness is startup-only. A missing verifier keeps
// the Master resource policy unapplied after every restart.
func (s *Service) ConfigureMasterResourceReadiness(origin string, verify func(context.Context, store.PublicIngress, string, string) error) error {
	if s == nil {
		return store.ErrNodeState
	}
	if origin != "" && ValidateMasterResourceOrigin(origin) != nil {
		return errors.New("invalid Master resource origin")
	}
	s.masterResourceOrigin, s.masterResourceReady = origin, verify
	return nil
}

// ConfigureMasterRelayObservation installs a startup-only local freshness
// check for a previously verified Relay path; it performs no network probe.
func (s *Service) ConfigureMasterRelayObservation(check func(context.Context, store.PublicIngress) error) {
	s.masterRelayObservation = check
}

// PrepareMasterResourcePolicy checks the explicitly saved choice while holding
// an ingress admission. It does not select an ingress or change the policy.
func (s *Service) PrepareMasterResourcePolicy(ctx context.Context) error {
	if s == nil {
		return store.ErrNodeState
	}
	prepared := false
	defer func() {
		if !prepared {
			s.masterPolicyMu.Lock()
			s.masterPolicy = masterResourceApplication{}
			s.masterPolicyMu.Unlock()
		}
	}()
	if s.repo == nil || s.masterResourceReady == nil {
		return store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return store.ErrNodeState
	}
	repository, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return store.ErrNodeState
	}
	ingress, lease, err := s.AcquireCurrentIngress(ctx)
	if err != nil {
		return err
	}
	defer lease.Release()
	policy, err := repository.NativeTransport(ctx, identity.ID)
	if err != nil || policy.MemberID != identity.ID || policy.Revision < 1 || policy.ConfiguredTransport != "Direct" && policy.ConfiguredTransport != "Relay" {
		return store.ErrNodeState
	}
	origin := ""
	if policy.ConfiguredTransport == "Direct" {
		origin = s.masterResourceOrigin
		if origin == "" {
			return store.ErrNodeState
		}
	}
	if s.masterResourceReady(ctx, ingress, policy.ConfiguredTransport, origin) != nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	if err := lease.Commit(); err != nil {
		return err
	}
	s.masterPolicyMu.Lock()
	s.masterPolicy = masterResourceApplication{ingress: ingress, revision: policy.Revision, transport: policy.ConfiguredTransport, origin: origin, verifiedAt: time.Now()}
	s.masterPolicyMu.Unlock()
	prepared = true
	return nil
}

// MasterNativePolicy reports a runtime-verified application only for the same
// saved revision and ingress generation. It never infers a policy from role.
func (s *Service) MasterNativePolicy(ctx context.Context) (store.NativeTransportPolicy, error) {
	if s == nil || s.repo == nil {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	repository, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	ingress, err := repository.PublicIngress(ctx)
	if err != nil {
		return store.NativeTransportPolicy{}, err
	}
	policy, err := repository.NativeTransport(ctx, identity.ID)
	if err != nil {
		return store.NativeTransportPolicy{}, err
	}
	return s.appliedMasterNativePolicy(ctx, identity.ID, ingress, policy), nil
}

// ExistingMasterNativePolicy reads the runtime application for the ingress
// already fenced by the caller. It never initializes routing or probes a peer.
func (s *Service) ExistingMasterNativePolicy(ctx context.Context, expected store.PublicIngress) (store.NativeTransportPolicy, error) {
	if s == nil || s.repo == nil {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	repository, ok := s.repo.(interface {
		store.ExistingIngressRepository
		ExistingNativeTransport(context.Context, string) (store.NativeTransportPolicy, error)
	})
	if !ok {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	ingress, err := repository.ExistingPublicIngress(ctx)
	if err != nil || ingress != expected {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	policy, err := repository.ExistingNativeTransport(ctx, identity.ID)
	if err != nil || policy.MemberID != identity.ID || policy.ConfiguredTransport == "Relay" && s.masterRelayObservation == nil {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	return s.appliedMasterNativePolicy(ctx, identity.ID, ingress, policy), nil
}

func (s *Service) appliedMasterNativePolicy(ctx context.Context, masterID string, ingress store.PublicIngress, policy store.NativeTransportPolicy) store.NativeTransportPolicy {
	s.masterPolicyMu.RLock()
	proof := s.masterPolicy
	s.masterPolicyMu.RUnlock()
	if s.masterResourceReady == nil || proof.verifiedAt.IsZero() || time.Since(proof.verifiedAt) < 0 || time.Since(proof.verifiedAt) >= masterResourceApplicationTTL || proof.ingress != ingress || proof.revision != policy.Revision || proof.transport != policy.ConfiguredTransport || proof.revision < 1 {
		policy.AppliedTransport, policy.AppliedOrigin = "", ""
		if policy.Revision > 0 {
			policy.PeerApplicationStatus = "pending"
			if ingress.NodeID == masterID {
				policy.State, policy.EffectiveTransport = "retained", "Local"
			} else {
				policy.State, policy.EffectiveTransport = "blocked", ""
			}
		}
		return policy
	}
	// Relay depends on the current peer's advertised origin and paired path,
	// both of which can change independently of the Master policy revision.
	// Recheck them while the caller holds public admission before issuing.
	relayInvalid := false
	if proof.transport == "Relay" {
		if s.masterRelayObservation != nil {
			relayInvalid = s.masterRelayObservation(ctx, ingress) != nil
		} else {
			relayInvalid = s.masterResourceReady(ctx, ingress, proof.transport, proof.origin) != nil
		}
	}
	if relayInvalid {
		policy.AppliedTransport, policy.AppliedOrigin = "", ""
		policy.PeerApplicationStatus = "pending"
		if ingress.NodeID != masterID {
			policy.State, policy.EffectiveTransport = "blocked", ""
		}
		return policy
	}
	policy.AppliedTransport, policy.AppliedOrigin = proof.transport, proof.origin
	policy.PeerApplicationStatus = "applied"
	if ingress.NodeID != masterID {
		policy.State, policy.EffectiveTransport = "applied", proof.transport
	}
	return policy
}
