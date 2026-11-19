package node

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type readyIngressLease struct {
	mu         sync.Mutex
	done       bool
	committing bool
	ctx        context.Context
	inner      store.PublicIngressLease
	ready      IngressPrerequisiteLease
}

// IngressPrerequisiteLease must prevent its verified prerequisites from
// silently changing while held; Check verifies the held authority immediately
// before admission or selection commits. Release is idempotent.
type IngressPrerequisiteLease interface {
	Check(context.Context) error
	Release()
}

func validPrerequisiteLease(lease IngressPrerequisiteLease) bool {
	if lease == nil {
		return false
	}
	value := reflect.ValueOf(lease)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

// BindPrerequisite exposes the very same held authority to trusted readers.
// Its Check fails after Commit or Release, so a retained context cannot extend
// the tree lease or authorize another operation.
func (l *readyIngressLease) BindPrerequisite(ctx context.Context) (context.Context, error) {
	l.mu.Lock()
	if l.done || ctx == nil {
		l.mu.Unlock()
		return nil, store.ErrNodeState
	}
	l.mu.Unlock()
	if l.ready.Check(ctx) != nil {
		return nil, store.ErrNodeState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return nil, store.ErrNodeState
	}
	if composite, ok := l.ready.(*CatalogPrerequisite); ok {
		return store.WithIngressPrerequisite(ctx, &ingressTreeBorrow{prerequisite: composite}), nil
	}
	return store.WithIngressPrerequisite(ctx, l.ready), nil
}

func (l *readyIngressLease) Commit() error {
	l.mu.Lock()
	if l.done {
		l.mu.Unlock()
		return store.ErrNodeState
	}
	l.done = true
	l.committing = true
	l.mu.Unlock()
	defer func() { l.mu.Lock(); l.committing = false; l.mu.Unlock() }()
	if guard, ok := l.ready.(catalogCommitGuard); ok {
		return guard.commitCatalog(l.ctx, func(context.Context, store.IngressPrerequisite) error { return nil }, l.inner.Commit, l.inner.Release)
	}
	if err := l.ready.Check(l.ctx); err != nil {
		l.inner.Release()
		l.ready.Release()
		return err
	}
	err := l.inner.Commit()
	l.ready.Release()
	return err
}

func (l *readyIngressLease) Release() {
	l.mu.Lock()
	if l.done {
		committing := l.committing
		l.mu.Unlock()
		if committing {
			if guard, ok := l.ready.(catalogCommitGuard); ok {
				guard.Release()
			}
		}
		return
	}
	l.done = true
	l.mu.Unlock()
	defer l.ready.Release()
	l.inner.Release()
}

// ConfigureIngressSelectionReadiness is startup-only. Prepared encrypted Master
// startup supplies the authenticated Owner and catalog tree prerequisite.
// acquire must verify and hold that authority until Release.
func (s *Service) ConfigureIngressSelectionReadiness(ctx context.Context, acquire func(context.Context) (IngressPrerequisiteLease, error)) error {
	return s.configureIngressReadiness(ctx, acquire, true)
}

// ConfigureLocalIngressReadiness equips the Master ingress with its actual
// tree and Owner proof. Selecting a peer needs the separate peer runtime.
func (s *Service) ConfigureLocalIngressReadiness(ctx context.Context, acquire func(context.Context) (IngressPrerequisiteLease, error)) error {
	return s.configureIngressReadiness(ctx, acquire, false)
}

func (s *Service) configureIngressReadiness(ctx context.Context, acquire func(context.Context) (IngressPrerequisiteLease, error), allowPeer bool) error {
	if s == nil || s.repo == nil || acquire == nil || s.ingressSelectionReady != nil {
		return store.ErrNodeState
	}
	ready, err := acquire(ctx)
	if err != nil || !validPrerequisiteLease(ready) {
		if validPrerequisiteLease(ready) {
			ready.Release()
		}
		return store.ErrNodeState
	}
	defer ready.Release()
	if ready.Check(ctx) != nil {
		return store.ErrNodeState
	}
	if allowPeer {
		repository, ok := s.repo.(store.PeerIngressRepository)
		if !ok {
			return store.ErrNodeState
		}
		repository.EnablePeerIngress()
	}
	s.ingressSelectionReady = acquire
	s.peerIngressSelection = allowPeer
	return nil
}

func (s *Service) IngressSelectionAvailable(ctx context.Context) bool {
	if s == nil || !s.peerIngressSelection || s.ingressSelectionReady == nil {
		return false
	}
	ready, err := s.ingressSelectionReady(ctx)
	if err != nil || !validPrerequisiteLease(ready) {
		if validPrerequisiteLease(ready) {
			ready.Release()
		}
		return false
	}
	defer ready.Release()
	return ready.Check(ctx) == nil
}

// IngressSelectionConfigured reports whether the startup-only prerequisite
// lease has been installed. Admission itself acquires and validates it.
func (s *Service) IngressSelectionConfigured() bool {
	return s != nil && s.ingressSelectionReady != nil
}

// AcquireResourcePrerequisite fences the post-admission relay phase. A relay
// grant can drain after ingress admission commits, but its current visibility,
// placement and owner open must share this separate tree read lease. Release
// it before streaming bytes. An unconfigured service retains its legacy Master
// behavior; its repository does not enable peer ingress.
func (s *Service) AcquireResourcePrerequisite(ctx context.Context) (context.Context, IngressPrerequisiteLease, error) {
	if s == nil || ctx == nil {
		return nil, nil, store.ErrNodeState
	}
	if s.ingressSelectionReady == nil {
		return ctx, nil, nil
	}
	lease, err := s.ingressSelectionReady(ctx)
	if err != nil || !validPrerequisiteLease(lease) {
		if validPrerequisiteLease(lease) {
			lease.Release()
		}
		return nil, nil, store.ErrNodeState
	}
	if lease.Check(ctx) != nil {
		lease.Release()
		return nil, nil, store.ErrNodeState
	}
	if composite, ok := lease.(*CatalogPrerequisite); ok {
		return store.WithIngressPrerequisite(ctx, &ingressTreeBorrow{prerequisite: composite}), lease, nil
	}
	return store.WithIngressPrerequisite(ctx, lease), lease, nil
}

// SelectPublicIngress is the explicit administrator action. It never changes
// Master identity, resource ownership or transport policies. The repository
// rechecks the probed candidate and generation under its exclusive CAS fence.
func (s *Service) SelectPublicIngress(ctx context.Context, memberID string, expected int64, audit store.NodeAudit) (store.PublicIngress, error) {
	return s.SelectPublicIngressAtOrigin(ctx, memberID, expected, "", audit)
}

// SelectPublicIngressAtOrigin can pin the address the administrator confirmed.
// A changed candidate must be confirmed again even if its member ID is unchanged.
func (s *Service) SelectPublicIngressAtOrigin(ctx context.Context, memberID string, expected int64, expectedOrigin string, audit store.NodeAudit) (store.PublicIngress, error) {
	if s == nil || s.repo == nil || s.ingressSelectionReady == nil || !ValidIdentifier(memberID) || expected < 1 {
		return store.PublicIngress{}, store.ErrNodeState
	}
	if expectedOrigin != "" && ValidateFollowerIngressOrigin(expectedOrigin) != nil {
		return store.PublicIngress{}, store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || memberID != identity.ID && !s.peerIngressSelection {
		return store.PublicIngress{}, store.ErrNodeState
	}
	routing, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return store.PublicIngress{}, store.ErrNodeState
	}
	var relation store.Relationship
	var origin string
	var challenge string
	var proof Envelope
	var opaqueChallenge string
	var opaqueProof Envelope
	var probeStarted time.Time
	opaqueTree := s.opaqueIngressTree.Load()
	if memberID != identity.ID {
		if current, err := routing.PublicIngress(ctx); err == nil && current.Generation != expected {
			return store.PublicIngress{}, store.ErrNodeState
		}
		relations, err := s.repo.Relationships(ctx, false)
		if err != nil {
			return store.PublicIngress{}, err
		}
		for _, candidate := range relations {
			if candidate.PeerID == memberID && candidate.Direction == "downstream" && candidate.State == "active" {
				if relation.ID != "" {
					return store.PublicIngress{}, store.ErrNodeState
				}
				relation = candidate
			}
		}
		if relation.ID == "" {
			return store.PublicIngress{}, store.ErrNodeState
		}
		// All peer I/O happens before acquiring owner or tree locks. The
		// relationship and ingress generation are rechecked under the locks.
		probeStarted = time.Now()
		origin, challenge, proof, err = s.verifyFollowerIngressProxyEvidence(ctx, relation.ID)
		if err != nil {
			return store.PublicIngress{}, err
		}
		if opaqueTree != nil {
			opaqueChallenge, opaqueProof, err = s.verifyFollowerOpaqueReadinessEvidence(ctx, relation, origin)
			if err != nil {
				return store.PublicIngress{}, store.ErrNodeState
			}
		}
	} else if s.masterPublicOrigin == "" {
		return store.PublicIngress{}, store.ErrNodeState
	} else {
		origin = s.masterPublicOrigin
	}
	if expectedOrigin != "" && expectedOrigin != origin {
		return store.PublicIngress{}, store.ErrNodeState
	}
	coordinator, hasCoordinator := s.repo.(store.OwnerControlCoordinator)
	var selected store.PublicIngress
	commit := func(locked context.Context) error {
		ready, e := s.ingressSelectionReady(locked)
		if e != nil || !validPrerequisiteLease(ready) {
			if validPrerequisiteLease(ready) {
				ready.Release()
			}
			return store.ErrNodeState
		}
		defer ready.Release()
		s.opaqueIngressMu.RLock()
		defer s.opaqueIngressMu.RUnlock()
		if _, composite := ready.(*CatalogPrerequisite); composite {
			if !hasCoordinator || opaqueTree == nil {
				return store.ErrNodeState
			}
		}
		if s.opaqueIngressTree.Load() != opaqueTree {
			return store.ErrNodeState
		}
		if opaqueTree != nil {
			composite, ok := ready.(*CatalogPrerequisite)
			if !ok || composite.treeStore != opaqueTree {
				return store.ErrNodeState
			}
			validator, ok := s.repo.(interface {
				CheckOrderedIngressTree(context.Context, *sealedtree.SQLStore, store.OwnerControlLease) error
			})
			if !ok || validator.CheckOrderedIngressTree(locked, opaqueTree, composite.owner) != nil {
				return store.ErrNodeState
			}
		}
		if ready.Check(locked) != nil {
			return store.ErrNodeState
		}
		currentIdentity, e := s.repo.ReadIdentity(locked)
		if e != nil || currentIdentity != identity {
			return store.ErrNodeState
		}
		var peer store.PeerIngressRepository
		var evidence store.PeerIngressEvidence
		if memberID != identity.ID {
			verified, e := s.repo.Relationship(locked, relation.ID)
			if e != nil || !sameCatalogRelationship(relation, verified) {
				return store.ErrNodeState
			}
			if validateSelectionProbe(verified, challenge, proof, probeStarted, time.Now()) != nil {
				return store.ErrNodeState
			}
			if opaqueTree != nil && validateSelectionOpaqueProbe(verified, opaqueChallenge, opaqueProof, probeStarted, time.Now()) != nil {
				return store.ErrNodeState
			}
			var ok bool
			peer, ok = s.repo.(store.PeerIngressRepository)
			if !ok {
				return store.ErrNodeState
			}
			evidence = store.PeerIngressEvidence{MemberID: verified.PeerID, RelationshipID: verified.ID, PublicKey: verified.PublicKey, ControlEndpoint: verified.Endpoint, PublicOrigin: origin, CredentialDigest: store.PeerCredentialDigest(verified.Credential), CreatedAt: verified.CreatedAt, LastHeartbeat: verified.LastHeartbeat}
		}
		write := func() error {
			var e error
			if memberID == identity.ID {
				selected, e = routing.CommitMasterPublicIngress(locked, s.masterPublicOrigin, expected, audit)
			} else {
				selected, e = peer.CommitPeerPublicIngress(locked, evidence, expected, audit)
			}
			return e
		}
		if guard, ok := ready.(catalogCommitGuard); ok {
			return guard.commitCatalog(locked, func(context.Context, store.IngressPrerequisite) error { return nil }, write, func() {})
		}
		if ready.Check(locked) != nil || locked.Err() != nil {
			return store.ErrNodeState
		}
		return write()
	}
	commitCtx := ctx
	if memberID != identity.ID {
		var cancel context.CancelFunc
		commitCtx, cancel = context.WithDeadline(ctx, probeStarted.Add(time.Duration(protocol.TokenSeconds)*time.Second))
		defer cancel()
	}
	orderedCommit := func(locked context.Context) error {
		if opaqueTree == nil {
			return commit(locked) // preserve existing non-tree protocol
		}
		// A concrete tree prerequisite must not stay held while the writer
		// waits for ingress. Drop the preliminary check, then let the same
		// Owner-fenced repository acquire ingress -> tree before SQL.
		preliminary, err := s.ingressSelectionReady(locked)
		if err != nil || !validPrerequisiteLease(preliminary) {
			if validPrerequisiteLease(preliminary) {
				preliminary.Release()
			}
			return store.ErrNodeState
		}
		composite, hasTree := preliminary.(*CatalogPrerequisite)
		if preliminary.Check(locked) != nil {
			preliminary.Release()
			return store.ErrNodeState
		}
		if !hasTree {
			preliminary.Release()
			return store.ErrNodeState
		}
		tree := composite.treeStore
		preliminary.Release()
		if tree == nil || opaqueTree != nil && tree != opaqueTree {
			return store.ErrNodeState
		}
		ordered, ok := s.repo.(interface {
			WithOrderedIngressTree(context.Context, *sealedtree.SQLStore, func(context.Context) error) error
		})
		if !ok {
			return store.ErrNodeState
		}
		return ordered.WithOrderedIngressTree(locked, tree, commit)
	}
	if hasCoordinator {
		err = coordinator.WithOwnerControlExclusive(commitCtx, orderedCommit)
	} else {
		err = orderedCommit(commitCtx)
	}
	if err == nil {
		s.Wake()
	}
	return selected, err
}

func validateSelectionProbe(relation store.Relationship, challenge string, proof Envelope, started, now time.Time) error {
	age := now.Sub(started)
	if started.IsZero() || age < 0 || age > time.Duration(protocol.TokenSeconds)*time.Second {
		return store.ErrNodeState
	}
	payload, err := validateFollowerIdentityEnvelope(relation, challenge, proof)
	if err != nil {
		return store.ErrNodeState
	}
	features, err := protocol.ReadCapabilities(payload)
	if err != nil || !slices.Contains(features, peerIngressProxyCapability) {
		return store.ErrNodeState
	}
	return nil
}

func validateSelectionOpaqueProbe(relation store.Relationship, challenge string, proof Envelope, started, now time.Time) error {
	age := now.Sub(started)
	if started.IsZero() || age < 0 || age > time.Duration(protocol.TokenSeconds)*time.Second {
		return store.ErrNodeState
	}
	payload, err := validateFollowerIdentityEnvelope(relation, challenge, proof)
	if err != nil || textField(payload, "native_plain_probe") != "verified-v5-opaque" {
		return store.ErrNodeState
	}
	features, err := protocol.ReadCapabilities(payload)
	if err != nil || !slices.Contains(features, protocol.NativeOpaqueProofCapability) {
		return store.ErrNodeState
	}
	return nil
}
