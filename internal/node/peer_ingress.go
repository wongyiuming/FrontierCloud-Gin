package node

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This process-local observation is never authority to select an ingress. A
// restart waits for a fresh authenticated Master heartbeat; every forwarded
// request is still verified against the Master's current lease.
type peerIngressState struct {
	relationship string
	masterID     string
	ingress      store.PublicIngress
	observedAt   time.Time
}

// Three expected 30-second heartbeats bound the lifetime of a stale origin.
// This bounds configuration observation, not a resource grant's lifetime.
const peerIngressObservationTTL = 90 * time.Second

func (s *Service) observePeerIngress(ctx context.Context, relation store.Relationship, raw any) {
	value, ok := raw.(map[string]any)
	if !ok || len(value) != 3 {
		return
	}
	nodeID, ok := value["node_id"].(string)
	if !ok || !ValidIdentifier(nodeID) {
		return
	}
	public, ok := value["public_origin"].(string)
	if !ok {
		return
	}
	canonical, err := Endpoint(public)
	if err != nil || canonical != public {
		return
	}
	generation, ok := intField(value, "generation")
	if !ok || generation < 1 {
		return
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" {
		return
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "upstream" || current.Protocol != protocol.Version || current.PeerID != relation.PeerID {
		return
	}
	observation := peerIngressState{relationship: relation.ID, masterID: current.PeerID, ingress: store.PublicIngress{NodeID: nodeID, PublicOrigin: public, Generation: generation}, observedAt: time.Now()}
	s.peerIngressMu.Lock()
	defer s.peerIngressMu.Unlock()
	old := s.peerIngress
	if old.masterID == current.PeerID && (old.ingress.Generation > generation || old.ingress.Generation == generation && old.ingress != observation.ingress) {
		return
	}
	s.peerIngress = observation
}

// ObservedPublicIngress provides fresh configuration only, not authorization.
func (s *Service) ObservedPublicIngress(ctx context.Context) (store.PublicIngress, store.Relationship, error) {
	s.peerIngressMu.RLock()
	value := s.peerIngress
	s.peerIngressMu.RUnlock()
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" || value.relationship == "" || value.observedAt.IsZero() || time.Since(value.observedAt) < 0 || time.Since(value.observedAt) >= peerIngressObservationTTL {
		return store.PublicIngress{}, store.Relationship{}, store.ErrNodeState
	}
	relation, err := s.repo.Relationship(ctx, value.relationship)
	if err != nil || relation.State != "active" || relation.Direction != "upstream" || relation.Protocol != protocol.Version || relation.PeerID != value.masterID {
		return store.PublicIngress{}, store.Relationship{}, store.ErrNodeState
	}
	return value.ingress, relation, nil
}

// CurrentPeerIngress is an observation for preparing a proxy, not authority.
func (s *Service) CurrentPeerIngress(ctx context.Context) (store.PublicIngress, store.Relationship, error) {
	ingress, relation, err := s.ObservedPublicIngress(ctx)
	if err != nil {
		return store.PublicIngress{}, store.Relationship{}, err
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || ingress.NodeID != identity.ID {
		return store.PublicIngress{}, store.Relationship{}, store.ErrNodeState
	}
	return ingress, relation, nil
}
