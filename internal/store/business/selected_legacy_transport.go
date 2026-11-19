package business

import (
	"context"
	"database/sql"
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Called in the reservation transaction after identity and before member locks.
// An absent ingress row is the established Master-only deployment default.
func (r *Repository) legacySelectedIngress(ctx context.Context, q queryer, identity store.NodeIdentity, lock string) (store.PublicIngress, error) {
	var ingress store.PublicIngress
	err := q.QueryRowContext(ctx, "SELECT node_id,public_origin,generation FROM public_ingress_config WHERE singleton=1"+lock).Scan(&ingress.NodeID, &ingress.PublicOrigin, &ingress.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return store.PublicIngress{NodeID: identity.ID}, nil
	}
	if err != nil {
		return ingress, err
	}
	if !nodeIDPattern.MatchString(ingress.NodeID) || !validPublicOrigin(ingress.PublicOrigin) || ingress.Generation < 1 {
		return ingress, store.ErrNodeState
	}
	return ingress, nil
}

// The old capability protocol addresses the peer's control origin and carries
// no independent resource-policy revision. Do not use it to implement a new
// applied route which differs from those legacy facts.
func (r *Repository) checkLegacySelectedTransport(ctx context.Context, q queryer, identity store.NodeIdentity, ingress store.PublicIngress, member store.StorageMember, lock string) error {
	policy, err := r.nativeTransport(ctx, q, identity, ingress, member.ID, lock)
	if err != nil {
		return err
	}
	if member.Kind == "MasterLocal" && member.ID == identity.ID && member.Transport == "Local" {
		return nil
	}
	if policy.LegacyTransport != member.Transport {
		return nodeConflict("selected node relationship and storage transport disagree")
	}
	if member.RelationshipID == nil {
		return store.ErrNodeState
	}
	var endpoint string
	var version, credentialBytes int
	if err := q.QueryRowContext(ctx, "SELECT peer_endpoint,protocol,LENGTH(credential) FROM node_relationships WHERE relationship_id=?"+lock, *member.RelationshipID).Scan(&endpoint, &version, &credentialBytes); err != nil {
		return err
	}
	if version != protocol.Version || credentialBytes == 0 {
		return store.ErrNodeState
	}
	if policy.Revision == 0 {
		if ingress.NodeID == identity.ID {
			return nil
		}
		return nodeConflict("peer ingress uploads require an applied native transport policy")
	}
	if policy.State != "applied" || policy.AppliedTransport != member.Transport || policy.ConfiguredTransport != member.Transport {
		return nodeConflict("selected node transport requires the versioned upload protocol")
	}
	if member.Transport == "Direct" && policy.AppliedOrigin != endpoint {
		return nodeConflict("selected node resource origin requires the versioned upload protocol")
	}
	return nil
}

// LegacySelectedUploadReady is a read-only UI observation. Only the checks in
// the reservation's write transaction authorize storage capacity or a ticket.
func (r *Repository) LegacySelectedUploadReady(ctx context.Context, memberID string) error {
	identity, err := r.ReadIdentity(ctx)
	if err != nil {
		return err
	}
	if identity.Role != "Master" || !nodeIDPattern.MatchString(memberID) {
		return store.ErrNodeState
	}
	ingress, err := r.legacySelectedIngress(ctx, r.db, identity, "")
	if err != nil {
		return err
	}
	member, err := scanMember(r.db.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?", memberID))
	if err != nil {
		return err
	}
	return r.checkLegacySelectedTransport(ctx, r.db, identity, ingress, member, "")
}
