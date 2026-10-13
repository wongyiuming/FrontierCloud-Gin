package noderetirement

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func clear(report Report) bool {
	return report.ObservationComplete && report.Master.DatabaseClear && report.Peer.DatabaseClear && len(report.Concerns) == 0 && report.ExpectedItems == 0
}
func (s *Service) Apply(ctx context.Context, member, relationship string, audit store.NodeAudit) (result store.RetirementFence, e error) {
	repo, ok := s.Repository.(store.RetirementFenceRepository)
	if !ok || s.Nodes == nil || s.Client == nil {
		return result, ErrObservation
	}
	identity, e := s.Nodes.ReadIdentity(ctx)
	if e != nil {
		return result, e
	}
	rel, e := s.Nodes.Relationship(ctx, relationship)
	if e != nil {
		return result, e
	}
	if identity.Role != "Master" || identity.ID == member || rel.PeerID != member || rel.Direction != "downstream" || rel.Protocol != 2 {
		return result, ErrObservation
	}
	if rel.State == "revoked" {
		return repo.RetirementFence(ctx, relationship, member)
	}
	if rel.State == "active" {
		report, e := s.Check(ctx, member, relationship)
		if e != nil {
			return result, e
		}
		if !clear(report) {
			return result, ErrObservation
		}
	}
	result, e = repo.BeginRetirement(ctx, relationship, member, audit)
	if e != nil {
		return result, e
	}
	peerCall := func(action string) (f store.RetirementFence, e error) {
		value, e := s.Client.Call(ctx, rel, "/internal/v1/retirement", map[string]any{"action": action, "confirm_member_id": member})
		if e != nil {
			return f, e
		}
		if e = decode(value, &f); e != nil {
			return f, e
		}
		if f.MemberID != member || f.RelationshipID != relationship || f.MasterID != identity.ID || f.FencedAt <= 0 || f.CompletedAt != 0 && f.CompletedAt < f.FencedAt {
			return f, ErrObservation
		}
		return f, nil
	}
	peer, e := peerCall("begin")
	if e != nil {
		return result, e
	}
	if peer.CompletedAt == 0 {
		report, e := s.Check(ctx, member, relationship)
		if e != nil {
			return result, e
		}
		if !clear(report) {
			return result, ErrObservation
		}
		peer, e = peerCall("complete")
		if e != nil {
			return result, e
		}
		if peer.CompletedAt == 0 {
			return result, ErrObservation
		}
	}
	return repo.CompleteRetirement(ctx, relationship, member, audit)
}
