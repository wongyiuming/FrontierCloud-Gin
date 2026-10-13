package business

import (
	"context"
	"encoding/json"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

func retirementMember(n store.NodeIdentity, v store.Relationship, member string) bool {
	return v.Protocol == 2 && (n.Role == "Master" && v.Direction == "downstream" && v.PeerID == member && member != n.ID || n.Role == "Follower" && v.Direction == "upstream" && n.ID == member && member != v.PeerID)
}
func retirementFenceValue(n store.NodeIdentity, v store.Relationship, member string) (f store.RetirementFence, e error) {
	if !retirementMember(n, v, member) || v.State != "retiring" && v.State != "revoked" {
		return f, store.ErrNodeState
	}
	raw, e := json.Marshal(v.Summary["retirement"])
	if e != nil || len(raw) > 1024 {
		return f, store.ErrNodeState
	}
	if json.Unmarshal(raw, &f) != nil {
		return f, store.ErrNodeState
	}
	master := n.ID
	if n.Role == "Follower" {
		master = v.PeerID
	}
	if f.MemberID != member || f.MasterID != master || f.RelationshipID != v.ID || f.FencedAt <= 0 || f.FencedAt > time.Now().Unix()+30 || v.State == "retiring" && f.CompletedAt != 0 || v.State == "revoked" && f.CompletedAt < f.FencedAt {
		return f, store.ErrNodeState
	}
	return f, nil
}
func (r *Repository) RetirementFence(ctx context.Context, relationship, member string) (store.RetirementFence, error) {
	n, e := r.ReadIdentity(ctx)
	if e != nil {
		return store.RetirementFence{}, e
	}
	v, e := r.Relationship(ctx, relationship)
	if e != nil {
		return store.RetirementFence{}, e
	}
	return retirementFenceValue(n, v, member)
}

// BeginRetirement closes ordinary relationship authentication durably. Its
// transaction serializes with owned mutations through the existing node lock.
// A failed later observation leaves this fence in place across process restart.
func (r *Repository) BeginRetirement(ctx context.Context, relationship, member string, a store.NodeAudit) (f store.RetirementFence, e error) {
	if !nodeIDPattern.MatchString(member) {
		return f, store.ErrNodeState
	}
	e = r.withRelation(ctx, relationship, func(q queryer, n store.NodeIdentity, v store.Relationship) error {
		if !retirementMember(n, v, member) {
			return store.ErrNodeState
		}
		if v.State == "retiring" || v.State == "revoked" {
			var e error
			f, e = retirementFenceValue(n, v, member)
			return e
		}
		if v.State != "active" {
			return store.ErrNodeState
		}
		ledger, e := r.retirementLedger(ctx, q, relationship, member)
		if e != nil {
			return e
		}
		if !ledger.DatabaseClear {
			return store.ErrNodeState
		}
		master := n.ID
		if n.Role == "Follower" {
			master = v.PeerID
		}
		f = store.RetirementFence{MemberID: member, RelationshipID: relationship, MasterID: master, FencedAt: time.Now().Unix()}
		v.Summary["retirement"] = f
		raw, e := json.Marshal(v.Summary)
		if e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE node_relationships SET state='retiring',summary=? WHERE relationship_id=?", string(raw), relationship); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE cluster_storage_members SET writable=0,updated_at=? WHERE member_id=?", f.FencedAt, member); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "retirement-fenced", relationship, map[string]any{"member_id": member, "fenced_at": f.FencedAt}, a)
	})
	return f, e
}

// CompleteRetirement is called only after native barriers and a fresh physical
// observation. It independently repeats SQL checks under the existing writer
// transaction. Tombstones keep identity, receipts and encrypted notification
// credentials; every ordinary capability and control path rejects this state.
func (r *Repository) CompleteRetirement(ctx context.Context, relationship, member string, a store.NodeAudit) (f store.RetirementFence, e error) {
	e = r.withRelation(ctx, relationship, func(q queryer, n store.NodeIdentity, v store.Relationship) error {
		var e error
		f, e = retirementFenceValue(n, v, member)
		if e != nil {
			return e
		}
		if v.State == "revoked" {
			return nil
		}
		ledger, e := r.retirementLedger(ctx, q, relationship, member)
		if e != nil {
			return e
		}
		if !ledger.DatabaseClear {
			return store.ErrNodeState
		}
		f.CompletedAt = time.Now().Unix()
		v.Summary["retirement"] = f
		v.Summary["revocation_acknowledged"] = true
		raw, e := json.Marshal(v.Summary)
		if e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE node_relationships SET state='revoked',status='offline',summary=? WHERE relationship_id=?", string(raw), relationship); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE cluster_storage_members SET health='offline',writable=0,updated_at=? WHERE member_id=?", f.CompletedAt, member); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "retirement-completed", relationship, map[string]any{"member_id": member, "fenced_at": f.FencedAt, "completed_at": f.CompletedAt}, a)
	})
	return f, e
}
