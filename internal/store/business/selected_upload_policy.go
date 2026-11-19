package business

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// AcquireSelectedUploadOwnerPolicy is only a policy/relation fence, never a
// complete bearer or browser-session authorization. The configured Owner
// control fence must be shared until upload ends so a coordinated relation or
// policy writer cannot acknowledge a change while the old stream is active.
// The caller must reject unverified capabilities before calling it and recheck
// the lease before accepting bytes and publishing. This primitive is dormant.
func (r *Repository) AcquireSelectedUploadOwnerPolicy(ctx context.Context, expected store.SelectedUploadPolicy) (store.OwnerControlLease, error) {
	if ctx == nil || !nodeIDPattern.MatchString(expected.RelationshipID) || !nodeIDPattern.MatchString(expected.MasterID) || !nodeIDPattern.MatchString(expected.OwnerID) || expected.MasterID == expected.OwnerID || expected.Revision < 1 ||
		(expected.Transport != "Direct" && expected.Transport != "Relay") ||
		(expected.Transport == "Direct" && !validPublicOrigin(expected.ResourceOrigin)) || (expected.Transport == "Relay" && expected.ResourceOrigin != "") {
		return nil, store.ErrNodeState
	}
	lease, err := r.AcquireOwnerControlShared(ctx)
	if err != nil {
		return nil, store.ErrNodeState
	}
	accepted := false
	defer func() {
		if !accepted {
			lease.Release()
		}
	}()
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, store.ErrNodeState
	}
	defer tx.Rollback()
	if err = r.checkOwnerControlMarker(ctx, tx, lease); err != nil || lease.Check(ctx) != nil {
		return nil, store.ErrNodeState
	}
	identity, err := readNode(ctx, tx, "")
	if err != nil || identity.Role != "Follower" || identity.ID != expected.OwnerID {
		return nil, store.ErrNodeState
	}
	relation, err := scanRelation(tx.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?", expected.RelationshipID))
	if err != nil || relation.ID != expected.RelationshipID || relation.PeerID != expected.MasterID || relation.Direction != "upstream" || relation.State != "active" || relation.Protocol != protocol.Version {
		return nil, store.ErrNodeState
	}
	raw, err := json.Marshal(relation.Summary[nativeTransportReceiptKey])
	var applied nativeTransportReceipt
	if err != nil || json.Unmarshal(raw, &applied) != nil || applied.Revision != expected.Revision || applied.Transport != expected.Transport || applied.Origin != expected.ResourceOrigin {
		return nil, store.ErrNodeState
	}
	if err = lease.Check(ctx); err != nil || tx.Commit() != nil {
		return nil, store.ErrNodeState
	}
	accepted = true
	return lease, nil
}

var _ store.SelectedUploadOwnerPolicyRepository = (*Repository)(nil)
