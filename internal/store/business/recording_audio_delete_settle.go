package business

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func recordingAudioCleanupMarker(key []byte, receipt protocol.OpaqueCapacityReceipt) (string, error) {
	payload, err := receipt.Payload()
	if err != nil {
		return "", store.ErrRecordingState
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", store.ErrRecordingState
	}
	defer clear(raw)
	return hex.EncodeToString(capacityMAC(key, "recording-audio-cleanup-v1", raw)), nil
}

func recordingAudioCleanupReceipt(claim protocol.SelectedStorageUpload) protocol.OpaqueCapacityReceipt {
	return protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-cleaned-v1", MasterID: claim.Master, OwnerID: claim.Owner,
		RelationshipID: claim.Relationship, RelationshipBinding: claim.RelationshipBinding, Generation: claim.Generation,
		OperationID: claim.OperationID, StageID: claim.StageID, BlobID: claim.ObjectID, Digest: claim.ContentSHA256,
		Challenge: claim.CleanupChallenge, Bytes: claim.Size, State: "cleaned"}
}

// finishRecordingAudioDeletion is private until Owner cleanup, recovery and
// account-session authority are wired as a single product lifecycle. The
// keyed permanent marker attests that this exact signed cleanup was verified
// before the single quota refund. It does not reveal the receipt in the tree.
func (s *SelectedUploadRuntime) finishRecordingAudioDeletion(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, recordingID string, receipt protocol.OpaqueCapacityReceipt, signature string, audit store.KaraokeAudit, checkAccount func(context.Context) error) (bool, error) {
	if s == nil || s.repo == nil || ctx == nil || tree == nil || tree != s.tree || s.crypto == nil || s.vault == nil || selectedNil(s.gate) || checkAccount == nil || checkAccount(ctx) != nil || signature == "" {
		return false, store.ErrRecordingState
	}
	actualBrowser, sessionID, _, valid := mediacrypto.DirectSessionFromContext(ctx).Values()
	if !valid || actualBrowser != browser {
		return false, store.ErrRecordingState
	}
	lease, err := s.gate.AcquireSelectedUpload(ctx, tree)
	if err != nil || selectedNil(lease) {
		return false, store.ErrNodeState
	}
	defer lease.Release()
	if lease.Check(ctx) != nil {
		return false, store.ErrNodeState
	}
	if _, err := store.RecordingAudioPreparationBinding(user.ID, browser, recordingID); err != nil {
		return false, err
	}
	return s.finishRecordingAudioDeletionChecked(ctx, tree, user.ID, recordingID, receipt, signature, audit, func(c context.Context, q queryer, intent recordingAudioIntent) error {
		if lease.Check(c) != nil {
			return store.ErrRecordingState
		}
		return s.checkRecordingAudioAuthorityTx(c, q, expected, user, browser, sessionID, intent.MemberID)
	})
}

func (s *SelectedUploadRuntime) finishRecordingAudioDeletionChecked(ctx context.Context, tree *sealedtree.SQLStore, userID, recordingID string, receipt protocol.OpaqueCapacityReceipt, signature string, audit store.KaraokeAudit, check func(context.Context, queryer, recordingAudioIntent) error) (bool, error) {
	already := false
	err := s.repo.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		var intent recordingAudioIntent
		e := s.repo.withSelectedMutation(held, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
			var found bool
			var e error
			intent, _, _, found, e = s.repo.readRecordingAudioIntentTx(c, q, s.key, recordingID)
			if e != nil || !found || intent.UserID != userID || (intent.State != "deleting" && intent.State != "deleted") || check(c, q, intent) != nil || m.CheckRecordingAudioCompletionTx(c, q, intent.UserID, intent.RecordingID, intent.OperationID, intent.BlobID) != nil {
				return store.ErrRecordingState
			}
			return c.Err()
		})
		if e != nil {
			return e
		}
		if intent.State == "deleting" {
			ready, e := s.recordingAudioReadyChecked(held, userID, recordingID, nil, nil, true, check, nil)
			if e != nil || !ready {
				return store.ErrRecordingState
			}
		}
		return s.repo.withSelectedMutation(held, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
			current, _, _, found, e := s.repo.readRecordingAudioIntentTx(c, q, s.key, recordingID)
			if e != nil || !found || current != intent || check(c, q, current) != nil || m.CheckRecordingAudioCompletionTx(c, q, intent.UserID, intent.RecordingID, intent.OperationID, intent.BlobID) != nil {
				return store.ErrRecordingState
			}
			claim, e := s.repo.recordingAudioCleanupClaimTx(c, q, s.key, intent)
			if e != nil {
				return e
			}
			wanted := recordingAudioCleanupReceipt(claim)
			if receipt != wanted {
				return store.ErrRecordingState
			}
			payload, e := receipt.Payload()
			if e != nil {
				return store.ErrRecordingState
			}
			identity, e := readNode(c, q, s.repo.lock())
			if e != nil || identity.Role != "Master" || identity.ID != intent.MasterID {
				return store.ErrNodeState
			}
			ownerBinding, e := s.repo.recordingAudioOwnerBinding(c, q, s.key, identity, intent.MemberID)
			if e != nil || ownerBinding != intent.OwnerBinding {
				return store.ErrNodeState
			}
			public, e := s.recordingAudioCleanupPublicKey(c, q, identity, intent, claim)
			if e != nil || protocol.Verify(public, payload, signature) != nil {
				return store.ErrRecordingState
			}
			marker, e := recordingAudioCleanupMarker(s.key, receipt)
			if e != nil {
				return e
			}
			row, e := recordingLookup(q.QueryRowContext(c, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+s.repo.lock(), recordingID))
			if e != nil || row == nil || row.UserID != userID || row.MemberID != intent.MemberID || row.Bytes != intent.Bytes || row.State != intent.State || row.SHA256 == nil || *row.SHA256 != intent.Digest {
				return store.ErrRecordingState
			}
			if intent.State == "deleted" {
				if !capacityIDExists(c, q, marker, s.repo.lock()) {
					return store.ErrRecordingState
				}
				already = true
				return c.Err()
			}
			if _, e = q.ExecContext(c, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, marker); e != nil {
				return store.ErrRecordingState
			}
			account, e := scanUser(q.QueryRowContext(c, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+s.repo.lock(), userID))
			if e != nil || account.Status != "active" || account.Used < intent.Bytes || account.Quota < account.Used {
				return store.ErrRecordingState
			}
			member, e := scanMember(q.QueryRowContext(c, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+s.repo.lock(), intent.MemberID))
			kind := "Follower"
			if intent.MemberID == intent.MasterID {
				kind = "MasterLocal"
			}
			if e != nil || member.Kind != kind || member.Used < intent.Bytes {
				return store.ErrRecordingState
			}
			updated, e := q.ExecContext(c, `UPDATE karaoke_users SET used_bytes=used_bytes-?,updated_at=? WHERE user_id=? AND used_bytes=?`, intent.Bytes, time.Now().Unix(), userID, account.Used)
			if e != nil {
				return e
			}
			if n, e := updated.RowsAffected(); e != nil || n != 1 {
				return store.ErrRecordingState
			}
			updated, e = q.ExecContext(c, `UPDATE cluster_storage_members SET used_bytes=used_bytes-?,updated_at=? WHERE member_id=? AND used_bytes=?`, intent.Bytes, time.Now().Unix(), intent.MemberID, member.Used)
			if e != nil {
				return e
			}
			if n, e := updated.RowsAffected(); e != nil || n != 1 {
				return store.ErrRecordingState
			}
			if e = s.repo.transitionRecordingAudioTx(c, q, s.key, intent, "deleting", "deleted"); e != nil {
				return e
			}
			updated, e = q.ExecContext(c, `UPDATE karaoke_recordings SET state='deleted',updated_at=? WHERE recording_id=? AND user_id=? AND state='deleting' AND sha256=?`, time.Now().Unix(), recordingID, userID, intent.Digest)
			if e != nil {
				return e
			}
			if n, e := updated.RowsAffected(); e != nil || n != 1 {
				return store.ErrRecordingState
			}
			audit.UserID, audit.Action, audit.Result = userID, "recording-delete", "success"
			audit.Detail = map[string]any{"recording_id": recordingID, "size_bytes": intent.Bytes}
			if e = s.repo.karaokeAudit(c, q, audit); e != nil {
				return e
			}
			if check(c, q, intent) != nil {
				return store.ErrRecordingState
			}
			return c.Err()
		})
	})
	return already, err
}

func (s *SelectedUploadRuntime) recordingAudioCleanupPublicKey(c context.Context, q queryer, identity store.NodeIdentity, intent recordingAudioIntent, claim protocol.SelectedStorageUpload) (string, error) {
	if intent.MemberID == identity.ID {
		secret, err := s.vault.Unseal(identity.PrivateKey)
		if err != nil {
			return "", store.ErrNodeState
		}
		return protocol.PublicKey(secret)
	}
	relation, err := scanRelation(q.QueryRowContext(c, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+s.repo.lock(), claim.Relationship))
	if err != nil || relation.PeerID != intent.MemberID || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version {
		return "", store.ErrNodeState
	}
	binding := store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID,
		PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt})
	if binding != claim.RelationshipBinding {
		return "", store.ErrNodeState
	}
	return relation.PublicKey, nil
}
