package business

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// recordingAudioAdmission is constructed only after an authenticated account
// and current browser binding are established. It is never a public API or an
// Owner capability. Lyrics remain closed until their own tree reservation is
// integrated, so an audio ID cannot bypass the global file-ID ledger.
type recordingAudioAdmission struct {
	UserID, RecordingID, MemberID string
	Digest, Binding, Title        string
	ContentType                   string
	Encryption                    mediacrypto.Metadata
}

// ReserveRecordingAudioPreparation is called only by the authenticated Master
// after resolving the server-side browser binding. It permanently reserves the
// file ID under the same Owner/ingress/tree/SQLite lock order as a ticket. It
// neither authorizes nor returns a key; the caller must issue the transient
// browser token/envelope only after this transaction commits.
func (r *Repository) ReserveRecordingAudioPreparation(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, userID, browserBinding, recordingID string, meta mediacrypto.Metadata) error {
	binding, err := store.RecordingAudioPreparationBinding(userID, browserBinding, recordingID)
	if r == nil || ctx == nil || tree == nil || err != nil || meta.Validate() != nil || meta.CiphertextSize <= 0 || meta.CiphertextSize > store.MaxRecordingBytes || !nodeIDPattern.MatchString(expected.NodeID) || !validPublicOrigin(expected.PublicOrigin) || expected.Generation < 1 {
		return store.ErrRecordingState
	}
	session := mediacrypto.DirectSessionFromContext(ctx)
	checkSession := func() bool {
		actual, _, _, valid := session.Values()
		return valid && actual == browserBinding
	}
	if !checkSession() {
		return store.ErrRecordingState
	}
	return r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		identity, e := readNode(c, q, r.lock())
		if e != nil || identity.Role != "Master" || identity.PrivateKey == "" || identity.CreatedAt <= 0 {
			return store.ErrNodeState
		}
		var current store.PublicIngress
		if e = q.QueryRowContext(c, "SELECT node_id,public_origin,generation FROM public_ingress_config WHERE singleton=1"+r.lock()).Scan(&current.NodeID, &current.PublicOrigin, &current.Generation); e != nil || current != expected {
			return store.ErrNodeState
		}
		if current.NodeID == identity.ID {
			if r.configuredPublicOrigin() == "" || current.PublicOrigin != r.configuredPublicOrigin() {
				return store.ErrNodeState
			}
		} else if !r.peerIngressEnabled.Load() || validateActivePeerIngress(c, q, current.NodeID, current.PublicOrigin) != nil {
			return store.ErrNodeState
		}
		user, e := scanUser(q.QueryRowContext(c, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+r.lock(), userID))
		if e != nil || user.Status != "active" || user.Used < 0 || user.Quota < user.Used || meta.CiphertextSize > user.Quota-user.Used || !checkSession() {
			return store.ErrRecordingState
		}
		var existing int
		if e = q.QueryRowContext(c, "SELECT COUNT(*) FROM karaoke_recordings WHERE recording_id=?", recordingID).Scan(&existing); e != nil || existing != 0 {
			return store.ErrRecordingState
		}
		if e = mutation.ReserveRecordingAudioPreparationTx(c, q, meta, binding); e != nil {
			return e
		}
		if !checkSession() {
			return store.ErrRecordingState
		}
		return c.Err()
	})
}

// recordingAudioOwnerBinding pins the actual Master, selected member, paired
// Owner identity at reservation. A later grant independently checks current
// transport policy, so reapplying Direct to the same pair preserves its data.
func (r *Repository) recordingAudioOwnerBinding(ctx context.Context, q queryer, key []byte, master store.NodeIdentity, memberID string) (string, error) {
	if master.Role != "Master" || master.PrivateKey == "" || master.CreatedAt <= 0 {
		return "", store.ErrNodeState
	}
	member, err := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), memberID))
	if err != nil || member.ID != memberID || member.Kind == "S3" || member.Enabled == 0 || member.Health != "online" || member.Draining {
		return "", store.ErrStorageCapacity
	}
	state := struct {
		Master, Member, Relation, PeerBinding, Policy, Origin string
		Revision                                              int64
	}{Master: capacityMasterBinding(master), Member: member.ID}
	if member.ID == master.ID {
		if member.Kind != "MasterLocal" || member.Transport != "Local" || member.RelationshipID != nil || member.Writable == 0 {
			return "", store.ErrNodeState
		}
		state.Policy, state.Revision = "Local", 1
	} else {
		if member.Kind != "Follower" || member.RelationshipID == nil {
			return "", store.ErrStorageCapacity
		}
		relation, e := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), *member.RelationshipID))
		now := time.Now().Unix()
		if e != nil || relation.PeerID != member.ID || relation.Direction != "downstream" || relation.State != "active" || relation.Status != "online" || relation.Protocol != protocol.Version || relation.Endpoint == "" || relation.Credential == "" || relation.CreatedAt <= 0 || relation.LastHeartbeat <= 0 || now-relation.LastHeartbeat < 0 || now-relation.LastHeartbeat >= 120 {
			return "", store.ErrStorageCapacity
		}
		if pub, e := protocol.Decode(relation.PublicKey); e != nil || len(pub) != 32 {
			return "", store.ErrNodeState
		}
		state.Relation = relation.ID
		state.PeerBinding = store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt})
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return "", store.ErrNodeState
	}
	defer clear(raw)
	return hex.EncodeToString(capacityMAC(key, "recording-audio-owner-v1", raw)), nil
}

// reserveRecordingAudioCoordinated is a deliberately unregistered SQLite
// coordinator. check must verify current account authorization, requested
// Owner permission and the browser-bound transient preparation while q and the
// real fences remain held. It must not perform network I/O. Publication,
// Owner receipts, cancellation and safe readback are separate required gates.
func (r *Repository) reserveRecordingAudioCoordinated(ctx context.Context, tree *sealedtree.SQLStore, key []byte, request recordingAudioAdmission, localFree int64, audit store.KaraokeAudit, check func(context.Context, queryer, recordingAudioAdmission) error) (recordingAudioIntent, bool, error) {
	var result recordingAudioIntent
	var already bool
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || check == nil || localFree < 0 || !nodeIDPattern.MatchString(request.UserID) || !nodeIDPattern.MatchString(request.RecordingID) || !nodeIDPattern.MatchString(request.MemberID) || !nodeHashPattern.MatchString(request.Digest) || request.Encryption.Validate() != nil || request.Encryption.CiphertextSize <= 0 || request.Encryption.CiphertextSize > store.MaxRecordingBytes || !store.RecordingContentType(request.ContentType) {
		return result, false, store.ErrRecordingState
	}
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		if err := check(c, q, request); err != nil {
			return err
		}
		identity, err := readNode(c, q, r.lock())
		if err != nil {
			return store.ErrNodeState
		}
		ownerBinding, err := r.recordingAudioOwnerBinding(c, q, key, identity, request.MemberID)
		if err != nil {
			return err
		}
		user, err := scanUser(q.QueryRowContext(c, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+r.lock(), request.UserID))
		if err != nil || user.Status != "active" || user.Used < 0 || user.Quota < user.Used {
			return store.ErrRecordingState
		}
		titleHash := sha256.Sum256([]byte(request.Title))
		previous, oldTitle, oldLyrics, found, err := r.readRecordingAudioIntentTx(c, q, key, request.RecordingID)
		if err != nil {
			return err
		}
		if found {
			if previous.State != "pending" || previous.UserID != request.UserID || previous.MasterID != identity.ID || previous.MemberID != request.MemberID || previous.OwnerBinding != ownerBinding || previous.Binding != request.Binding || previous.Digest != request.Digest || previous.Encryption != request.Encryption || previous.ContentType != request.ContentType || oldTitle != request.Title || len(oldLyrics) != 0 || user.Used < previous.Bytes {
				return store.ErrRecordingState
			}
			row, e := recordingLookup(q.QueryRowContext(c, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+r.lock(), request.RecordingID))
			if e != nil || row == nil || row.UserID != request.UserID || row.MemberID != request.MemberID || row.State != "pending" || row.Bytes != previous.Bytes {
				return store.ErrRecordingState
			}
			if err = mutation.CheckRecordingAudioBlobTx(c, q, previous.BlobID); err != nil {
				return err
			}
			result = previous
		} else {
			if user.Quota-user.Used < request.Encryption.CiphertextSize {
				return store.ErrRecordingQuota
			}
			op, e := sealedtree.NewBlobID()
			if e != nil {
				return e
			}
			blob, e := sealedtree.NewBlobID()
			if e != nil || blob == op {
				return store.ErrRecordingState
			}
			result = recordingAudioIntent{UserID: request.UserID, RecordingID: request.RecordingID, MasterID: identity.ID, MemberID: request.MemberID, OperationID: op, BlobID: blob, Digest: request.Digest, Bytes: request.Encryption.CiphertextSize, Binding: request.Binding, OwnerBinding: ownerBinding, ContentType: request.ContentType, Encryption: request.Encryption, TitleDigest: hex.EncodeToString(titleHash[:]), State: "pending"}
			if !validRecordingAudioIntent(result) {
				return store.ErrRecordingState
			}
			if err = mutation.ClaimRecordingAudioPreparationTx(c, q, request.Encryption, request.Binding, op); err != nil {
				return err
			}
			if err = mutation.ReserveRecordingAudioBlobTx(c, q, blob); err != nil {
				return err
			}
			if err = r.insertRecordingAudioIntentTx(c, q, key, result, request.Title, nil); err != nil {
				return err
			}
			now := time.Now().Unix()
			row := store.Recording{ID: request.RecordingID, UserID: request.UserID, MemberID: request.MemberID, Filename: request.RecordingID + ".bin", ContentType: "application/octet-stream", Bytes: result.Bytes, Title: "Recording", Lyrics: []store.RecordingLyric{}, CreatedAt: now, UpdatedAt: now}
			if !validRecording(row) || insertRecording(c, q, row) != nil {
				return store.ErrRecordingState
			}
			changed, e := q.ExecContext(c, "UPDATE karaoke_users SET used_bytes=used_bytes+?,updated_at=? WHERE user_id=? AND used_bytes=?", result.Bytes, now, user.ID, user.Used)
			if e != nil {
				return e
			}
			if n, e := changed.RowsAffected(); e != nil || n != 1 {
				return store.ErrRecordingState
			}
		}
		capacity := OpaqueCapacityIntent{OperationID: result.OperationID, MasterID: result.MasterID, MemberID: result.MemberID, BlobID: result.BlobID, Digest: result.Digest, Bytes: result.Bytes}
		index := opaqueCapacityIndex(key, capacity.OperationID)
		encID, sealed, err := sealOpaqueCapacity(key, index, capacity)
		if err != nil {
			return err
		}
		prior, err := r.reserveOpaqueCapacityTx(c, q, key, capacity, localFree, func(queryer, store.NodeIdentity) error { return nil }, index, encID, sealed, false)
		if err != nil || prior != found {
			return errors.Join(err, store.ErrRecordingState)
		}
		if !found {
			audit.UserID, audit.Action, audit.Result = request.UserID, "recording-reserve", "success"
			audit.Detail = map[string]any{"recording_id": request.RecordingID, "size_bytes": result.Bytes, "storage_member_id": request.MemberID}
			if err = r.karaokeAudit(c, q, audit); err != nil {
				return err
			}
		}
		// The preparation/session may expire or be revoked while the SQL work
		// runs. The trusted caller repeats its authorization against the same
		// transaction immediately before the coordinator commits.
		if err = check(c, q, request); err != nil {
			return err
		}
		already = found
		return c.Err()
	})
	if err != nil {
		return recordingAudioIntent{}, false, err
	}
	return result, already, nil
}
