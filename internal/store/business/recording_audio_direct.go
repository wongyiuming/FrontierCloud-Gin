package business

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const recordingAudioDirectPath = "/api/v1/node/recording-selected-upload"
const recordingAudioDirectDestinationLimit = 64

type RecordingAudioDirectTicket struct {
	RecordingID    string `json:"recording_id"`
	MemberID       string `json:"storage_member_id"`
	Transport      string `json:"transport"`
	State          string `json:"state"`
	URL            string `json:"url,omitempty"`
	RetryUploadURL string `json:"retry_upload_url,omitempty"`
	Capability     string `json:"capability,omitempty"`
	ExpiresAt      int64  `json:"expires_at,omitempty"`
}

type RecordingAudioDirectDestination struct {
	MemberID       string `json:"member_id"`
	Address        string `json:"address"`
	Transport      string `json:"transport"`
	AvailableBytes int64  `json:"available_bytes"`
}

// RecordingAudioDirectSource contains a short-lived grant issued after account
// authorization. Callers return only the browser's required playback fields.
type RecordingAudioDirectSource struct {
	RecordingID, MemberID, ResourceOrigin, BlobID, CipherSHA256 string
	ContentType, Title, ReadAlias, Capability                   string
	Size, ExpiresAt                                             int64
	Encryption                                                  mediacrypto.Metadata
}

type recordingAudioDirectOwner struct {
	member  store.StorageMember
	policy  store.NativeTransportPolicy
	binding string
}

func (s *SelectedUploadRuntime) recordingAudioDirectOwner(ctx context.Context, q queryer, master store.NodeIdentity, ingress store.PublicIngress, memberID string) (recordingAudioDirectOwner, error) {
	var owner recordingAudioDirectOwner
	if master.ID == memberID || !nodeIDPattern.MatchString(memberID) {
		return owner, store.ErrStorageCapacity
	}
	member, err := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+s.repo.lock(), memberID))
	if err != nil || member.Kind != "Follower" || member.RelationshipID == nil {
		return owner, store.ErrStorageCapacity
	}
	draining, err := s.repo.migrationDraining(ctx, q, memberID)
	if err != nil || draining {
		return owner, store.ErrStorageCapacity
	}
	binding, err := s.repo.recordingAudioOwnerBinding(ctx, q, s.key, master, memberID)
	if err != nil {
		return owner, err
	}
	policy, err := s.repo.nativeTransport(ctx, q, master, ingress, memberID, s.repo.lock())
	if err != nil || policy.ConfiguredTransport != "Direct" || policy.AppliedTransport != "Direct" ||
		policy.Revision < 1 || !validSelectedTransport("Direct", policy.AppliedOrigin) ||
		(policy.State != "applied" && !(ingress.NodeID == memberID && policy.State == "retained")) {
		return owner, store.ErrStorageCapacity
	}
	if policy.State == "retained" {
		relation, err := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+s.repo.lock(), *member.RelationshipID))
		if err != nil {
			return owner, store.ErrStorageCapacity
		}
		raw, err := json.Marshal(relation.Summary[nativeTransportReceiptKey])
		var receipt nativeTransportReceipt
		if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Revision != policy.Revision || receipt.Transport != "Direct" || receipt.Origin != policy.AppliedOrigin || relation.Summary["native_resource_origin"] != receipt.Origin {
			return owner, store.ErrStorageCapacity
		}
	}
	return recordingAudioDirectOwner{member: member, policy: policy, binding: binding}, nil
}

func (s *SelectedUploadRuntime) recordingAudioDirectLease(ctx context.Context, tree *sealedtree.SQLStore) (SelectedUploadRuntimeLease, error) {
	if s == nil || ctx == nil || s.repo == nil || tree == nil || tree != s.tree || s.crypto == nil ||
		s.vault == nil || selectedNil(s.gate) {
		return nil, store.ErrRecordingState
	}
	lease, err := s.gate.AcquireSelectedUpload(ctx, tree)
	if err != nil || selectedNil(lease) {
		return nil, store.ErrNodeState
	}
	if lease.Check(ctx) != nil {
		lease.Release()
		return nil, store.ErrNodeState
	}
	return lease, nil
}

// RecordingAudioDirectDestinations lists eligible Owners for the authenticated
// account page. This is only a read snapshot. Ticket admission rechecks the
// actual member, current policy and requested byte count under its write fence.
func (s *SelectedUploadRuntime) RecordingAudioDirectDestinations(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress) ([]RecordingAudioDirectDestination, error) {
	lease, err := s.recordingAudioDirectLease(ctx, tree)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	tx, err := s.repo.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	master, err := s.checkRecordingAudioIngressTx(ctx, tx, expected)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT member_id FROM cluster_storage_members WHERE member_kind='Follower' AND storage_enabled=1 AND writable=1 AND health='online' ORDER BY member_id LIMIT ?", recordingAudioDirectDestinationLimit+1)
	if err != nil {
		return nil, err
	}
	var members []string
	for rows.Next() {
		var member string
		if err = rows.Scan(&member); err != nil {
			rows.Close()
			return nil, err
		}
		members = append(members, member)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(members) > recordingAudioDirectDestinationLimit {
		return nil, store.ErrNodeState
	}
	result := make([]RecordingAudioDirectDestination, 0, len(members))
	for _, id := range members {
		owner, err := s.recordingAudioDirectOwner(ctx, tx, master, expected, id)
		if err != nil {
			continue
		}
		if available := capacity(owner.member); available > 0 {
			result = append(result, RecordingAudioDirectDestination{MemberID: id, Address: owner.policy.AppliedOrigin,
				Transport: "Direct", AvailableBytes: available})
		}
	}
	if lease.Check(ctx) != nil {
		return nil, store.ErrNodeState
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// AdmitRecordingAudioDirect reserves the exact encrypted recording and issues
// a short-lived Owner grant. A failure after reservation keeps the operation
// recoverable. The account callback must authenticate the live session and
// CSRF outside SQL locks, under the caller's account revocation authority.
func (s *SelectedUploadRuntime) AdmitRecordingAudioDirect(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser string, request store.RecordingAudioTicketRequest, audit store.KaraokeAudit, checkAccount func(context.Context) error) (RecordingAudioDirectTicket, error) {
	var empty RecordingAudioDirectTicket
	if ctx == nil || checkAccount == nil || !request.Valid() || checkAccount(ctx) != nil {
		return empty, store.ErrRecordingState
	}
	lease, err := s.recordingAudioDirectLease(ctx, tree)
	if err != nil {
		return empty, err
	}
	defer lease.Release()
	binding, err := store.RecordingAudioPreparationBinding(user.ID, browser, request.RecordingID)
	if err != nil {
		return empty, err
	}
	in := recordingAudioAdmission{UserID: user.ID, RecordingID: request.RecordingID, MemberID: request.MemberID,
		Digest: request.CipherSHA256, Binding: binding, Title: request.Title, ContentType: request.ContentType, Encryption: request.Encryption}
	_, _, err = s.repo.reserveRecordingAudioCoordinated(ctx, tree, s.key, in, 0, audit, func(c context.Context, q queryer, pending recordingAudioAdmission) error {
		if lease.Check(c) != nil {
			return store.ErrNodeState
		}
		master, e := s.checkRecordingAudioSessionTx(c, q, expected, user, browser, request.SessionID)
		if e != nil {
			return e
		}
		if _, e = s.recordingAudioDirectOwner(c, q, master, expected, pending.MemberID); e != nil {
			return e
		}
		return s.crypto.VerifyTransientPreparation(binding, request.PreparationToken, pending.Encryption)
	})
	if err != nil {
		return empty, err
	}
	if checkAccount(ctx) != nil {
		return empty, store.ErrRecordingState
	}
	return s.issueRecordingAudioDirect(ctx, expected, user, browser, request.SessionID, request.RecordingID, binding, false, lease, checkAccount)
}

func (s *SelectedUploadRuntime) checkRecordingAudioDirectIntent(c context.Context, q queryer, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID string, intent recordingAudioIntent, lease SelectedUploadRuntimeLease) (recordingAudioDirectOwner, error) {
	var empty recordingAudioDirectOwner
	if lease.Check(c) != nil || intent.UserID != user.ID {
		return empty, store.ErrRecordingState
	}
	master, err := s.checkRecordingAudioSessionTx(c, q, expected, user, browser, sessionID)
	if err != nil {
		return empty, err
	}
	if master.ID != intent.MasterID {
		return empty, store.ErrNodeState
	}
	owner, err := s.recordingAudioDirectOwner(c, q, master, expected, intent.MemberID)
	if err != nil {
		return empty, err
	}
	if owner.binding != intent.OwnerBinding {
		return empty, store.ErrNodeState
	}
	return owner, nil
}

func recordingAudioDirectAlias(key []byte, operationID string) string {
	return hex.EncodeToString(capacityMAC(key, "recording-audio-direct-alias-v1", []byte(operationID)))
}

func (s *SelectedUploadRuntime) issueRecordingAudioDirect(ctx context.Context, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID, recordingID, binding string, recoverExisting bool, lease SelectedUploadRuntimeLease, checkAccount func(context.Context) error) (RecordingAudioDirectTicket, error) {
	var ticket RecordingAudioDirectTicket
	var owner recordingAudioDirectOwner
	_, _, err := s.repo.bindRecordingAudioScopeChecked(ctx, s.tree, s.key, user.ID, recordingID, false, func(c context.Context, q queryer, intent recordingAudioIntent) error {
		if binding != "" && intent.Binding != binding {
			return store.ErrRecordingState
		}
		var err error
		owner, err = s.checkRecordingAudioDirectIntent(c, q, expected, user, browser, sessionID, intent, lease)
		return err
	}, func(c context.Context, q queryer, intent recordingAudioIntent, scope OpaqueCapacityScope) error {
		if owner.member.RelationshipID == nil || *owner.member.RelationshipID != scope.RelationshipID {
			return store.ErrNodeState
		}
		relation, err := scanRelation(q.QueryRowContext(c, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+s.repo.lock(), scope.RelationshipID))
		if err != nil || relation.PeerID != intent.MemberID {
			return store.ErrNodeState
		}
		credential, err := s.vault.Unseal(relation.Credential)
		if err != nil {
			return store.ErrNodeState
		}
		_, _, sessionExpiry, valid := mediacrypto.DirectSessionFromContext(c).Values()
		now := time.Now().Unix()
		if !valid || sessionExpiry <= now {
			return store.ErrRecordingState
		}
		alias := recordingAudioDirectAlias(s.key, intent.OperationID)
		association, err := json.Marshal([4]string{user.ID, browser, sessionID, intent.OperationID})
		if err != nil {
			return err
		}
		defer clear(association)
		claim := protocol.SelectedStorageUpload{
			Relationship: relation.ID, Master: intent.MasterID, Owner: intent.MemberID, MediaID: alias,
			ObjectID: intent.BlobID, UploadID: intent.RecordingID, OperationID: intent.OperationID,
			ContentSHA256: intent.Digest, Size: intent.Bytes, Policy: "Direct", Revision: owner.policy.Revision,
			ResourceOrigin: owner.policy.AppliedOrigin, AdminOrigin: expected.PublicOrigin,
			AdminBinding:         hex.EncodeToString(capacityMAC(s.key, "recording-audio-direct-session-v1", association)),
			RecordingIngressNode: expected.NodeID, RecordingIngressGeneration: expected.Generation,
			RelationshipBinding: scope.RelationshipBinding, Generation: scope.Generation, StageID: scope.StageID,
			PublishChallenge: scope.PublishChallenge, CleanupChallenge: scope.CleanupChallenge,
			ExpiresAt: min(now+protocol.TokenSeconds, sessionExpiry), Encryption: &intent.Encryption,
		}
		capability, err := protocol.SignSelectedRecordingUpload(credential, claim, now)
		if err != nil {
			return err
		}
		url := owner.policy.AppliedOrigin + recordingAudioDirectPath
		ticket = RecordingAudioDirectTicket{RecordingID: recordingID, MemberID: intent.MemberID, Transport: "Direct",
			State: "pending", URL: url, Capability: capability, ExpiresAt: claim.ExpiresAt}
		if recoverExisting {
			ticket.URL = url + "/recover"
			ticket.RetryUploadURL = url
		}
		return c.Err()
	})
	if err != nil {
		return RecordingAudioDirectTicket{}, err
	}
	if lease.Check(ctx) != nil || checkAccount(ctx) != nil {
		return RecordingAudioDirectTicket{}, store.ErrRecordingState
	}
	return ticket, nil
}

// RecoverRecordingAudioDirect reauthorizes the same recording and same Owner
// from the current account session. A reissued ticket never reserves capacity
// again. The retry upload URL accepts only the identical ciphertext and only
// if the Owner has no existing stage, enforced by its exclusive creation.
func (s *SelectedUploadRuntime) RecoverRecordingAudioDirect(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID, recordingID string, checkAccount func(context.Context) error) (RecordingAudioDirectTicket, error) {
	var empty RecordingAudioDirectTicket
	if ctx == nil || checkAccount == nil || !nodeIDPattern.MatchString(recordingID) || checkAccount(ctx) != nil {
		return empty, store.ErrRecordingState
	}
	lease, err := s.recordingAudioDirectLease(ctx, tree)
	if err != nil {
		return empty, err
	}
	defer lease.Release()
	var intent recordingAudioIntent
	ready, err := s.recordingAudioReadyChecked(ctx, user.ID, recordingID, &intent, nil, false, func(c context.Context, q queryer, item recordingAudioIntent) error {
		_, e := s.checkRecordingAudioDirectIntent(c, q, expected, user, browser, sessionID, item, lease)
		return e
	}, nil)
	if err != nil {
		return empty, err
	}
	if lease.Check(ctx) != nil || checkAccount(ctx) != nil {
		return empty, store.ErrRecordingState
	}
	if ready {
		return RecordingAudioDirectTicket{RecordingID: recordingID, MemberID: intent.MemberID, Transport: "Direct", State: "ready"}, nil
	}
	return s.issueRecordingAudioDirect(ctx, expected, user, browser, sessionID, recordingID, "", true, lease, checkAccount)
}

// CompleteRecordingAudioDirect settles the original reservation only after the
// current account is authorized and the exact signed Owner receipt verifies.
func (s *SelectedUploadRuntime) CompleteRecordingAudioDirect(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID, recordingID string, receipt protocol.OpaqueCapacityReceipt, signature string, audit store.KaraokeAudit, checkAccount func(context.Context) error) (bool, error) {
	if ctx == nil || checkAccount == nil || !nodeIDPattern.MatchString(recordingID) || checkAccount(ctx) != nil {
		return false, store.ErrRecordingState
	}
	lease, err := s.recordingAudioDirectLease(ctx, tree)
	if err != nil {
		return false, err
	}
	defer lease.Release()
	already, err := s.repo.finalizeRecordingAudio(ctx, tree, s.key, s.vault, user.ID, recordingID, receipt, signature, audit,
		func(c context.Context, q queryer, intent recordingAudioIntent) error {
			_, e := s.checkRecordingAudioDirectIntent(c, q, expected, user, browser, sessionID, intent, lease)
			return e
		})
	if err != nil {
		return false, err
	}
	if lease.Check(ctx) != nil || checkAccount(ctx) != nil {
		return false, store.ErrRecordingState
	}
	return already, nil
}

// LookupRecordingAudioDirect issues a bounded Owner read grant only after the
// current account and the durable recording completion have been verified.
func (s *SelectedUploadRuntime) LookupRecordingAudioDirect(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID, recordingID string, checkAccount func(context.Context) error) (RecordingAudioDirectSource, error) {
	var empty RecordingAudioDirectSource
	if ctx == nil || checkAccount == nil || !nodeIDPattern.MatchString(recordingID) || checkAccount(ctx) != nil {
		return empty, store.ErrRecordingState
	}
	lease, err := s.recordingAudioDirectLease(ctx, tree)
	if err != nil {
		return empty, err
	}
	defer lease.Release()
	var intent recordingAudioIntent
	var owner recordingAudioDirectOwner
	var title, alias, capability string
	var expiresAt int64
	ready, err := s.recordingAudioReadyChecked(ctx, user.ID, recordingID, &intent, &title, false, func(c context.Context, q queryer, item recordingAudioIntent) error {
		var e error
		owner, e = s.checkRecordingAudioDirectIntent(c, q, expected, user, browser, sessionID, item, lease)
		return e
	}, func(c context.Context, q queryer, item recordingAudioIntent) error {
		if owner.member.RelationshipID == nil {
			return store.ErrNodeState
		}
		relation, e := scanRelation(q.QueryRowContext(c, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+s.repo.lock(), *owner.member.RelationshipID))
		if e != nil || relation.PeerID != item.MemberID {
			return store.ErrNodeState
		}
		credential, e := s.vault.Unseal(relation.Credential)
		if e != nil {
			return store.ErrNodeState
		}
		_, _, sessionExpiry, valid := mediacrypto.DirectSessionFromContext(c).Values()
		now := time.Now().Unix()
		if !valid || sessionExpiry <= now {
			return store.ErrRecordingState
		}
		alias = recordingAudioDirectAlias(s.key, item.OperationID)
		expiresAt = min(sessionExpiry, now+protocol.TokenSeconds)
		capability, e = protocol.OpaqueIngressMediaToken(credential, relation.ID, item.MasterID, item.MemberID,
			alias, expected.NodeID, expected.PublicOrigin, sessionID, item.BlobID, expected.Generation,
			now, expiresAt, item.Bytes, item.Digest, &item.Encryption)
		return e
	})
	if err != nil {
		return empty, err
	}
	if !ready || lease.Check(ctx) != nil || checkAccount(ctx) != nil {
		return empty, store.ErrRecordingState
	}
	return RecordingAudioDirectSource{RecordingID: recordingID, MemberID: intent.MemberID, ResourceOrigin: owner.policy.AppliedOrigin,
		BlobID: intent.BlobID, CipherSHA256: intent.Digest, ContentType: intent.ContentType, Title: title,
		Size: intent.Bytes, Encryption: intent.Encryption, ReadAlias: alias, Capability: capability, ExpiresAt: expiresAt}, nil
}
