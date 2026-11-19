package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// RecoveryRecordingPlacement is a trusted Master projection of one settled
// recording. It contains no title, filename, lyrics, credentials, or key.
type RecoveryRecordingPlacement struct {
	RecordingID, UserID, OwnerID, BlobID, SHA256 string
	Bytes                                        int64
	ReadAlias, AliasRevision, Descriptor         string
	UserUsedBytes, UserQuotaBytes                int64
	OwnerUsedBytes, OwnerReservedBytes           int64
	OwnerAllocationBytes                         int64
	Publication                                  protocol.OpaqueCapacityReceipt
	PublicationSignature                         string
}

type RecoveryRecordingInventory struct {
	Recordings int64
	Bytes      int64
}

// VisitRecoveryRecordings walks the entire sealed recording inventory in one
// read-only snapshot while the caller holds its Owner fence and shared tree
// lease. Banned users' recordings still occupy storage and quota. The visitor
// must not reenter the repository or lease, and its records are provisional
// until the method succeeds. This verifies expected state, not Owner bytes.
func (r *Repository) VisitRecoveryRecordings(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, key []byte, nodeVault *vault.Vault, visit func(RecoveryRecordingPlacement) error) (RecoveryRecordingInventory, error) {
	if r == nil || r.backend != "sqlite" || ctx == nil || tree == nil || lease == nil || !validCapacityKey(key) || nodeVault == nil || visit == nil {
		return RecoveryRecordingInventory{}, store.ErrRecordingState
	}
	var result RecoveryRecordingInventory
	err := tree.WithRecordingRecoverySnapshot(ctx, lease, r.db, func(c context.Context, tx *sql.Tx, complete func(context.Context, string, string, string, string) error) error {
		var err error
		result, err = r.visitRecoveryRecordingsTx(c, tx, key, nodeVault, complete, visit)
		return err
	})
	if err != nil {
		return RecoveryRecordingInventory{}, err
	}
	return result, nil
}

func (r *Repository) visitRecoveryRecordingsTx(ctx context.Context, q queryer, key []byte, nodeVault *vault.Vault, complete func(context.Context, string, string, string, string) error, visit func(RecoveryRecordingPlacement) error) (result RecoveryRecordingInventory, err error) {
	master, err := readNode(ctx, q, "")
	if err != nil || master.Role != "Master" || !nodeIDPattern.MatchString(master.ID) || master.PrivateKey == "" || master.CreatedAt <= 0 {
		return result, store.ErrRecordingState
	}
	var unsettled, hasCapacityVerifier bool
	var expectedRows int64
	if err = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM karaoke_recordings WHERE state NOT IN ('ready','deleted')),
		(SELECT COUNT(*) FROM karaoke_recordings), EXISTS(SELECT 1 FROM sealed_tree_capacity_meta)`).Scan(&unsettled, &expectedRows, &hasCapacityVerifier); err != nil || unsettled {
		return result, store.ErrRecordingState
	}
	if hasCapacityVerifier && checkCapacityVerifier(ctx, q, key) != nil {
		return result, store.ErrRecordingState
	}
	if err = checkRecoveryRecordingQuota(ctx, q); err != nil {
		return result, err
	}
	const pageSize = 64
	var seen int64
	after := ""
	for {
		rows, err := q.QueryContext(ctx, `SELECT recording_index FROM sealed_recording_audio WHERE recording_index>? ORDER BY recording_index LIMIT ?`, after, pageSize)
		if err != nil {
			return RecoveryRecordingInventory{}, store.ErrRecordingState
		}
		indices := make([]string, 0, pageSize)
		for rows.Next() {
			var index string
			if err = rows.Scan(&index); err != nil || !nodeHashPattern.MatchString(index) || index <= after {
				_ = rows.Close()
				return RecoveryRecordingInventory{}, store.ErrRecordingState
			}
			after = index
			indices = append(indices, index)
		}
		if rowsErr, closeErr := rows.Err(), rows.Close(); rowsErr != nil || closeErr != nil {
			return RecoveryRecordingInventory{}, store.ErrRecordingState
		}
		for _, index := range indices {
			if seen >= expectedRows {
				return RecoveryRecordingInventory{}, store.ErrRecordingState
			}
			seen++
			intent, err := r.readRecoveryRecordingIntent(ctx, q, key, index)
			if err != nil || intent.MasterID != master.ID {
				return RecoveryRecordingInventory{}, store.ErrRecordingState
			}
			var user, member, state string
			var size int64
			var digest sql.NullString
			if q.QueryRowContext(ctx, `SELECT user_id,storage_member_id,state,size_bytes,sha256 FROM karaoke_recordings WHERE recording_id=?`, intent.RecordingID).Scan(&user, &member, &state, &size, &digest) != nil ||
				user != intent.UserID || member != intent.MemberID || size != intent.Bytes || digest.Valid != (intent.State == "ready" || intent.State == "deleted") || digest.Valid && digest.String != intent.Digest {
				return RecoveryRecordingInventory{}, store.ErrRecordingState
			}
			switch intent.State {
			case "deleted", "cancelled":
				if state != "deleted" || r.checkRecoveryRecordingTerminal(ctx, q, key, intent, complete) != nil {
					return RecoveryRecordingInventory{}, store.ErrRecordingState
				}
			case "ready":
				if state != "ready" || complete(ctx, user, intent.RecordingID, intent.OperationID, intent.BlobID) != nil {
					return RecoveryRecordingInventory{}, store.ErrRecordingState
				}
				item, err := r.recoveryRecordingPlacement(ctx, q, key, nodeVault, intent)
				if err != nil || result.Bytes > math.MaxInt64-item.Bytes {
					return RecoveryRecordingInventory{}, store.ErrRecordingState
				}
				if err = visit(item); err != nil {
					return RecoveryRecordingInventory{}, err
				}
				result.Recordings++
				result.Bytes += item.Bytes
			default:
				return RecoveryRecordingInventory{}, store.ErrRecordingState
			}
		}
		if len(indices) < pageSize {
			break
		}
	}
	if seen != expectedRows {
		return RecoveryRecordingInventory{}, store.ErrRecordingState
	}
	return result, ctx.Err()
}

// The sealed index is the discovery source. Looking only at account-visible
// rows would overlook a pending or orphaned encrypted intent.
func (r *Repository) readRecoveryRecordingIntent(ctx context.Context, q queryer, key []byte, index string) (recordingAudioIntent, error) {
	var zero recordingAudioIntent
	var id string
	var sealed []byte
	if q.QueryRowContext(ctx, `SELECT encryption_id,sealed FROM sealed_recording_audio WHERE recording_index=?`, index).Scan(&id, &sealed) != nil {
		return zero, store.ErrRecordingState
	}
	raw, err := openCapacityRecord(key, index, id, sealed)
	if err != nil {
		return zero, store.ErrRecordingState
	}
	defer clear(raw)
	var discovered recordingAudioIntent
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&discovered) != nil || decoder.Decode(new(any)) != io.EOF || !validRecordingAudioIntent(discovered) || recordingAudioIndex(key, discovered.RecordingID) != index {
		return zero, store.ErrRecordingState
	}
	intent, _, lyrics, found, err := r.readRecordingAudioIntentTx(ctx, q, key, discovered.RecordingID)
	clear(lyrics)
	if err != nil || !found || intent != discovered {
		return zero, store.ErrRecordingState
	}
	return intent, nil
}

func checkRecoveryRecordingQuota(ctx context.Context, q queryer) error {
	var invalid bool
	// The karaoke account counter is exact. The Owner counter may also
	// account for non-recording resources, so only its recording floor applies.
	if q.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM karaoke_users u LEFT JOIN
			(SELECT user_id,SUM(size_bytes) AS total FROM karaoke_recordings WHERE state='ready' GROUP BY user_id) a ON a.user_id=u.user_id
		WHERE u.used_bytes<>COALESCE(a.total,0) OR u.used_bytes<0 OR u.quota_bytes<u.used_bytes
	) OR EXISTS(
		SELECT 1 FROM (SELECT storage_member_id,SUM(size_bytes) AS total FROM karaoke_recordings WHERE state='ready' GROUP BY storage_member_id) a
		LEFT JOIN cluster_storage_members m ON m.member_id=a.storage_member_id
		WHERE m.member_id IS NULL OR m.used_bytes<a.total OR m.reserved_bytes<0 OR m.allocated_bytes<0
	)`).Scan(&invalid) != nil || invalid {
		return store.ErrRecordingState
	}
	return nil
}

func (r *Repository) recoveryRecordingPlacement(ctx context.Context, q queryer, key []byte, nodeVault *vault.Vault, intent recordingAudioIntent) (RecoveryRecordingPlacement, error) {
	var out RecoveryRecordingPlacement
	scope, receipt, err := r.verifyRecordingAudioPublishedTx(ctx, q, key, nodeVault, intent)
	if err != nil {
		return out, err
	}
	claim, err := recordingAudioCleanupClaim(key, intent, scope)
	if err != nil {
		return out, err
	}
	descriptor, err := protocol.IngressMediaDescriptor(intent.Bytes, &intent.Encryption)
	if err != nil {
		return out, store.ErrRecordingState
	}
	revision, err := protocol.OpaquePlacementRevisionFromDescriptor(claim.MediaID, intent.BlobID, intent.Digest, descriptor, intent.Bytes)
	if err != nil {
		return out, store.ErrRecordingState
	}
	out = RecoveryRecordingPlacement{
		RecordingID: intent.RecordingID, UserID: intent.UserID, OwnerID: intent.MemberID,
		BlobID: intent.BlobID, SHA256: intent.Digest, Bytes: intent.Bytes, ReadAlias: claim.MediaID,
		AliasRevision: revision, Descriptor: descriptor, Publication: receipt, PublicationSignature: scope.PublishedSignature,
	}
	var status string
	if q.QueryRowContext(ctx, `SELECT status,used_bytes,quota_bytes FROM karaoke_users WHERE user_id=?`, intent.UserID).Scan(&status, &out.UserUsedBytes, &out.UserQuotaBytes) != nil ||
		status != "active" && status != "banned" || out.UserUsedBytes < intent.Bytes || out.UserQuotaBytes < out.UserUsedBytes {
		return RecoveryRecordingPlacement{}, store.ErrRecordingState
	}
	if q.QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes,allocated_bytes FROM cluster_storage_members WHERE member_id=?`, intent.MemberID).Scan(&out.OwnerUsedBytes, &out.OwnerReservedBytes, &out.OwnerAllocationBytes) != nil ||
		out.OwnerUsedBytes < intent.Bytes || out.OwnerReservedBytes < 0 || out.OwnerAllocationBytes < 0 {
		return RecoveryRecordingPlacement{}, store.ErrRecordingState
	}
	return out, nil
}

func (r *Repository) checkRecoveryRecordingTerminal(ctx context.Context, q queryer, key []byte, intent recordingAudioIntent, complete func(context.Context, string, string, string, string) error) error {
	var marker string
	switch {
	case intent.State == "deleted":
		if complete(ctx, intent.UserID, intent.RecordingID, intent.OperationID, intent.BlobID) != nil {
			return store.ErrRecordingState
		}
		claim, err := r.recordingAudioCleanupClaimTx(ctx, q, key, intent)
		if err != nil {
			return err
		}
		marker, err = recordingAudioCleanupMarker(key, recordingAudioCleanupReceipt(claim))
		if err != nil {
			return err
		}
	case intent.MemberID == intent.MasterID:
		var unfinished bool
		index := opaqueCapacityIndex(key, intent.OperationID)
		if q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sealed_tree_capacity_scopes WHERE operation_index=?)`, index).Scan(&unfinished) != nil || unfinished {
			return store.ErrRecordingState
		}
		capacity := OpaqueCapacityIntent{OperationID: intent.OperationID, MasterID: intent.MasterID, MemberID: intent.MemberID, BlobID: intent.BlobID, Digest: intent.Digest, Bytes: intent.Bytes}
		raw, err := json.Marshal(capacity)
		if err != nil {
			return store.ErrRecordingState
		}
		marker = hex.EncodeToString(capacityMAC(key, "recording-audio-unstarted-expiry-v1", raw))
		clear(raw)
	default:
		scope, _, err := r.readRecordingAudioCleanupScopeTx(ctx, q, key, intent)
		if err != nil || scope.Settled || scope.CompletionBinding != "" || scope.PublishedSignature != "" || scope.CleanupSignature == "" {
			return store.ErrRecordingState
		}
		claim, err := recordingAudioCleanupClaim(key, intent, scope)
		if err != nil {
			return err
		}
		marker, err = recordingAudioCleanupMarker(key, recordingAudioCleanupReceipt(claim))
		if err != nil {
			return err
		}
	}
	if intent.State == "cancelled" {
		var unfinished bool
		if q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sealed_tree_operation_ids WHERE operation_id=?)`, intent.OperationID).Scan(&unfinished) != nil || unfinished {
			return store.ErrRecordingState
		}
	}
	if !capacityIDExists(ctx, q, marker, "") {
		return store.ErrRecordingState
	}
	return nil
}
