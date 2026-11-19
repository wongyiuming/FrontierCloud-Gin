package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ErrSelectedS3RecoveryRequired keeps S3 closed until authenticated pending
// operations are reconciled. It does not mean that provider data is absent.
var ErrSelectedS3RecoveryRequired = errors.New("selected S3 recovery required")

// CheckSelectedS3Startup authenticates the local journal and tree under the
// existing Owner -> ingress -> tree -> SQLite transaction. It does no provider
// I/O and does not confer readiness or recreate origin/probe proofs. A pending
// operation, including an uncertain create, blocks ordinary S3 startup.
func (r *Repository) CheckSelectedS3Startup(ctx context.Context, tree *sealedtree.SQLStore, key []byte) error {
	_, err := r.checkSelectedS3Startup(ctx, tree, key, "")
	return err
}

// CheckSelectedS3RecoveryMember authorizes only a member with an actual,
// fully authenticated pending operation. Caller holds the recovery gate.
func (r *Repository) CheckSelectedS3RecoveryMember(ctx context.Context, tree *sealedtree.SQLStore, key []byte, memberID string) error {
	if !nodeIDPattern.MatchString(memberID) {
		return store.ErrNodeState
	}
	matched, err := r.checkSelectedS3Startup(ctx, tree, key, memberID)
	if err != ErrSelectedS3RecoveryRequired || !matched {
		return store.ErrNodeState
	}
	return nil
}

func (r *Repository) checkSelectedS3Startup(ctx context.Context, tree *sealedtree.SQLStore, key []byte, memberID string) (bool, error) {
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) {
		return false, store.ErrNodeState
	}
	needsRecovery := false
	matchedMember := false
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if checkCapacityVerifier(c, q, key) != nil {
			return store.ErrNodeState
		}
		identity, err := readNode(c, q, r.lock())
		if err != nil || identity.Role != "Master" {
			return store.ErrNodeState
		}
		// Missing counterparts cannot be treated as an empty journal.
		for _, query := range []string{
			`SELECT s.operation_index FROM selected_s3_uploads s LEFT JOIN selected_upload_intents i ON i.operation_index=s.operation_index WHERE i.operation_index IS NULL LIMIT 1`,
			`SELECT p.operation_index FROM selected_s3_parts p LEFT JOIN selected_s3_uploads s ON s.operation_index=p.operation_index WHERE s.operation_index IS NULL LIMIT 1`,
		} {
			var orphan string
			if e := q.QueryRowContext(c, query).Scan(&orphan); !errors.Is(e, sql.ErrNoRows) {
				return store.ErrNodeState
			}
		}
		pendingBytes := make(map[string]int64)
		completedBytes := make(map[string]int64)
		type parentTotals struct {
			member       string
			count, bytes int64
		}
		parents := make(map[string]parentTotals)
		after := ""
		for {
			rows, e := q.QueryContext(c, `SELECT operation_index,encryption_id,sealed FROM selected_upload_intents WHERE operation_index>? ORDER BY operation_index LIMIT 32`, after)
			if e != nil {
				return e
			}
			type row struct {
				index, id string
				sealed    []byte
			}
			var batch []row
			for rows.Next() {
				var v row
				if e = rows.Scan(&v.index, &v.id, &v.sealed); e != nil {
					break
				}
				batch = append(batch, v)
			}
			if e == nil {
				e = rows.Err()
			}
			rows.Close()
			if e != nil {
				return e
			}
			if len(batch) == 0 {
				break
			}
			for _, v := range batch {
				if c.Err() != nil || v.index <= after || !capacityIDExists(c, q, v.id, r.lock()) {
					return store.ErrNodeState
				}
				after = v.index
				raw, e := openCapacityRecord(key, v.index, v.id, v.sealed)
				if e != nil {
					return store.ErrNodeState
				}
				var hint struct {
					UploadID string `json:"u"`
				}
				e = json.Unmarshal(raw, &hint)
				clear(raw)
				selected, _, found, verifyErr := r.selectedIntentAnyTx(c, q, key, hint.UploadID)
				if e != nil || verifyErr != nil || !found || opaqueCapacityIndex(key, selected.Capacity.OperationID) != v.index {
					return store.ErrNodeState
				}
				var journalCount int
				if q.QueryRowContext(c, `SELECT COUNT(*) FROM selected_s3_uploads WHERE operation_index=?`, v.index).Scan(&journalCount) != nil {
					return store.ErrNodeState
				}
				if selected.Policy != "S3" {
					if journalCount != 0 {
						return store.ErrNodeState
					}
					continue
				}
				intent, found, e := r.readSelectedS3IntentTx(c, q, key, selected.Capacity.OperationID)
				capacity := selected.Capacity.capacity()
				if e != nil || !found || journalCount != 1 || intent.UploadID != selected.UploadID || intent.MemberID != capacity.MemberID || intent.BlobID != capacity.BlobID || intent.Bytes != capacity.Bytes || intent.Digest != capacity.Digest || intent.LocationBinding != selected.RelationshipBinding || capacity.MasterID != identity.ID || selected.MasterBinding != capacityMasterBinding(identity) || intent.State != selected.State {
					return store.ErrNodeState
				}
				var capMember, capBlob, capID string
				var capSealed []byte
				if q.QueryRowContext(c, `SELECT member_index,blob_index,encryption_id,sealed FROM sealed_tree_capacity_intents WHERE operation_index=?`, v.index).Scan(&capMember, &capBlob, &capID, &capSealed) != nil || capMember != opaqueCapacityMemberIndex(key, capacity.MemberID) || capBlob != opaqueCapacityBlobIndex(key, capacity.BlobID) || !capacityIDExists(c, q, capID, r.lock()) {
					return store.ErrNodeState
				}
				recorded, e := openOpaqueCapacity(key, v.index, capID, capSealed)
				if e != nil || recorded != capacity {
					return store.ErrNodeState
				}
				member, e := r.s3Member(c, q, intent.MemberID, r.lock())
				if e != nil || member.Kind != "S3" || member.Transport != "S3" || member.RelationshipID != nil {
					return store.ErrNodeState
				}
				switch selected.State {
				case "pending":
					if intent.MemberID == memberID {
						binding, bindingErr := selectedS3MemberIdentityBinding(key, member)
						if bindingErr != nil || binding != intent.LocationBinding || member.Revision != selected.Revision || member.CredentialRevision != intent.CredentialRevision || member.Enabled == 0 || member.Draining || member.CleanupOnly || member.CredentialExpiresAt != 0 && member.CredentialExpiresAt <= time.Now().Unix() {
							return store.ErrNodeState
						}
						matchedMember = true
					}
					pending, e := m.ReadSelectedFileTx(c, q, intent.OperationID)
					if e != nil || verifySelectedPendingBinding(key, selected, pending) != nil || pending.ObjectID != intent.ObjectID || pending.Placement.Encryption == nil || *pending.Placement.Encryption != intent.Encryption {
						return store.ErrNodeState
					}
					if _, exists, e := r.readSelectedParentScope(c, q, key, selected.ParentID, capacity.MemberID); e != nil || !exists {
						return store.ErrNodeState
					}
					parts, partErr := r.listSelectedS3PartsTx(c, q, key, intent, false)
					hashes := make([]string, len(parts))
					for i, part := range parts {
						hashes[i] = part.SHA256
					}
					commitment, commitmentErr := selectedS3Commitment(intent.Bytes, hashes)
					if partErr != nil || commitmentErr != nil || commitment != intent.PartCommitment || pendingBytes[intent.MemberID] > math.MaxInt64-intent.Bytes {
						return store.ErrNodeState
					}
					pendingBytes[intent.MemberID] += intent.Bytes
					total := parents[selected.ParentID]
					if total.member != "" && total.member != intent.MemberID || total.count == math.MaxInt64 || total.bytes > math.MaxInt64-intent.Bytes {
						return store.ErrNodeState
					}
					total.member, total.count, total.bytes = intent.MemberID, total.count+1, total.bytes+intent.Bytes
					parents[selected.ParentID] = total
					needsRecovery = true
				case "completed":
					var object, blob, mac string
					if !intent.ProofRecorded || q.QueryRowContext(c, `SELECT object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`, intent.OperationID).Scan(&object, &blob, &mac) != nil || opaqueledger.CompletionBinding(object, blob, mac) != selected.CompletionBinding {
						return store.ErrNodeState
					}
					deleted, e := m.S3PublicationDeletionRecordedTx(c, q, intent.ObjectID, intent.UploadID)
					if e != nil {
						return store.ErrNodeState
					}
					if !deleted {
						placement, e := m.ReadSelectedS3CompletedTx(c, q, intent.OperationID, intent.ObjectID, intent.BlobID)
						if e != nil || placement.MemberID != intent.MemberID || placement.Proof != intent.ProviderProof || placement.Encryption == nil || *placement.Encryption != intent.Encryption || completedBytes[intent.MemberID] > math.MaxInt64-intent.Bytes {
							return store.ErrNodeState
						}
						completedBytes[intent.MemberID] += intent.Bytes
					}
				case "cancelled":
					cancelled, e := m.IsSelectedCancelledTx(c, q, intent.OperationID)
					if e != nil || !cancelled || !selected.CancelRequested || intent.CancellationBinding != selected.CompletionBinding {
						return store.ErrNodeState
					}
				default:
					return store.ErrNodeState
				}
				if selected.State != "pending" {
					var parts int
					if q.QueryRowContext(c, `SELECT COUNT(*) FROM selected_s3_parts WHERE operation_index=?`, v.index).Scan(&parts) != nil || parts != 0 {
						return store.ErrNodeState
					}
				}
			}
		}
		for parent, total := range parents {
			scope, exists, e := r.readSelectedParentScope(c, q, key, parent, total.member)
			if e != nil || !exists || scope.Count != total.count || scope.Bytes != total.bytes {
				return store.ErrNodeState
			}
		}
		rows, err := q.QueryContext(c, `SELECT member_id FROM s3_members ORDER BY member_id`)
		if err != nil {
			return err
		}
		var members []string
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				break
			}
			members = append(members, id)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		for _, id := range members {
			member, e := r.s3Member(c, q, id, r.lock())
			account, _, found, accountErr := r.readOpaqueCapacityAccount(c, q, key, id, r.lock())
			if e != nil || accountErr != nil || member.Reserved != pendingBytes[id] || account.Total != pendingBytes[id] || pendingBytes[id] != 0 && !found || member.Used != completedBytes[id] {
				return store.ErrNodeState
			}
		}
		return c.Err()
	})
	if err != nil {
		return false, err
	}
	if needsRecovery {
		return matchedMember, ErrSelectedS3RecoveryRequired
	}
	return false, nil
}
