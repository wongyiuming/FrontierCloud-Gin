package business

import (
	"context"
	"encoding/json"
	"math"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// finalizeSelectedS3 accepts a provider observation obtained by the trusted
// Master adapter, never a browser-supplied proof. It rechecks all persisted
// part hashes, object metadata, current member configuration, reservation and
// authenticated Admin lease under the same transaction that publishes the tree
// record and settles capacity. A lost commit result is retried by upload ID.
// It performs no network I/O and does not register a product route.
func (r *Repository) finalizeSelectedS3(ctx context.Context, tree *sealedtree.SQLStore, key []byte, uploadID string, observed s3store.Proof, checkAdmin func(context.Context) error) (bool, error) {
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || !nodeIDPattern.MatchString(uploadID) || checkAdmin == nil {
		return false, store.ErrNodeState
	}
	already := false
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		selected, oldSelectedID, found, err := r.selectedIntentAnyTx(c, q, key, uploadID)
		if err != nil || !found || selected.Policy != "S3" || selected.CancelRequested {
			return store.ErrNodeState
		}
		if err = checkAdmin(c); err != nil {
			return err
		}
		if err = r.selectedFinalizePolicyTx(c, q, key, selected); err != nil {
			return err
		}
		capacity := selected.Capacity.capacity()
		intent, found, err := r.readSelectedS3IntentTx(c, q, key, capacity.OperationID)
		if err != nil || !found || intent.UploadID != uploadID || intent.MemberID != capacity.MemberID || intent.BlobID != capacity.BlobID || intent.Bytes != capacity.Bytes || intent.Digest != capacity.Digest || intent.LocationBinding != selected.RelationshipBinding {
			return store.ErrNodeState
		}
		if selected.State == "pending" && (intent.State != "pending" || intent.Phase != "completing") || selected.State == "completed" && (intent.State != "completed" || intent.Phase != "completed") || selected.State != "pending" && selected.State != "completed" {
			return store.ErrNodeState
		}
		encryption := intent.Encryption
		var parts []store.S3Part
		verified := intent.ProviderProof
		if selected.State == "pending" {
			parts, err = r.completeSelectedS3PartsTx(c, q, key, intent)
			if err != nil {
				return err
			}
			upload := store.S3Upload{Reservation: store.UploadReservation{ID: uploadID, MemberID: intent.MemberID, MediaID: intent.ObjectID, ExpectedBytes: intent.Bytes, Encryption: &encryption}, Key: intent.Key, ObjectID: intent.ObjectID, Parts: parts, Proof: store.S3ObjectProof{MetadataFormat: store.S3OpaqueMetadata, MetadataOwner: intent.Owner}}
			verified, err = s3media.VerifySelectedMultipartProof(upload, observed)
			if err != nil {
				return store.ErrNodeState
			}
		} else if !intent.ProofRecorded || observed.Size != verified.Bytes || observed.ETag != verified.ETag || observed.VersionID != verified.VersionID || observed.ChecksumType != "COMPOSITE" || observed.ChecksumSHA256 != verified.CompositeSHA256 || len(observed.Metadata) != 2 || observed.Metadata["fc-format"] != store.S3OpaqueMetadata || observed.Metadata["fc-owner"] != intent.Owner {
			return store.ErrNodeState
		}
		member, err := r.s3Member(c, q, intent.MemberID, r.lock())
		if err != nil {
			return store.ErrNodeState
		}
		location := s3store.Config{Endpoint: member.Location.Endpoint, Region: member.Location.Region, Bucket: member.Location.Bucket, Prefix: member.Location.Prefix, AddressStyle: member.Location.Style}
		placement := sealedtree.S3Placement{Version: 1, ObjectID: intent.ObjectID, MemberID: intent.MemberID, ObjectRevision: 1, Location: location, Proof: verified, Encryption: &encryption}
		if selected.State == "completed" {
			if !intent.ProofRecorded || intent.ProviderProof != verified || m.VerifySelectedS3CompletedTx(c, q, capacity.OperationID, placement) != nil {
				return store.ErrNodeState
			}
			var object, blob, mac string
			if q.QueryRowContext(c, `SELECT object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`, capacity.OperationID).Scan(&object, &blob, &mac) != nil || opaqueledger.CompletionBinding(object, blob, mac) != selected.CompletionBinding {
				return store.ErrNodeState
			}
			already = true
			return nil
		}
		pending, err := m.ReadSelectedFileTx(c, q, capacity.OperationID)
		if err != nil || verifySelectedPendingBinding(key, selected, pending) != nil || pending.ObjectID != intent.ObjectID || pending.Placement.Encryption == nil || *pending.Placement.Encryption != encryption {
			return store.ErrNodeState
		}
		parent, found, err := r.readSelectedParentScope(c, q, key, selected.ParentID, capacity.MemberID)
		if err != nil || !found {
			return store.ErrNodeState
		}
		var parentID string
		if q.QueryRowContext(c, `SELECT encryption_id FROM selected_upload_parent_scopes WHERE parent_index=?`+r.lock(), selectedParentIndex(key, selected.ParentID)).Scan(&parentID) != nil {
			return store.ErrNodeState
		}
		account, oldAccountID, found, err := r.readOpaqueCapacityAccount(c, q, key, capacity.MemberID, r.lock())
		if err != nil || !found || account.Total < capacity.Bytes || account.Revision == math.MaxInt64 || member.Reserved < account.Total || member.Used < 0 || member.Allocation < member.Used || member.Reserved > member.Allocation-member.Used || capacity.Bytes > member.Allocation-member.Used {
			return store.ErrNodeState
		}
		if err = m.FinalizeSelectedS3Tx(c, q, capacity.OperationID, placement, func(_ context.Context, p sealedtree.SelectedPending, _ sealedtree.S3Placement) error {
			return verifySelectedPendingBinding(key, selected, p)
		}); err != nil {
			return err
		}
		var object, blob, mac string
		if q.QueryRowContext(c, `SELECT object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`, capacity.OperationID).Scan(&object, &blob, &mac) != nil {
			return store.ErrNodeState
		}
		completion := opaqueledger.CompletionBinding(object, blob, mac)
		if completion == "" {
			return store.ErrNodeState
		}
		account.Total -= capacity.Bytes
		account.Revision++
		raw, err := json.Marshal(account)
		if err != nil {
			return store.ErrNodeState
		}
		accountID, accountSealed, err := sealCapacityRecord(key, opaqueCapacityMemberIndex(key, capacity.MemberID), raw)
		clear(raw)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(c, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, accountID); err != nil {
			return err
		}
		result, err := q.ExecContext(c, `UPDATE sealed_tree_capacity_accounts SET encryption_id=?,sealed=? WHERE member_index=? AND encryption_id=?`, accountID, accountSealed, opaqueCapacityMemberIndex(key, capacity.MemberID), oldAccountID)
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		result, err = q.ExecContext(c, `UPDATE cluster_storage_members SET used_bytes=used_bytes+?,reserved_bytes=reserved_bytes-? WHERE member_id=? AND used_bytes=? AND reserved_bytes=?`, capacity.Bytes, capacity.Bytes, capacity.MemberID, member.Used, member.Reserved)
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		if parent.Count == 1 {
			if parent.Bytes != capacity.Bytes {
				return store.ErrNodeState
			}
			result, err = q.ExecContext(c, `DELETE FROM selected_upload_parent_scopes WHERE parent_index=? AND encryption_id=?`, selectedParentIndex(key, selected.ParentID), parentID)
			if err != nil {
				return err
			}
			if n, e := result.RowsAffected(); e != nil || n != 1 {
				return store.ErrNodeState
			}
		} else {
			if parent.Count < 2 || parent.Bytes-capacity.Bytes < parent.Count-1 {
				return store.ErrNodeState
			}
			parent.Count--
			parent.Bytes -= capacity.Bytes
			if err = r.writeSelectedParentScope(c, q, key, parent, true); err != nil {
				return err
			}
		}
		finished := intent
		result, err = q.ExecContext(c, `DELETE FROM selected_s3_parts WHERE operation_index=?`, opaqueCapacityIndex(key, capacity.OperationID))
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != int64(len(parts)) {
			return store.ErrNodeState
		}
		finished.State, finished.Phase, finished.Revision, finished.ProviderProof, finished.ProofRecorded = "completed", "completed", intent.Revision+1, verified, true
		if err = r.writeSelectedS3IntentTx(c, q, key, finished, func(_ context.Context, _ queryer, old selectedS3Intent, exists bool) error {
			if !exists || old != intent {
				return store.ErrNodeState
			}
			return nil
		}); err != nil {
			return err
		}
		selected.State, selected.CompletionBinding = "completed", completion
		raw, err = json.Marshal(selected)
		if err != nil {
			return store.ErrNodeState
		}
		id, sealed, err := sealCapacityRecord(key, opaqueCapacityIndex(key, capacity.OperationID), raw)
		clear(raw)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(c, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, id); err != nil {
			return err
		}
		result, err = q.ExecContext(c, `UPDATE selected_upload_intents SET encryption_id=?,sealed=?,state='completed' WHERE operation_index=? AND encryption_id=? AND state='pending'`, id, sealed, opaqueCapacityIndex(key, capacity.OperationID), oldSelectedID)
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		return c.Err()
	})
	return already, err
}
