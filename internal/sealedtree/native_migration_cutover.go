package sealedtree

import (
	"context"
	"math"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

const nativeMigrationCutoverTimeout = 5 * time.Second

// NativeMigrationCutover binds a verified unit to the paired native target.
// The coordinator authenticates this admission, its lease and its target
// receipts and settles quotas and task state in the same transaction.
type NativeMigrationCutover struct {
	Unit                                          NativeMigrationUnit
	MasterID, TargetOwnerID, TargetRelationshipID string
}

// NativeMigrationPublication is the target's admitted publication identity.
// It must be returned by a lookup of the exact verified target receipt.
type NativeMigrationPublication struct {
	SourceOperationID, OperationID string
	Binding                        protocol.OpaqueOwnerBinding
}

// CutoverNativeMigrationUnitTx moves only current placement and alias rows.
// publication reads the authenticated per-object receipts inside this SQL
// transaction. It must not do I/O outside the transaction or reenter the tree.
// The caller must roll back on any error, including a late roster mismatch,
// and commit capacity and the durable cutover record in this same transaction.
func (m *CoordinatedMutation) CutoverNativeMigrationUnitTx(ctx context.Context, tx treeQuery, admission NativeMigrationCutover, publication func(context.Context, NativeMigrationObject) (NativeMigrationPublication, error)) (int64, error) {
	expected := admission.Unit
	if m == nil || ctx == nil || tx == nil || publication == nil || !hexID(expected.ParentID) ||
		!hexID(expected.Digest) || expected.TreeGeneration <= 0 || expected.ObjectCount <= 0 ||
		!lowerHex(expected.SourceOwnerID, 32) || !lowerHex(admission.MasterID, 32) ||
		!lowerHex(admission.TargetOwnerID, 32) || !lowerHex(admission.TargetRelationshipID, 32) ||
		admission.MasterID == expected.SourceOwnerID || admission.MasterID == admission.TargetOwnerID || expected.SourceOwnerID == admission.TargetOwnerID {
		return 0, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, nativeMigrationCutoverTimeout)
	defer cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || expected.ParentID == s.rootID {
		return 0, ErrFenceRequired
	}
	if err := s.lockIndexedWriter(ctx, tx); err != nil {
		return 0, err
	}
	var total int64
	var classes [3]bool
	actual, err := s.visitNativeMigrationUnitTx(ctx, tx, expected.ParentID, expected.SourceOwnerID, func(c context.Context, current nativeMigrationPlacement) error {
		object := current.object
		if total > math.MaxInt64-object.Bytes {
			return ErrInvalid
		}
		receipt, err := publication(c, object)
		if err != nil {
			return err
		}
		binding := receipt.Binding
		if !binding.Valid() || binding.MasterID != admission.MasterID || binding.OwnerID != admission.TargetOwnerID ||
			binding.RelationshipID != admission.TargetRelationshipID || binding.Alias == object.ReadAlias || binding.Blob == object.BlobID ||
			binding.Size != object.Bytes || binding.Digest != object.SHA256 || binding.Descriptor != object.Descriptor ||
			!hexID(receipt.OperationID) || receipt.OperationID == binding.Blob || receipt.OperationID == binding.Alias ||
			receipt.OperationID == object.BlobID || receipt.OperationID == object.ReadAlias ||
			receipt.OperationID == object.ObjectID || receipt.OperationID == object.NativeObjectID {
			return ErrConflict
		}
		if err := s.verifyCompletedNativePublication(c, tx, object.ObjectID, object.BlobID, receipt.SourceOperationID); err != nil {
			return err
		}
		if err := s.cutoverNativeMigrationPlacement(c, tx, current, receipt); err != nil {
			return err
		}
		total += object.Bytes
		classes[current.class] = true
		return nil
	})
	if err != nil {
		return 0, err
	}
	if actual.Digest != expected.Digest || actual.ObjectCount != expected.ObjectCount {
		return 0, ErrConflict
	}
	for class, changed := range classes {
		if changed {
			if err := s.listingAdjust(ctx, tx, s.listingClassGroup(expected.ParentID, class), 0); err != nil {
				return 0, err
			}
		}
	}
	return total, ctx.Err()
}

func (s *SQLStore) cutoverNativeMigrationPlacement(ctx context.Context, tx treeQuery, current nativeMigrationPlacement, receipt NativeMigrationPublication) error {
	if current.revision == math.MaxInt64 {
		return ErrConflict
	}
	next := current.placement
	next.OwnerID, next.BlobID, next.ReadAlias = receipt.Binding.OwnerID, receipt.Binding.Blob, receipt.Binding.Alias
	sealed, err := s.tree.SealPlacement(next, current.revision+1)
	if err != nil || sealed.ObjectIndex != current.index {
		return ErrConflict
	}
	encryptionID, err := PlacementEncryptionID(sealed)
	if err != nil {
		return err
	}
	if _, err := reserveID(ctx, tx, encryptionID); err != nil {
		return err
	}
	aliasIndex, err := s.tree.BlobIndex(next.ReadAlias)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?),(?)`, sealed.BlobIndex, aliasIndex); err != nil {
		return ErrConflict
	}
	oldBlob, err := s.tree.BlobIndex(current.placement.BlobID)
	if err != nil {
		return err
	}
	oldAlias, err := s.tree.BlobIndex(current.placement.ReadAlias)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_placements SET blob_index=?,revision=?,encryption_id=?,sealed=? WHERE object_index=? AND blob_index=? AND revision=?`, sealed.BlobIndex, sealed.Revision, encryptionID, sealed.Sealed, sealed.ObjectIndex, oldBlob, current.revision)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrConflict
	}
	result, err = tx.ExecContext(ctx, `DELETE FROM sealed_tree_aliases WHERE alias_index=? AND object_index=?`, oldAlias, sealed.ObjectIndex)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_aliases(alias_index,object_index) VALUES(?,?)`, aliasIndex, sealed.ObjectIndex); err != nil {
		return ErrConflict
	}
	mac := s.completionMAC(receipt.OperationID, sealed.ObjectIndex, sealed.BlobIndex)
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_operation_ids(operation_id,completed,object_index,blob_index,receipt_mac) VALUES(?,1,?,?,?)`, receipt.OperationID, sealed.ObjectIndex, sealed.BlobIndex, mac); err != nil {
		return ErrConflict
	}
	return nil
}
