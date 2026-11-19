package sealedtree

import (
	"context"
	"database/sql"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// MasterLocalDeletePrepared is the volume's process-local proof. The
// coordinator supplies a live owner lease and a fresh durable-intent check.
type MasterLocalDeletePrepared interface {
	Close() error
	Delete(context.Context, store.OwnerControlLease, func(context.Context) error) error
}

func validMasterLocalDeleteIntent(r *RevocationIntent) bool {
	return r.LocalDelete && r.SelectedDelete && r.Action == "delete" && lowerHex(r.OperationID, 32) &&
		lowerHex(r.MasterID, 32) && r.OwnerID == r.MasterID && hexID(r.MasterBinding) &&
		r.RelationshipID == "" && hexID(r.RelationshipBinding) && hexID(r.Alias) && hexID(r.BlobID) &&
		r.Alias != r.BlobID && hexID(r.Revision) && r.OwnerPublicKey == "" && r.OwnerSignature == "" &&
		r.DeletionPublicKey == "" && r.DeletionSignature == "" &&
		(r.LocalPublication == "" || hexID(r.LocalPublication) && r.LocalPublication != r.BlobID)
}

func masterLocalDeleteBindings(ctx context.Context, tx treeQuery, p Placement) (string, string, error) {
	master, err := revocationMasterBinding(ctx, tx, p.OwnerID)
	if err != nil || p.State != "active" || p.Encryption == nil || p.Bytes <= 0 {
		return "", "", ErrConflict
	}
	var owner string
	err = tx.QueryRowContext(ctx, `SELECT fence_tag FROM sealed_tree_owner_fence WHERE singleton=1 AND EXISTS (
		SELECT 1 FROM cluster_storage_members WHERE member_id=? AND member_kind='MasterLocal' AND transport='Local'
		AND relationship_id IS NULL AND used_bytes>=?)`, p.OwnerID, p.Bytes).Scan(&owner)
	if err != nil || !hexID(owner) {
		return "", "", ErrConflict
	}
	return master, owner, nil
}

func (s *SQLStore) verifyMasterLocalDeleteIntent(ctx context.Context, tx treeQuery, intent *RevocationIntent, p Placement) error {
	master, owner, err := masterLocalDeleteBindings(ctx, tx, p)
	if err != nil || !validMasterLocalDeleteIntent(intent) || master != intent.MasterBinding || owner != intent.RelationshipBinding {
		return ErrConflict
	}
	if op := intent.LocalPublication; op != "" {
		return s.verifyCompletedNativePublication(ctx, tx, p.ObjectID, p.BlobID, op)
	}
	return nil
}

type masterLocalDeletionView struct {
	entry     Entry
	record    Record
	facts     Facts
	revision  int64
	placement Placement
}

func (s *SQLStore) masterLocalMediaDeletionView(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget) (masterLocalDeletionView, error) {
	var out masterLocalDeletionView
	entry, index, err := s.pathEntryTx(ctx, tx, target.Path)
	if err != nil || entry.ObjectID != target.ResourceID || !((entry.Kind == "audio" && strings.HasPrefix(target.Path, "music/")) ||
		(entry.Kind == "video" && strings.HasPrefix(target.Path, "vido/")) || (entry.Kind == "lyric" && validMasterLocalLyricDeletePath(target.Path))) ||
		strings.Count(target.Path, "/") > 3 {
		return out, ErrConflict
	}
	record, matched, err := s.recordByID(ctx, tx, entry.ObjectID)
	if err != nil || matched != entry || record.ObjectIndex != index {
		return out, ErrInvalid
	}
	placement, err := s.placementFor(ctx, tx, entry, index)
	if err != nil || entry.Kind == "lyric" && placement.NativeObjectID != entry.ObjectID {
		return out, ErrConflict
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, index)
	if err != nil || revision < 1 || facts.InternalPlaceholder || facts.PendingSelectedUpload != nil || facts.HiddenProof != nil || facts.S3Deletion != nil {
		return out, ErrConflict
	}
	return masterLocalDeletionView{entry: entry, record: record, facts: facts, revision: revision, placement: placement}, nil
}

func (s *SQLStore) masterLocalMediaDeleteOperation(id, path string) string {
	return s.listingMAC("selected-master-local-delete-v1", id, path)[:32]
}

// QueueMasterLocalMediaDeletionTx makes the selected object unavailable to new
// public grants and commits the exact operation before any volume mutation.
func (m *CoordinatedMutation) QueueMasterLocalMediaDeletionTx(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget) (store.SelectedMediaDeleteItem, bool, error) {
	return m.queueMasterLocalMediaDeletionTx(ctx, tx, target, nil, nil, store.AdminAudit{})
}

// QueueMasterLocalLyricDeletionTx also detaches the preflight's exact explicit
// associations in the same transaction that blocks new lyric grants.
func (m *CoordinatedMutation) QueueMasterLocalLyricDeletionTx(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget, proof *MasterLocalLyricDeletePreflight, audit store.AdminAudit) (store.SelectedMediaDeleteItem, bool, error) {
	if !validMasterLocalLyricDeletePath(target.Path) {
		return store.SelectedMediaDeleteItem{}, false, ErrInvalid
	}
	return m.queueMasterLocalMediaDeletionTx(ctx, tx, target, proof, nil, audit)
}

func (m *CoordinatedMutation) QueueMasterLocalLyricDeletionAdmittedTx(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget, admission *MasterLocalLyricDeleteAdmission, audit store.AdminAudit) (store.SelectedMediaDeleteItem, bool, error) {
	if !validMasterLocalLyricDeletePath(target.Path) || admission == nil || admission.mutation != m {
		return store.SelectedMediaDeleteItem{}, false, ErrFenceRequired
	}
	return m.queueMasterLocalMediaDeletionTx(ctx, tx, target, nil, admission, audit)
}

func (m *CoordinatedMutation) queueMasterLocalMediaDeletionTx(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget, proof *MasterLocalLyricDeletePreflight, admission *MasterLocalLyricDeleteAdmission, audit store.AdminAudit) (store.SelectedMediaDeleteItem, bool, error) {
	var empty store.SelectedMediaDeleteItem
	if m == nil || ctx == nil || tx == nil || !hexID(target.ResourceID) {
		return empty, false, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || target.ResourceID == s.rootID {
		return empty, false, ErrFenceRequired
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return empty, false, err
	}
	op := s.masterLocalMediaDeleteOperation(target.ResourceID, target.Path)
	if target.OperationID != "" && target.OperationID != op {
		return empty, false, ErrConflict
	}
	item := store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: target, State: store.SelectedMediaDeletePending}
	item.OperationID = op
	if done, err := s.nativeDeleteCompleted(ctx, tx, target.ResourceID, op); err != nil {
		return empty, false, err
	} else if done {
		item.State = store.SelectedMediaDeleteDeleted
		return item, false, nil
	}
	view, err := s.masterLocalMediaDeletionView(ctx, tx, target)
	if err != nil {
		return empty, false, err
	}
	if pending := view.facts.Revocation; pending != nil {
		if !pending.LocalDelete || pending.OperationID != op || s.verifyRevocation(ctx, tx, pending, view.placement) != nil {
			return empty, false, ErrConflict
		}
		return item, false, nil
	}
	if target.OperationID != "" {
		return empty, false, ErrConflict
	}
	if view.entry.Kind == "lyric" {
		if admission != nil {
			proof = admission.proofs[target.ResourceID]
			if admission.mutation != m || proof == nil || proof.store != s || proof.target != target {
				return empty, false, ErrFenceChanged
			}
		} else {
			if err := s.verifyMasterLocalLyricDeletePreflight(ctx, tx, target, proof); err != nil {
				return empty, false, err
			}
		}
	}
	p := view.placement
	master, owner, err := masterLocalDeleteBindings(ctx, tx, p)
	if err != nil {
		return empty, false, err
	}
	revision, err := protocol.OpaquePlacementRevision(p.ReadAlias, p.BlobID, p.SHA256, p.Bytes, p.Encryption)
	if err != nil {
		return empty, false, err
	}
	publication, err := s.completedNativePublicationOperation(ctx, tx, p.ObjectID, p.BlobID)
	if err != nil {
		return empty, false, err
	}
	intent := RevocationIntent{OperationID: op, MasterID: p.OwnerID, MasterBinding: master, OwnerID: p.OwnerID, RelationshipBinding: owner,
		Alias: p.ReadAlias, BlobID: p.BlobID, Revision: revision, Action: "delete", SelectedDelete: true, LocalDelete: true, LocalPublication: publication}
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return empty, false, err
	}
	if view.entry.Kind == "lyric" {
		if err = s.detachMasterLocalLyricReferencesTx(ctx, tx, target, op, proof, audit); err != nil {
			return empty, false, err
		}
	}
	if err = s.writeRevocationTx(ctx, tx, view.entry, view.record, view.facts, view.revision, intent); err != nil {
		return empty, false, err
	}
	return item, true, nil
}

func (s *SQLStore) pendingMasterLocalMediaDeletion(ctx context.Context, tx treeQuery, item store.SelectedMediaDeleteItem) (masterLocalDeletionView, bool, error) {
	var empty masterLocalDeletionView
	if !hexID(item.ResourceID) || item.ResourceID == s.rootID || item.State != store.SelectedMediaDeletePending ||
		item.OperationID != s.masterLocalMediaDeleteOperation(item.ResourceID, item.Path) {
		return empty, false, ErrInvalid
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return empty, false, err
	}
	if done, err := s.nativeDeleteCompleted(ctx, tx, item.ResourceID, item.OperationID); err != nil || done {
		return empty, done, err
	}
	view, err := s.masterLocalMediaDeletionView(ctx, tx, item.SelectedMediaDeleteTarget)
	if err != nil {
		return empty, false, err
	}
	intent := view.facts.Revocation
	if intent == nil || !intent.LocalDelete || intent.OperationID != item.OperationID || s.verifyRevocation(ctx, tx, intent, view.placement) != nil {
		return empty, false, ErrConflict
	}
	return view, false, nil
}

type MasterLocalMediaDeletionSnapshot struct {
	Placement            Placement
	PublicationOperation string
}

// ReadMasterLocalMediaDeletionWithLease reads the committed intent without
// admitting public bytes or acquiring a fresh tree/Owner lease.
func (s *SQLStore) ReadMasterLocalMediaDeletionWithLease(ctx context.Context, lease *TreeLease, item store.SelectedMediaDeleteItem) (MasterLocalMediaDeletionSnapshot, bool, error) {
	var empty MasterLocalMediaDeletionSnapshot
	if !s.valid() || ctx == nil || lease == nil {
		return empty, false, ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return empty, false, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return empty, false, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	view, done, err := s.pendingMasterLocalMediaDeletion(ctx, tx, item)
	if err != nil {
		return empty, false, err
	}
	if err = tx.Commit(); err != nil {
		return empty, false, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return empty, false, err
	}
	if done {
		return empty, true, nil
	}
	return MasterLocalMediaDeletionSnapshot{Placement: view.placement, PublicationOperation: view.facts.Revocation.LocalPublication}, false, nil
}

// ListMasterLocalMediaDeletionsWithLease enumerates already-committed local
// operations only. The worker releases this lease before advancing a row.
func (s *SQLStore) ListMasterLocalMediaDeletionsWithLease(ctx context.Context, lease *TreeLease, after string, limit int) ([]store.SelectedMediaDeleteItem, string, error) {
	rows, next, err := s.listPendingRevocationsWithLease(ctx, lease, after, limit, pendingMasterLocalDeletion)
	if err != nil {
		return nil, "", err
	}
	items := make([]store.SelectedMediaDeleteItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: store.SelectedMediaDeleteTarget{
			Path: row.local, ResourceID: row.ObjectID, OperationID: row.Intent.OperationID,
		}, State: store.SelectedMediaDeletePending})
	}
	return items, next, nil
}

// FinalizeMasterLocalMediaDeletionTx accepts the placement for which the
// trusted coordinator already proved a durable volume unlink. The caller
// settles quota and audit in the same transaction.
func (m *CoordinatedMutation) FinalizeMasterLocalMediaDeletionTx(ctx context.Context, tx treeQuery, item store.SelectedMediaDeleteItem, removed Placement) (DeletedNativeMedia, error) {
	var out DeletedNativeMedia
	if m == nil || ctx == nil || tx == nil {
		return out, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() {
		return out, ErrFenceRequired
	}
	view, done, err := s.pendingMasterLocalMediaDeletion(ctx, tx, item)
	if err != nil || done {
		return DeletedNativeMedia{Already: done}, err
	}
	p := view.placement
	if p.Encryption == nil || removed.Encryption == nil || *p.Encryption != *removed.Encryption {
		return out, ErrConflict
	}
	// The two descriptors have just been compared by value.
	removed.Encryption = p.Encryption
	if p != removed {
		return out, ErrConflict
	}
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return out, err
	}
	if err = s.removeDeletedLeafTx(ctx, tx, view.entry, view.record, view.facts); err != nil {
		return out, err
	}
	index, err := s.revocationReservation(item.OperationID)
	if err != nil {
		return out, err
	}
	if err = deleteExactlyOne(ctx, tx, `DELETE FROM sealed_tree_revocations WHERE operation_index=? AND object_index=?`, index, view.record.ObjectIndex); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, s.listingMAC("native-delete-completed-v1", item.ResourceID, item.OperationID)); err != nil {
		return out, err
	}
	return DeletedNativeMedia{OwnerID: p.OwnerID, Bytes: p.Bytes}, nil
}
