package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const DirectoryDeleteLeafLimit = 200
const directoryDeleteEntriesLimit = 4096

var ErrDirectoryDeleteLimit = errors.New("directory deletion exceeds the supported subtree limit")
var ErrDirectoryDeleteUploadPending = errors.New("directory contains a pending upload")

type DirectoryDeleteIntent struct {
	OperationID string `json:"operation_id"`
}

// DirectoryDeletePreflight is a complete bounded snapshot, not permission to
// delete. It carries exact leaf selectors in memory only.
type DirectoryDeletePreflight struct {
	store      *SQLStore
	fence      *TreeFence
	generation int64
	target     store.SelectedMediaDeleteTarget
	leaves     []store.SelectedMediaDeleteTarget
}

func (p *DirectoryDeletePreflight) Leaves() []store.SelectedMediaDeleteTarget {
	if p == nil {
		return nil
	}
	return append([]store.SelectedMediaDeleteTarget(nil), p.leaves...)
}

type DirectoryDeleteAdmission struct {
	mutation *CoordinatedMutation
	plans    map[string]*DirectoryDeletePreflight
}

func validDirectoryDeleteTarget(target store.SelectedMediaDeleteTarget) bool {
	if !target.Directory || !hexID(target.ResourceID) || !factPath(target.Path) || target.OperationID != "" && !lowerHex(target.OperationID, 32) {
		return false
	}
	parts := strings.Split(target.Path, "/")
	if len(parts) < 2 || len(parts) > 3 || (parts[0] != "music" && parts[0] != "vido" && parts[0] != "lyrics") {
		return false
	}
	for _, part := range parts {
		if !validComponent(part) || strings.HasPrefix(part, ".") || strings.Contains(part, ":") {
			return false
		}
	}
	return true
}

func (s *SQLStore) directoryDeleteOperation(target store.SelectedMediaDeleteTarget) string {
	return s.listingMAC("directory-delete-request-v1", target.ResourceID, target.Path)[:32]
}

func (s *SQLStore) directoryDeleteIndex(objectIndex, operation string) string {
	return s.listingMAC("directory-delete-pending-v1", objectIndex, operation)
}

func (s *SQLStore) directoryDeleteCompleted(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget, operation string) (bool, error) {
	var complete int
	marker := s.listingMAC("directory-delete-complete-v1", target.ResourceID, operation)
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, marker).Scan(&complete); err != nil || complete == 0 {
		return false, err
	}
	index, err := s.tree.ObjectIndex(target.ResourceID)
	if err != nil {
		return false, err
	}
	var live int
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM sealed_tree_records WHERE object_index=?)+
		(SELECT COUNT(*) FROM sealed_tree_facts WHERE object_index=?)+(SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?)+
		(SELECT COUNT(*) FROM sealed_tree_listing WHERE object_index=? OR group_tag IN (?,?,?))`, index, index, index, index,
		s.listingClassGroup(target.ResourceID, listingVisibleGroup), s.listingClassGroup(target.ResourceID, listingHidden), s.listingClassGroup(target.ResourceID, listingInternal)).Scan(&live); err != nil || live != 0 {
		return false, ErrConflict
	}
	return true, nil
}

func (s *SQLStore) directoryDeleteRoot(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget) (directoryDeleteChild, error) {
	var out directoryDeleteChild
	entry, index, err := s.pathEntryTx(ctx, tx, target.Path)
	if err != nil || entry.Kind != "directory" || entry.ObjectID != target.ResourceID || entry.ObjectID == s.rootID {
		return out, ErrConflict
	}
	record, matched, err := s.recordByID(ctx, tx, entry.ObjectID)
	if err != nil || matched != entry || record.ObjectIndex != index {
		return out, ErrInvalid
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, index)
	if err != nil || facts.InternalPlaceholder || s.verifyDirectoryDeleteListing(ctx, tx, entry, record, facts) != nil {
		return out, ErrConflict
	}
	return directoryDeleteChild{entry: entry, record: record, facts: facts, revision: revision, path: target.Path}, nil
}

func (s *SQLStore) verifyDirectoryDeleteIntent(ctx context.Context, tx treeQuery, entry Entry, record Record, facts Facts) (store.SelectedMediaDeleteTarget, error) {
	var empty store.SelectedMediaDeleteTarget
	name, err := s.pathInTransaction(ctx, tx, entry)
	if err != nil || entry.Kind != "directory" || facts.DirectoryDeletion == nil {
		return empty, ErrConflict
	}
	target := store.SelectedMediaDeleteTarget{Path: name, ResourceID: entry.ObjectID, OperationID: facts.DirectoryDeletion.OperationID, Directory: true}
	if !validDirectoryDeleteTarget(target) || target.OperationID != s.directoryDeleteOperation(target) {
		return empty, ErrConflict
	}
	index := s.directoryDeleteIndex(record.ObjectIndex, target.OperationID)
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations r JOIN sealed_tree_blob_ids b ON b.blob_index=r.operation_index WHERE r.operation_index=? AND r.object_index=?`, index, record.ObjectIndex).Scan(&n); err != nil || n != 1 {
		return empty, ErrConflict
	}
	return target, nil
}

func (s *SQLStore) PreflightDirectoryDeletion(ctx context.Context, target store.SelectedMediaDeleteTarget) (*DirectoryDeletePreflight, error) {
	if !s.valid() || ctx == nil || !validDirectoryDeleteTarget(target) {
		return nil, ErrInvalid
	}
	operation := s.directoryDeleteOperation(target)
	if target.OperationID != "" && target.OperationID != operation {
		return nil, ErrConflict
	}
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	lease, err := s.AcquireReadFence(c)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	tx, err := s.db.BeginTx(c, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(c, tx); err != nil {
		return nil, err
	}
	if done, err := s.directoryDeleteCompleted(c, tx, target, operation); err != nil || done {
		return nil, err
	}
	root, err := s.directoryDeleteRoot(c, tx, target)
	if err != nil {
		return nil, err
	}
	if root.facts.DirectoryDeletion != nil {
		_, err = s.verifyDirectoryDeleteIntent(c, tx, root.entry, root.record, root.facts)
		return nil, err
	}
	if target.OperationID != "" {
		return nil, ErrConflict
	}
	// An existing parent folder deletion already owns this subtree.
	if _, err = s.listingAncestorAnchor(c, tx, root.entry.ParentID, true); err != nil {
		return nil, err
	}
	plan := &DirectoryDeletePreflight{store: s, fence: lease.fence, generation: lease.generation, target: target}
	_, err = s.walkDirectoryDelete(c, tx, root, false, func(child directoryDeleteChild) error {
		if len(plan.leaves) == DirectoryDeleteLeafLimit {
			return ErrDirectoryDeleteLimit
		}
		plan.leaves = append(plan.leaves, store.SelectedMediaDeleteTarget{Path: child.path, ResourceID: child.entry.ObjectID})
		return nil
	})
	if err != nil {
		if ctx.Err() == nil && errors.Is(c.Err(), context.DeadlineExceeded) {
			return nil, ErrDirectoryDeleteLimit
		}
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if err = lease.Check(c); err != nil {
		return nil, err
	}
	return plan, nil
}

// AdmitDirectoryDeletionsTx compares every plan with the original generation
// before the same transaction queues any leaf. No work may be performed with
// this admission after the enclosing mutation ends.
func (m *CoordinatedMutation) AdmitDirectoryDeletionsTx(ctx context.Context, tx treeQuery, plans []*DirectoryDeletePreflight) (*DirectoryDeleteAdmission, error) {
	if m == nil || ctx == nil || tx == nil {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() {
		return nil, ErrFenceRequired
	}
	admission := &DirectoryDeleteAdmission{mutation: m, plans: map[string]*DirectoryDeletePreflight{}}
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&generation); err != nil {
		return nil, err
	}
	s.fenceMu.RLock()
	fence := s.fence
	s.fenceMu.RUnlock()
	var leafCount int
	for _, p := range plans {
		if p == nil { // an already pending/completed exact root needs no plan
			continue
		}
		if p.store != s || p.fence == nil || p.fence != fence || p.generation != generation || admission.plans[p.target.ResourceID] != nil {
			return nil, ErrFenceChanged
		}
		for _, current := range admission.plans {
			if strings.HasPrefix(current.target.Path, p.target.Path+"/") || strings.HasPrefix(p.target.Path, current.target.Path+"/") {
				return nil, ErrConflict
			}
		}
		leafCount += len(p.leaves)
		if leafCount > DirectoryDeleteLeafLimit {
			return nil, ErrDirectoryDeleteLimit
		}
		admission.plans[p.target.ResourceID] = p
	}
	return admission, nil
}

// QueueDirectoryDeletionTx publishes the folder fence only after all exact
// leaf deletion intents have been queued in this same transaction.
func (m *CoordinatedMutation) QueueDirectoryDeletionTx(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget, admission *DirectoryDeleteAdmission) (store.SelectedMediaDeleteItem, bool, error) {
	var empty store.SelectedMediaDeleteItem
	if m == nil || ctx == nil || tx == nil || !validDirectoryDeleteTarget(target) || admission == nil || admission.mutation != m {
		return empty, false, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() {
		return empty, false, ErrFenceRequired
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return empty, false, err
	}
	operation := s.directoryDeleteOperation(target)
	if target.OperationID != "" && target.OperationID != operation {
		return empty, false, ErrConflict
	}
	item := store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: target, State: store.SelectedMediaDeletePending}
	item.OperationID = operation
	if done, err := s.directoryDeleteCompleted(ctx, tx, target, operation); err != nil || done {
		item.State = store.SelectedMediaDeleteDeleted
		return item, false, err
	}
	root, err := s.directoryDeleteRoot(ctx, tx, target)
	if err != nil {
		return empty, false, err
	}
	if root.facts.DirectoryDeletion != nil {
		_, err = s.verifyDirectoryDeleteIntent(ctx, tx, root.entry, root.record, root.facts)
		return item, false, err
	}
	plan := admission.plans[target.ResourceID]
	if plan == nil || plan.target != target || root.revision == math.MaxInt64 {
		return empty, false, ErrConflict
	}
	for _, leaf := range plan.leaves {
		if err = s.verifyQueuedDirectoryLeaf(ctx, tx, leaf); err != nil {
			return empty, false, err
		}
	}
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return empty, false, err
	}
	oldClass := listingClass(&root.facts)
	root.facts.DirectoryDeletion = &DirectoryDeleteIntent{OperationID: operation}
	sealed, err := s.tree.SealFacts(root.facts, root.revision+1)
	if err != nil {
		return empty, false, err
	}
	id, err := FactsEncryptionID(sealed)
	if err != nil {
		return empty, false, err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return empty, false, err
	}
	index := s.directoryDeleteIndex(root.record.ObjectIndex, operation)
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, index); err != nil {
		return empty, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_revocations(operation_index,object_index) VALUES(?,?)`, index, root.record.ObjectIndex); err != nil {
		return empty, false, err
	}
	if err = deleteExactlyOne(ctx, tx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, id, sealed.Sealed, sealed.ObjectIndex, root.revision); err != nil {
		return empty, false, err
	}
	if err = s.listingRemove(ctx, tx, root.entry, root.record, oldClass); err != nil {
		return empty, false, err
	}
	if err = s.listingAdd(ctx, tx, root.entry, root.record, listingInternal); err != nil {
		return empty, false, err
	}
	return item, true, nil
}

// ListDirectoryDeletionsWithLease enumerates folder markers without exposing
// them to any physical leaf worker or revealing a plaintext pending record.
func (s *SQLStore) ListDirectoryDeletionsWithLease(ctx context.Context, lease *TreeLease, after string, limit int) ([]store.SelectedMediaDeleteItem, string, error) {
	rows, next, err := s.listPendingRevocationsWithLease(ctx, lease, after, limit, pendingDirectoryDeletion)
	if err != nil {
		return nil, "", err
	}
	items := make([]store.SelectedMediaDeleteItem, 0, len(rows))
	for _, row := range rows {
		if row.directory == nil {
			return nil, "", ErrConflict
		}
		items = append(items, store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: *row.directory, State: store.SelectedMediaDeletePending})
	}
	return items, next, nil
}
