package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var (
	ErrMasterLocalLyricDeleteLimit        = errors.New("lyric deletion exceeds the association change limit")
	ErrMasterLocalLyricDeleteCatalogLimit = errors.New("lyric deletion exceeds the catalog scan limit")
)

func validMasterLocalLyricDeletePath(name string) bool {
	if strings.EqualFold(name, "lyrics/default.lrc") || !strings.EqualFold(path.Ext(name), ".lrc") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) < 2 || len(parts) > 4 || parts[0] != "lyrics" {
		return false
	}
	for _, part := range parts {
		if !validComponent(part) || strings.HasPrefix(part, ".") || strings.Contains(part, ":") {
			return false
		}
	}
	return true
}

// MasterLocalLyricDeletePreflight is bound to one authenticated tree
// generation and exact lyric. A catalog page is not a reference census.
type MasterLocalLyricDeletePreflight struct {
	store      *SQLStore
	fence      *TreeFence
	generation int64
	target     store.SelectedMediaDeleteTarget
	changes    []NativeLyricChange
}

// PreflightMasterLocalLyricDeletion reads all published and pending facts in a
// bounded shared snapshot, including hidden and internal rows. Encrypted facts
// contain the only authoritative reverse links; incomplete scans never admit
// deletion. No filesystem or catalog mutation occurs here.
func (s *SQLStore) PreflightMasterLocalLyricDeletion(ctx context.Context, target store.SelectedMediaDeleteTarget) (*MasterLocalLyricDeletePreflight, error) {
	batch, err := s.PreflightMasterLocalLyricDeletions(ctx, []store.SelectedMediaDeleteTarget{target})
	if err != nil || batch == nil {
		return nil, err
	}
	return batch.proofs[target.ResourceID], nil
}

type MasterLocalLyricDeleteBatchPreflight struct {
	proofs map[string]*MasterLocalLyricDeletePreflight
}

type MasterLocalLyricDeleteAdmission struct {
	mutation *CoordinatedMutation
	proofs   map[string]*MasterLocalLyricDeletePreflight
}

// PreflightMasterLocalLyricDeletions shares one complete scan across a mixed
// Admin selection. The scan and total detached-track budgets apply to the
// whole batch, including hidden/internal published and pending facts.
func (s *SQLStore) PreflightMasterLocalLyricDeletions(ctx context.Context, targets []store.SelectedMediaDeleteTarget) (*MasterLocalLyricDeleteBatchPreflight, error) {
	if !s.valid() || ctx == nil || len(targets) == 0 || len(targets) > MaxNativeLyricPatchTracks {
		return nil, ErrInvalid
	}
	selected := make([]store.SelectedMediaDeleteTarget, 0, len(targets))
	for _, target := range targets {
		if !strings.HasPrefix(target.Path, "lyrics/") {
			continue
		}
		if !hexID(target.ResourceID) || !validMasterLocalLyricDeletePath(target.Path) {
			return nil, ErrInvalid
		}
		if target.OperationID == "" {
			selected = append(selected, target)
		}
	}
	if len(selected) == 0 {
		return nil, nil
	}
	scanCtx, cancel := context.WithTimeout(ctx, nativeLyricAutoTimeout)
	defer cancel()
	lease, err := s.AcquireReadFence(scanCtx)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	tx, err := s.db.BeginTx(scanCtx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(scanCtx, tx); err != nil {
		return nil, err
	}
	var generation int64
	if err = tx.QueryRowContext(scanCtx, `SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&generation); err != nil || generation != lease.generation {
		return nil, ErrFenceChanged
	}
	batch := &MasterLocalLyricDeleteBatchPreflight{proofs: map[string]*MasterLocalLyricDeletePreflight{}}
	for _, target := range selected {
		if _, exists := batch.proofs[target.ResourceID]; exists {
			return nil, ErrInvalid
		}
		if done, err := s.nativeDeleteCompleted(scanCtx, tx, target.ResourceID, s.masterLocalMediaDeleteOperation(target.ResourceID, target.Path)); err != nil {
			return nil, err
		} else if done {
			continue
		}
		view, err := s.masterLocalMediaDeletionView(scanCtx, tx, target)
		if err != nil || view.entry.Kind != "lyric" {
			return nil, ErrConflict
		}
		if view.facts.Revocation != nil {
			continue // the queue transaction verifies the existing intent
		}
		if _, _, err = masterLocalDeleteBindings(scanCtx, tx, view.placement); err != nil {
			return nil, err
		}
		batch.proofs[target.ResourceID] = &MasterLocalLyricDeletePreflight{store: s, fence: lease.fence, generation: generation, target: target}
	}
	if len(batch.proofs) == 0 {
		return nil, nil
	}
	remaining := MaxLyricScopeEntries
	changes := 0
	scratch := make([]byte, factsPayloadBytes)
	for _, source := range []struct {
		query   string
		pending bool
	}{
		{`SELECT object_index,revision,encryption_id,sealed FROM sealed_tree_facts ORDER BY object_index LIMIT ?`, false},
		{`SELECT object_index,revision,encryption_id,sealed FROM sealed_tree_pending_facts ORDER BY operation_id LIMIT ?`, true},
	} {
		err = s.scanMasterLocalLyricReferencesBatch(scanCtx, tx, source.query, source.pending, batch.proofs, scratch, &remaining, &changes)
		if err != nil {
			if scanCtx.Err() != nil {
				return nil, scanCtx.Err()
			}
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if err = lease.Check(scanCtx); err != nil {
		return nil, err
	}
	return batch, nil
}

func (s *SQLStore) scanMasterLocalLyricReferencesBatch(ctx context.Context, tx treeQuery, query string, pending bool, proofs map[string]*MasterLocalLyricDeletePreflight, scratch []byte, remaining, changes *int) error {
	rows, err := tx.QueryContext(ctx, query, *remaining+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if *remaining == 0 {
			return ErrMasterLocalLyricDeleteCatalogLimit
		}
		*remaining = *remaining - 1
		record, err := scanFacts(rows)
		if err != nil {
			return err
		}
		facts, err := s.tree.openFactsWithScratch(record, scratch)
		if err != nil {
			return err
		}
		if facts.InternalDefaultLyric != nil {
			if _, protected := proofs[facts.InternalDefaultLyric.DefaultLyricID]; protected {
				return ErrConflict
			}
		}
		if facts.Lyric == nil {
			continue
		}
		proof := proofs[facts.Lyric.LyricID]
		if proof == nil {
			continue
		}
		if pending || facts.Revocation != nil || facts.S3Deletion != nil {
			return ErrConflict
		}
		if *changes == MaxNativeLyricPatchTracks {
			return ErrMasterLocalLyricDeleteLimit
		}
		proof.changes = append(proof.changes, NativeLyricChange{TrackID: facts.ObjectID, ExpectedFactsRevision: record.Revision})
		*changes = *changes + 1
	}
	return rows.Err()
}

// AdmitMasterLocalLyricDeletionsTx validates every proof against the original
// transaction generation before any batch member is queued. The returned
// admission belongs only to this held mutation and cannot cross requests.
func (m *CoordinatedMutation) AdmitMasterLocalLyricDeletionsTx(ctx context.Context, tx treeQuery, batch *MasterLocalLyricDeleteBatchPreflight) (*MasterLocalLyricDeleteAdmission, error) {
	if m == nil || ctx == nil || tx == nil {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active || !m.store.valid() {
		return nil, ErrFenceRequired
	}
	admission := &MasterLocalLyricDeleteAdmission{mutation: m, proofs: map[string]*MasterLocalLyricDeletePreflight{}}
	if batch == nil {
		return admission, nil
	}
	for id, proof := range batch.proofs {
		if proof == nil || proof.target.ResourceID != id || m.store.verifyMasterLocalLyricDeletePreflight(ctx, tx, proof.target, proof) != nil {
			return nil, ErrFenceChanged
		}
		admission.proofs[id] = proof
	}
	return admission, nil
}

// detachMasterLocalLyricReferencesTx runs after verifying the preflight's
// generation and taking the indexed write fence. Any failure also rolls back
// the newly queued lyric intent. Existing links move to built-in fallback.
func (s *SQLStore) detachMasterLocalLyricReferencesTx(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget, op string, proof *MasterLocalLyricDeletePreflight, audit store.AdminAudit) error {
	if len(proof.changes) == 0 {
		return nil
	}
	cache, err := s.newLyricTxCache(ctx, tx)
	if err != nil {
		return err
	}
	operation := s.listingMAC("master-local-lyric-detach-v1", target.ResourceID, op)
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
	changes, err := cache.applyChanges(operation, now, proof.changes, func(_ NativeLyricChange, facts Facts) error {
		if facts.Lyric == nil || facts.Lyric.LyricID != target.ResourceID {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	targets := make([]string, 0, len(changes))
	for _, change := range changes {
		targets = append(targets, change.Track)
	}
	audit = nativeLyricAudit(audit, "lyric_relations_removed_for_delete", len(targets)+1)
	return s.appendEncryptedLyricAudit(ctx, tx, operation, lyricAuditPayload{Origin: target.Path, Targets: targets, Changes: changes, Relations: len(changes), At: now, Audit: audit})
}

func (s *SQLStore) verifyMasterLocalLyricDeletePreflight(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget, proof *MasterLocalLyricDeletePreflight) error {
	if proof == nil || proof.store != s || proof.fence == nil || proof.target != target {
		return ErrFenceChanged
	}
	s.fenceMu.RLock()
	currentFence := s.fence
	s.fenceMu.RUnlock()
	var generation int64
	if currentFence != proof.fence || tx.QueryRowContext(ctx, `SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&generation) != nil || generation != proof.generation {
		return ErrFenceChanged
	}
	return ctx.Err()
}
