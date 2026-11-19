package sealedtree

import (
	"context"
	"database/sql"
	"math"
	"path"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// SetNativePriority changes only the encrypted playback preference. The caller
// must hold the authenticated Admin, Owner and ingress admission for the write.
func (s *SQLStore) SetNativePriority(ctx context.Context, path, expectedID string, value int, directory bool) (store.PlaybackResult, error) {
	empty := store.PlaybackResult{}
	if value < store.PriorityMinimum || value > store.PriorityMaximum || !(strings.HasPrefix(path, "music/") || strings.HasPrefix(path, "vido/")) || expectedID != "" && !hexID(expectedID) {
		return empty, store.ErrPriorityMove
	}
	var result store.PlaybackResult
	err := s.withPriorityTx(ctx, func(tx *sql.Tx) error {
		entry, index, err := s.pathEntryTx(ctx, tx, path)
		if err != nil {
			return err
		}
		if directory && entry.Kind != "directory" || !directory && entry.Kind != "audio" && entry.Kind != "video" {
			return store.ErrPriorityMove
		}
		if expectedID != "" && entry.ObjectID != expectedID {
			return store.ErrPriorityStale
		}
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
		var changed bool
		result, changed, err = s.updatePriorityTx(ctx, tx, entry, index, value, now)
		if err != nil || !changed {
			return err
		}
		action := "media_priority"
		if directory {
			action = "directory_priority"
		}
		return s.appendPriorityAudit(ctx, tx, action, 1, now)
	})
	if err != nil {
		return empty, err
	}
	return result, nil
}

func (s *SQLStore) NativePriorityOrderWithLease(ctx context.Context, lease *TreeLease, scope, kind string) (store.PriorityOrder, error) {
	if !s.valid() || ctx == nil || lease == nil {
		return store.PriorityOrder{}, ErrFenceRequired
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return store.PriorityOrder{}, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return store.PriorityOrder{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return store.PriorityOrder{}, err
	}
	defer tx.Rollback()
	order, err := s.priorityOrderTx(ctx, tx, scope, kind)
	if err != nil {
		return store.PriorityOrder{}, err
	}
	if err = tx.Commit(); err != nil {
		return store.PriorityOrder{}, err
	}
	return order, lease.checkLocked(ctx)
}

func (s *SQLStore) priorityOrderTx(ctx context.Context, tx treeQuery, scope, kind string) (store.PriorityOrder, error) {
	if (kind != "media" && kind != "directory") ||
		(scope != "music" && scope != "vido" && !strings.HasPrefix(scope, "music/") && !strings.HasPrefix(scope, "vido/")) {
		return store.PriorityOrder{}, store.ErrPriorityMove
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return store.PriorityOrder{}, err
	}
	parent, _, err := s.pathEntryTx(ctx, tx, scope)
	if err != nil {
		return store.PriorityOrder{}, err
	}
	if parent.Kind != "directory" {
		return store.PriorityOrder{}, store.ErrPriorityMove
	}
	entries := []store.PriorityEntry{}
	const maxPrioritySiblings = 2048
	scanned, cursor := 0, ""
	for {
		items, next, err := s.listCatalogPageTx(ctx, tx, parent.ObjectID, cursor, 128, true)
		if err != nil {
			return store.PriorityOrder{}, err
		}
		scanned += len(items)
		if scanned > maxPrioritySiblings || scanned == maxPrioritySiblings && next != "" {
			return store.PriorityOrder{}, store.ErrNodeState
		}
		for _, item := range items {
			e := item.Entry
			if kind == "directory" && e.Kind != "directory" || kind == "media" && e.Kind != "audio" && e.Kind != "video" {
				continue
			}
			preference := 0
			if item.Facts.Playback != nil {
				preference = int(item.Facts.Playback.Preference)
			}
			entries = append(entries, store.PriorityEntry{ID: e.ObjectID, Path: path.Join(scope, e.Name), Preference: preference, ObjectKind: e.Kind})
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return store.NewPriorityOrder(scope, kind, entries), nil
}

// MoveNativePriority reads and applies the whole revisioned sibling plan in
// one tree transaction. It uses the same Admin writer admission as SetNativePriority.
func (s *SQLStore) MoveNativePriority(ctx context.Context, scope, kind string, move store.PriorityMove) (store.PriorityOrder, error) {
	var result store.PriorityOrder
	err := s.withPriorityTx(ctx, func(tx *sql.Tx) error {
		current, err := s.priorityOrderTx(ctx, tx, scope, kind)
		if err != nil {
			return err
		}
		items, err := store.PlanPriorityMove(current, move)
		if err != nil {
			return err
		}
		old := make(map[string]int, len(current.Items))
		for _, item := range current.Items {
			old[item.ID] = item.Preference
		}
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
		changed := 0
		for _, item := range items {
			if old[item.ID] == item.Preference {
				continue
			}
			record, entry, err := s.recordByID(ctx, tx, item.ID)
			if err != nil {
				return err
			}
			if _, _, err = s.updatePriorityTx(ctx, tx, entry, record.ObjectIndex, item.Preference, now); err != nil {
				return err
			}
			changed++
		}
		if changed > 0 {
			if err = s.appendPriorityAudit(ctx, tx, "priority_reorder", changed, now); err != nil {
				return err
			}
		}
		result = store.NewPriorityOrder(scope, kind, items)
		result.Changed = changed
		return nil
	})
	if err != nil {
		return store.PriorityOrder{}, err
	}
	return result, nil
}

func (s *SQLStore) updatePriorityTx(ctx context.Context, tx treeQuery, entry Entry, index string, value int, now string) (store.PlaybackResult, bool, error) {
	empty := store.PlaybackResult{}
	facts, revision, err := s.factsFor(ctx, tx, entry, index)
	if err != nil {
		return empty, false, err
	}
	if facts.InternalPlaceholder || facts.Revocation != nil || revision < 1 || revision == math.MaxInt64 {
		return empty, false, ErrConflict
	}
	result := store.PlaybackResult{MediaID: entry.ObjectID, PlaybackStats: store.PlaybackStats{Preference: value}}
	if facts.Playback != nil {
		result.PlayScore = facts.Playback.PlayScore
	}
	if facts.Playback == nil && value == 0 || facts.Playback != nil && facts.Playback.Preference == int64(value) {
		return result, false, nil
	}
	if facts.Playback == nil {
		facts.Playback = &PlaybackFact{CreatedAt: now}
	}
	facts.Playback.Preference, facts.Playback.UpdatedAt = int64(value), now
	if err = s.replaceListingFactsTx(ctx, tx, entry, index, facts, revision); err != nil {
		return empty, false, err
	}
	return result, true, nil
}

func (s *SQLStore) replaceListingFactsTx(ctx context.Context, tx treeQuery, entry Entry, index string, facts Facts, revision int64) error {
	sealed, err := s.tree.SealFacts(facts, revision+1)
	if err != nil {
		return err
	}
	id, err := FactsEncryptionID(sealed)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, id, sealed.Sealed, index, revision)
	if err != nil {
		return err
	}
	if n, err := updated.RowsAffected(); err != nil || n != 1 {
		return ErrConflict
	}
	return s.listingAdjust(ctx, tx, s.listingClassGroup(entry.ParentID, listingClass(&facts)), 0)
}

func (s *SQLStore) appendPriorityAudit(ctx context.Context, tx treeQuery, action string, count int, now string) error {
	if handled, e := s.archiveAudit(ctx, tx, map[string]any{"action": action, "target_count": count, "at": now}); handled {
		return e
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO admin_audit_log (action,target_count,result,created_at) VALUES (?,?,'success',?)`, action, count, now)
	return err
}

func (s *SQLStore) withPriorityTx(ctx context.Context, write func(*sql.Tx) error) error {
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	if err = write(tx); err != nil {
		return err
	}
	return tx.Commit()
}
