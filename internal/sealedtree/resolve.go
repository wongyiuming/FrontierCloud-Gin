package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"unicode/utf8"
)

var ErrHidden = errors.New("sealed tree object is hidden")
var ErrRevocationPending = errors.New("sealed tree object revocation pending")

// ResolvePath reconstructs the current logical path from authenticated tree
// links under one database snapshot. The result is sensitive Master memory:
// callers must authorize the object independently and must never persist or
// send this path to a resource node. It does not prove filesystem content,
// visibility or immutable freshness after the transaction ends.
func (s *SQLStore) ResolvePath(ctx context.Context, objectID string) (string, error) {
	if !s.valid() {
		return "", ErrInvalid
	}
	s.fenceMu.RLock()
	prototype := s.unsafePrototype
	s.fenceMu.RUnlock()
	if !prototype {
		return "", ErrFenceRequired
	}
	return s.resolvePath(ctx, objectID, false)
}

// ResolveVisiblePath additionally checks each entry's encrypted hidden rule.
// A missing fact row fails closed. It is not a user/session authorization and
// its SQL snapshot is not a lease: a real caller must hold a valid tree fence
// through authorization and capability issuance, then map ErrHidden to the
// existing non-disclosing response. It must never send the path to a node.
func (s *SQLStore) ResolveVisiblePath(ctx context.Context, objectID string) (string, error) {
	if !s.valid() {
		return "", ErrInvalid
	}
	s.fenceMu.RLock()
	prototype := s.unsafePrototype
	s.fenceMu.RUnlock()
	if !prototype {
		return "", ErrFenceRequired
	}
	return s.resolvePath(ctx, objectID, true)
}

// ResolveVisibleWithLease binds tree/visibility resolution to a caller-owned
// shared lease. The caller must retain that lease until the separate user
// authorization and ingress/capability commit completes. This helper is not
// an authorization decision and does not itself enable product routing.
func (s *SQLStore) ResolveVisibleWithLease(ctx context.Context, lease *TreeLease, objectID string) (string, error) {
	if !s.valid() || lease == nil || ctx == nil {
		return "", ErrFenceRequired
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return "", ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return "", err
	}
	value, err := s.resolvePath(ctx, objectID, true)
	if err != nil {
		return "", err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return "", err
	}
	return value, nil
}

// VisibleObject is sensitive Master-only state, not a node wire payload or an
// access grant. Path and Facts may contain names or historical legacy paths.
type VisibleObject struct {
	Path              string
	Entry             Entry
	EntryRevision     int64
	Facts             Facts
	FactsRevision     int64
	Placement         Placement
	PlacementRevision int64
}

// ReadVisibleObjectWithLease reads a visible file and its authenticated
// placement while the caller's shared tree lease remains held. All legitimate
// tree mutations must obey the same fence for these reads to form one stable
// view; this method neither authorizes a user nor proves remote availability.
// Callers must retain the lease through authorization and capability commit.
func (s *SQLStore) ReadVisibleObjectWithLease(ctx context.Context, lease *TreeLease, objectID string) (VisibleObject, error) {
	if !s.valid() || lease == nil || ctx == nil {
		return VisibleObject{}, ErrFenceRequired
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return VisibleObject{}, ErrFenceRequired
	}
	return s.readVisibleObjectLocked(ctx, lease, objectID)
}

func (s *SQLStore) readVisibleObjectLocked(ctx context.Context, lease *TreeLease, objectID string) (VisibleObject, error) {
	if err := lease.checkLocked(ctx); err != nil {
		return VisibleObject{}, err
	}
	path, err := s.resolvePath(ctx, objectID, true)
	if err != nil {
		return VisibleObject{}, err
	}
	entry, entryRevision, err := s.Get(ctx, objectID)
	if err != nil {
		return VisibleObject{}, err
	}
	if entry.Kind == "directory" {
		return VisibleObject{}, ErrInvalid
	}
	facts, factsRevision, err := s.GetFacts(ctx, objectID)
	if err != nil {
		return VisibleObject{}, err
	}
	placement, placementRevision, err := s.getPlacementWithRevision(ctx, objectID)
	if err != nil {
		return VisibleObject{}, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return VisibleObject{}, err
	}
	return VisibleObject{Path: path, Entry: entry, EntryRevision: entryRevision, Facts: facts, FactsRevision: factsRevision, Placement: placement, PlacementRevision: placementRevision}, nil
}

// ReadVisibleObjectByAliasWithLease resolves a random read alias through a
// keyed, unique index and reauthenticates the entry, placement, alias and
// inherited visibility under the same caller-owned shared lease. It never
// scans the tree. This is not user authorization or an owner read grant.
func (s *SQLStore) ReadVisibleObjectByAliasWithLease(ctx context.Context, lease *TreeLease, alias string) (VisibleObject, error) {
	if !s.valid() || ctx == nil || lease == nil || !hexID(alias) {
		return VisibleObject{}, ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return VisibleObject{}, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return VisibleObject{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return VisibleObject{}, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return VisibleObject{}, err
	}
	_, entry, err := s.recordByAlias(ctx, tx, alias)
	if err != nil {
		return VisibleObject{}, ErrInvalid
	}
	if err = tx.Commit(); err != nil {
		return VisibleObject{}, err
	}
	visible, err := s.readVisibleObjectLocked(ctx, lease, entry.ObjectID)
	if err != nil {
		return VisibleObject{}, err
	}
	if visible.Placement.ReadAlias != alias {
		return VisibleObject{}, ErrInvalid
	}
	return visible, nil
}

func (s *SQLStore) recordByAlias(ctx context.Context, tx treeQuery, alias string) (Record, Entry, error) {
	index, err := s.tree.BlobIndex(alias)
	if err != nil {
		return Record{}, Entry{}, err
	}
	var objectIndex string
	if err = tx.QueryRowContext(ctx, `SELECT object_index FROM sealed_tree_aliases WHERE alias_index=?`, index).Scan(&objectIndex); err != nil || !hexID(objectIndex) {
		return Record{}, Entry{}, ErrInvalid
	}
	record, err := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE object_index=?`, objectIndex))
	if err != nil || verifyNameReservation(ctx, tx, record) != nil {
		return Record{}, Entry{}, ErrInvalid
	}
	entry, err := s.tree.OpenRecord(record)
	if err != nil || entry.Kind == "directory" {
		return Record{}, Entry{}, ErrInvalid
	}
	return record, entry, nil
}

func (s *SQLStore) resolvePath(ctx context.Context, objectID string, requireVisible bool) (string, error) {
	if !s.valid() || objectID == s.rootID || !hexID(objectID) {
		return "", ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return "", err
	}
	seen := make(map[string]bool)
	parts := make([]string, 0, 8)
	current := objectID
	total := 0
	for depth := 0; depth < 128; depth++ {
		if seen[current] {
			return "", ErrConflict
		}
		seen[current] = true
		record, entry, err := s.recordByID(ctx, tx, current)
		if err != nil {
			return "", err
		}
		if depth > 0 && entry.Kind != "directory" {
			return "", ErrInvalid
		}
		if requireVisible {
			facts, _, factErr := s.factsFor(ctx, tx, entry, record.ObjectIndex)
			if factErr != nil {
				return "", ErrInvalid
			}
			if facts.InternalPlaceholder {
				return "", ErrInvalid
			}
			if facts.Revocation != nil || facts.DirectoryDeletion != nil {
				return "", ErrRevocationPending
			}
			var pending int
			if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?`, record.ObjectIndex).Scan(&pending); err != nil || pending != 0 {
				return "", ErrInvalid
			}
			if facts.Visibility != nil && facts.Visibility.Hidden == 1 {
				return "", ErrHidden
			}
		}
		total += len(entry.Name)
		if len(parts) > 0 {
			total++
		}
		if total > 4096 {
			return "", ErrInvalid
		}
		parts = append(parts, entry.Name)
		if entry.ParentID == s.rootID {
			for left, right := 0, len(parts)-1; left < right; left, right = left+1, right-1 {
				parts[left], parts[right] = parts[right], parts[left]
			}
			if err = tx.Commit(); err != nil {
				return "", err
			}
			path := strings.Join(parts, "/")
			if utf8.RuneCountInString(path) > 1024 {
				return "", ErrInvalid
			}
			return path, nil
		}
		current = entry.ParentID
	}
	return "", ErrConflict
}
