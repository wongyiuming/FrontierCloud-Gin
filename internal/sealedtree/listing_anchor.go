package sealedtree

import (
	"context"
	"strconv"
)

// listingAncestorAnchor authenticates every ancestor in the caller's SQL
// snapshot. A parent rename, reparent, facts revision or hidden transition
// changes this opaque anchor even if that ancestor later becomes visible again.
func (s *SQLStore) listingAncestorAnchor(ctx context.Context, tx treeQuery, parent string, includeHidden bool) (string, error) {
	anchor := s.listingMAC("ancestor-root", s.rootID)
	seen := make(map[string]bool)
	current := parent
	for depth := 0; depth < 128; depth++ {
		if current == s.rootID {
			return anchor, nil
		}
		if !hexID(current) || seen[current] {
			return "", ErrInvalid
		}
		seen[current] = true
		r, entry, err := s.recordByID(ctx, tx, current)
		if err != nil || entry.Kind != "directory" {
			return "", ErrInvalid
		}
		facts, factRevision, err := s.factsFor(ctx, tx, entry, r.ObjectIndex)
		if err != nil || facts.Revocation != nil || facts.InternalPlaceholder {
			return "", ErrInvalid
		}
		if facts.DirectoryDeletion != nil {
			return "", ErrRevocationPending
		}
		var pending int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?`, r.ObjectIndex).Scan(&pending) != nil || pending != 0 {
			return "", ErrInvalid
		}
		if !includeHidden && !listingVisible(&facts) {
			return "", ErrHidden
		}
		anchor = s.listingMAC("ancestor", anchor, entry.ObjectID, entry.ParentID, strconv.FormatInt(r.Revision, 10), strconv.FormatInt(factRevision, 10))
		current = entry.ParentID
	}
	if current == s.rootID {
		return anchor, nil
	}
	return "", ErrInvalid
}
