package sealedtree

import (
	"context"
	"database/sql"
	"strings"
	"unicode/utf8"
)

// ResolveVisibleDirectoryWithLease resolves a canonical, slash-separated
// Master-only path to a directory ID. Empty path denotes the virtual root.
// Each component and its visibility are authenticated under the same shared
// tree lease and SQL snapshot. This is not user authorization: callers must
// separately authorize the request, map missing/hidden paths to a uniform
// response, and retain the lease through the admission commit. Names and the
// resulting identifier must not be sent to an untrusted owner. No runtime
// installs this prototype until the tree and its mutations are migrated.
func (s *SQLStore) ResolveVisibleDirectoryWithLease(ctx context.Context, lease *TreeLease, path string) (string, error) {
	return s.ResolveDirectoryWithLease(ctx, lease, path, false)
}

// ResolveDirectoryWithLease also supports the existing explicit include-hidden
// catalog scope. It does not grant media, lyric, or recording access.
func (s *SQLStore) ResolveDirectoryWithLease(ctx context.Context, lease *TreeLease, path string, includeHidden bool) (string, error) {
	if !s.valid() || ctx == nil || lease == nil || len(path) > 4096 || !utf8.ValidString(path) || utf8.RuneCountInString(path) > 1024 {
		return "", ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return "", ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return "", err
	}
	var parts []string
	if path != "" {
		parts = strings.Split(path, "/")
		if len(parts) > 128 {
			return "", ErrInvalid
		}
		for _, part := range parts {
			if !validComponent(part) {
				return "", ErrInvalid
			}
		}
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return "", err
	}
	if err = s.requireListingReady(ctx, tx); err != nil {
		return "", err
	}
	parent := s.rootID
	for _, part := range parts {
		group, e := s.tree.ParentIndex(parent)
		if e != nil {
			return "", ErrInvalid
		}
		lookup, e := s.tree.Lookup(parent, part)
		if e != nil {
			return "", ErrInvalid
		}
		r, e := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE parent_index=? AND lookup_tag=?`, group, lookup))
		if e != nil {
			return "", e
		}
		if e = verifyNameReservation(ctx, tx, r); e != nil {
			return "", e
		}
		entry, visible, e := s.visibleListEntry(ctx, tx, parent, r)
		if e != nil {
			return "", e
		}
		if !visible && !includeHidden {
			return "", ErrHidden
		}
		if entry.Name != part || entry.Kind != "directory" {
			return "", ErrInvalid
		}
		parent = entry.ObjectID
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return "", err
	}
	return parent, nil
}
