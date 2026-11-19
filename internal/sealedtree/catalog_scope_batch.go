package sealedtree

import (
	"context"
	"database/sql"
)

// CatalogScopeCheck binds one collected directory and display range to the
// proof captured before its first page. It is trusted-Master state only.
type CatalogScopeCheck struct {
	ParentID      string
	IncludeHidden bool
	Proof         CatalogScopeProof
}

// CheckCatalogScopesWithLease checks all collected scopes in one SQL snapshot
// under one already-held shared tree lease. Every visited directory (including
// empty branches) must be represented. This is consistency evidence only;
// it does not authorize bytes or verify external owner/source configuration.
// The caller retains the lease through the final admission commit.
func (s *SQLStore) CheckCatalogScopesWithLease(ctx context.Context, lease *TreeLease, checks []CatalogScopeCheck) error {
	if !s.valid() || ctx == nil || lease == nil || len(checks) == 0 {
		return ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	if err = s.requireListingReady(ctx, tx); err != nil {
		return err
	}
	seen := make(map[string]CatalogScopeProof, len(checks))
	for _, check := range checks {
		if err = ctx.Err(); err != nil {
			return err
		}
		if !hexID(check.ParentID) {
			return ErrInvalid
		}
		key := check.ParentID + ":" + strconvBool(check.IncludeHidden)
		if old, ok := seen[key]; ok {
			if old != check.Proof {
				return ErrInvalid
			}
			continue
		}
		seen[key] = check.Proof
		state, e := s.catalogScope(ctx, tx, check.ParentID, check.IncludeHidden)
		if e != nil {
			return e
		}
		proofScope := s.listingMAC("scope-proof", state.scope)
		marker := s.listingMAC("scope-proof-marker", check.ParentID)
		got, e := s.openListingCursor(check.Proof.sealed, proofScope, state.revision, state.anchor)
		if e != nil {
			return e
		}
		if got != marker {
			return ErrInvalid
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return lease.checkLocked(ctx)
}

func strconvBool(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
