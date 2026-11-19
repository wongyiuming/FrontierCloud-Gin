package sealedtree

import (
	"context"
	"database/sql"
	"math"
	"strconv"
)

type catalogScopeState struct {
	visibleGroup, hiddenGroup, scope, anchor string
	revision                                 int64
	groups                                   []string
	counts                                   []int64
}

func (s *SQLStore) catalogScope(ctx context.Context, tx treeQuery, parent string, includeHidden bool) (catalogScopeState, error) {
	var state catalogScopeState
	state.visibleGroup = s.listingGroup(parent, true)
	state.hiddenGroup = s.listingGroup(parent, false)
	state.scope = state.visibleGroup
	var err error
	state.anchor, err = s.listingAncestorAnchor(ctx, tx, parent, includeHidden)
	if err != nil {
		return state, err
	}
	count, revision, err := s.listingSummary(ctx, tx, state.visibleGroup)
	if err != nil || count == math.MaxInt64 {
		return state, ErrInvalid
	}
	state.revision = revision
	state.groups, state.counts = []string{state.visibleGroup}, []int64{count}
	if includeHidden {
		hiddenCount, hiddenRevision, e := s.listingSummary(ctx, tx, state.hiddenGroup)
		if e != nil || hiddenCount == math.MaxInt64 {
			return state, ErrInvalid
		}
		state.groups = append(state.groups, state.hiddenGroup)
		state.counts = append(state.counts, hiddenCount)
		state.scope = s.listingMAC("all-groups", parent)
		state.anchor = s.listingMAC("all-revision", state.anchor, strconv.FormatInt(hiddenRevision, 10))
	}
	return state, nil
}

// CatalogScopeProof stays in the trusted Master process. It is a point-in-time
// consistency proof, not an access grant and not a client continuation.
type CatalogScopeProof struct{ sealed string }

func (s *SQLStore) catalogProofWithLease(ctx context.Context, lease *TreeLease, parent string, includeHidden bool, previous *CatalogScopeProof) (CatalogScopeProof, error) {
	if !s.valid() || ctx == nil || lease == nil || !hexID(parent) {
		return CatalogScopeProof{}, ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return CatalogScopeProof{}, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return CatalogScopeProof{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return CatalogScopeProof{}, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return CatalogScopeProof{}, err
	}
	if err = s.requireListingReady(ctx, tx); err != nil {
		return CatalogScopeProof{}, err
	}
	state, err := s.catalogScope(ctx, tx, parent, includeHidden)
	if err != nil {
		return CatalogScopeProof{}, err
	}
	proofScope := s.listingMAC("scope-proof", state.scope)
	marker := s.listingMAC("scope-proof-marker", parent)
	var result CatalogScopeProof
	if previous == nil {
		result.sealed, err = s.sealListingCursor(proofScope, marker, state.revision, state.anchor)
	} else {
		var got string
		got, err = s.openListingCursor(previous.sealed, proofScope, state.revision, state.anchor)
		if err == nil && got != marker {
			err = ErrInvalid
		}
		result = *previous
	}
	if err != nil {
		return CatalogScopeProof{}, err
	}
	if err = tx.Commit(); err != nil {
		return CatalogScopeProof{}, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return CatalogScopeProof{}, err
	}
	return result, nil
}

// CaptureCatalogScopeWithLease captures the scope before the first batch.
func (s *SQLStore) CaptureCatalogScopeWithLease(ctx context.Context, lease *TreeLease, parent string, includeHidden bool) (CatalogScopeProof, error) {
	return s.catalogProofWithLease(ctx, lease, parent, includeHidden, nil)
}

// CheckCatalogScopeWithLease checks the original scope after collection and
// sorting. The caller must hold lease through the independent admission commit.
// This only proves mutations that update this index and ancestor facts under
// the same fence; all other writers and recovery must be integrated first.
func (s *SQLStore) CheckCatalogScopeWithLease(ctx context.Context, lease *TreeLease, parent string, includeHidden bool, proof CatalogScopeProof) error {
	_, err := s.catalogProofWithLease(ctx, lease, parent, includeHidden, &proof)
	return err
}
