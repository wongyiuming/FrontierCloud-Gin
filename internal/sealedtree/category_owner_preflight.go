package sealedtree

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"sync"
	"time"

	"modernc.org/sqlite"
)

// CategoryOwnerPreflight is a process-local, one-shot concurrency proof, not an
// upload permission. Its fields are private and copied handles share one state.
// It is only valid for the exact tree instance, parent, owner and generation.
type CategoryOwnerPreflight struct{ state *categoryOwnerPreflightState }
type categoryOwnerPreflightState struct {
	mu            sync.Mutex
	tree          *SQLStore
	fence         *TreeFence
	parent, owner string
	generation    int64
	deadline      time.Time
	origin        context.Context
	used          bool
}

// PreflightCategoryAndOwner reads one consistent SQLite snapshot under the
// real shared tree fence without holding the global ingress writer. All tree
// writers must follow the fenced, generation-incrementing contract. MySQL and
// wrapped/unknown SQLite drivers fail closed until separately proven.
func (s *SQLStore) PreflightCategoryAndOwner(ctx context.Context, parent, owner string) (*CategoryOwnerPreflight, error) {
	if !s.valid() || ctx == nil || !hexID(parent) || !lowerHex(owner, 32) || s.prototypeOnly() {
		return nil, ErrInvalid
	}
	if _, ok := s.db.Driver().(*sqlite.Driver); !ok {
		return nil, ErrInvalid
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
		return nil, ErrInvalid
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.checkMediaCategoryLayoutReadTx(ctx, tx, parent, owner); err != nil {
		return nil, err
	}
	var generation int64
	if err = tx.QueryRowContext(ctx, `SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&generation); err != nil || generation != lease.generation {
		return nil, ErrFenceChanged
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if err = lease.Check(ctx); err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return nil, ErrFenceChanged
	}
	return &CategoryOwnerPreflight{state: &categoryOwnerPreflightState{tree: s, fence: lease.fence, parent: parent, owner: owner, generation: generation, deadline: deadline, origin: ctx}}, nil
}

// BindContext ensures the final SQL transaction is cancelled when either its
// own caller or the request that produced this proof is cancelled. The caller
// must defer the returned cleanup and use the returned context for acquisition,
// checks and commit. It is not a substitute for consuming the proof.
func (p *CategoryOwnerPreflight) BindContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if p == nil || p.state == nil || ctx == nil {
		return nil, nil, ErrInvalid
	}
	st := p.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.used || st.origin == nil || st.origin.Err() != nil || ctx.Err() != nil || !time.Now().Before(st.deadline) {
		return nil, nil, ErrFenceChanged
	}
	bound, cancel := context.WithDeadline(ctx, st.deadline)
	stop := context.AfterFunc(st.origin, cancel)
	if st.origin.Err() != nil {
		stop()
		cancel()
		return nil, nil, ErrFenceChanged
	}
	return bound, func() { stop(); cancel() }, nil
}

// CheckContext synchronously rechecks the originating request and proof
// deadline. The coordinator calls this immediately before committing its
// transaction in addition to using the bound context for all SQL operations.
func (p *CategoryOwnerPreflight) CheckContext(ctx context.Context) error {
	if p == nil || p.state == nil || ctx == nil {
		return ErrInvalid
	}
	st := p.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.origin == nil || st.origin.Err() != nil || ctx.Err() != nil || !time.Now().Before(st.deadline) {
		return ErrFenceChanged
	}
	return nil
}

// ConsumeCategoryOwnerPreflightTx rechecks the proof inside the same trusted
// coordinator-owned SQLite write transaction and real exclusive tree fence.
// The coordinator must supply its own same-s.db transaction, hold the existing
// Owner -> ingress -> tree locks, revalidate identity/policy/capacity and write
// the pending object before committing. The proof is consumed even on failure.
// No caller-supplied generation or proof data is accepted as authority.
func (m *CoordinatedMutation) ConsumeCategoryOwnerPreflightTx(ctx context.Context, tx treeQuery, p *CategoryOwnerPreflight, parent, owner string) error {
	if m == nil || ctx == nil || tx == nil || p == nil || p.state == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st := p.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.used {
		return ErrFenceChanged
	}
	st.used = true
	s := m.store
	if !m.active || !s.valid() || st.tree != s || st.fence == nil || st.parent != parent || st.owner != owner || st.origin == nil || st.origin.Err() != nil || ctx.Err() != nil || !time.Now().Before(st.deadline) {
		return ErrFenceChanged
	}
	s.fenceMu.RLock()
	currentFence := s.fence
	s.fenceMu.RUnlock()
	if currentFence != st.fence {
		return ErrFenceChanged
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return ErrFenceChanged
	}
	if err := s.requireListingReady(ctx, tx); err != nil {
		return ErrFenceChanged
	}
	var tag string
	var generation int64
	if tx.QueryRowContext(ctx, `SELECT fence_tag FROM sealed_tree_fence WHERE singleton=1`).Scan(&tag) != nil || !hmac.Equal([]byte(tag), []byte(st.fence.tag())) {
		return ErrFenceChanged
	}
	if tx.QueryRowContext(ctx, `SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&generation) != nil || generation != st.generation || st.origin.Err() != nil || ctx.Err() != nil || !time.Now().Before(st.deadline) {
		return ErrFenceChanged
	}
	return nil
}
