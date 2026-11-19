package sealedtree

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"sync"
)

var ErrFenceRequired = errors.New("sealed tree fence required")
var ErrFenceChanged = errors.New("sealed tree fence or generation changed")
var ErrFactsRequired = errors.New("sealed tree facts and durable publication required")
var ErrExternalLocators = errors.New("caller-provided sealed tree locators are not allowed")

// TreeFence relies on a trusted Master-private directory and every tree writer
// and restore process obeying the same OS lock. It is not a distributed lock
// and cannot stop a privileged or non-cooperating writer. SQL metadata is
// authenticated to the persistent random fence identity; missing state never
// causes automatic regeneration.
type TreeFence struct {
	store     *SQLStore
	root      *os.Root
	directory string
	id        [32]byte
	device    uint64
	inode     uint64
}

// TreeLease implements a read prerequisite held until the caller commits or
// aborts authorization/selection. Release is idempotent. Check is bounded and
// verifies lock identity, encrypted root binding, and the captured SQL write
// generation; it does not perform a full catalog scan.
type TreeLease struct {
	mu         sync.Mutex
	fence      *TreeFence
	file       *os.File
	generation int64
	exclusive  bool
	released   bool
}

func (f *TreeFence) tag() string {
	h := hmac.New(sha256.New, f.store.tree.indexKey[:])
	_, _ = h.Write([]byte("frontiercloud:sealed-tree:fence:v1\x00"))
	_, _ = h.Write(f.id[:])
	var identity [16]byte
	binary.BigEndian.PutUint64(identity[:8], f.device)
	binary.BigEndian.PutUint64(identity[8:], f.inode)
	_, _ = h.Write(identity[:])
	return hex.EncodeToString(h.Sum(nil))
}

func (f *TreeFence) databaseGeneration(ctx context.Context) (int64, error) {
	if f == nil || f.store == nil || !f.store.valid() {
		return 0, ErrFenceRequired
	}
	tx, err := f.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return 0, ErrFenceChanged
	}
	defer tx.Rollback()
	if err = f.store.verifyRoot(ctx, tx); err != nil {
		return 0, ErrFenceChanged
	}
	var tag string
	var generation int64
	if err = tx.QueryRowContext(ctx, `SELECT fence_tag FROM sealed_tree_fence WHERE singleton=1`).Scan(&tag); err != nil || !hmac.Equal([]byte(tag), []byte(f.tag())) {
		return 0, ErrFenceChanged
	}
	if err = tx.QueryRowContext(ctx, `SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&generation); err != nil || generation < 0 {
		return 0, ErrFenceChanged
	}
	if err = tx.Commit(); err != nil {
		return 0, ErrFenceChanged
	}
	return generation, nil
}

// AcquireReadFence returns a real shared prerequisite. A caller must retain it
// through the dependent transaction and release it in all paths. It does not
// itself prove that the product's other migration/backup gates are satisfied.
func (s *SQLStore) AcquireReadFence(ctx context.Context) (*TreeLease, error) {
	if !s.valid() || ctx == nil {
		return nil, ErrFenceRequired
	}
	s.fenceMu.RLock()
	fence := s.fence
	s.fenceMu.RUnlock()
	if fence == nil {
		return nil, ErrFenceRequired
	}
	return fence.acquire(ctx, false)
}

func (s *SQLStore) acquireMutation(ctx context.Context) (func(), error) {
	if !s.valid() || ctx == nil {
		return nil, ErrFenceRequired
	}
	s.fenceMu.RLock()
	fence, prototype := s.fence, s.unsafePrototype
	s.fenceMu.RUnlock()
	if prototype {
		return func() {}, nil
	}
	if fence == nil {
		return nil, ErrFenceRequired
	}
	lease, err := fence.acquire(ctx, true)
	if err != nil {
		return nil, err
	}
	return lease.Release, nil
}

func (s *SQLStore) prototypeOnly() bool {
	if s == nil {
		return false
	}
	s.fenceMu.RLock()
	defer s.fenceMu.RUnlock()
	return s.unsafePrototype
}

// Check never returns a name, path, or secret. A writer's generation naturally
// advances while it holds the exclusive lock; read leases must stay unchanged.
func (l *TreeLease) Check(ctx context.Context) error {
	if l == nil || ctx == nil {
		return ErrFenceRequired
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.checkLocked(ctx)
}

func (l *TreeLease) checkLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.released || l.file == nil || l.fence == nil {
		return ErrFenceChanged
	}
	if err := l.fence.checkFile(l.file); err != nil {
		return ErrFenceChanged
	}
	generation, err := l.fence.databaseGeneration(ctx)
	if err != nil || (!l.exclusive && generation != l.generation) || l.fence.checkFile(l.file) != nil {
		return ErrFenceChanged
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (l *TreeLease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return
	}
	l.released = true
	if l.file != nil {
		unlockFenceFile(l.file)
		_ = l.file.Close()
		l.file = nil
	}
}
