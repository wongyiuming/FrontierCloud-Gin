package business

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	driver "github.com/go-sql-driver/mysql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// PreparePublicIngressLease establishes the inode before native inventory pins
// its selected SQLite state. Every acquisition verifies the named inode.
func (r *Repository) PreparePublicIngressLease(ctx context.Context) error {
	if r.backend == "mysql" {
		return ctx.Err()
	}
	release, err := r.ingressLease(ctx, true)
	if err != nil {
		return err
	}
	release()
	return nil
}

// ingressLease orders requests and state changes made by native processes using
// the same SQLite database path. MySQL uses transactional row locks instead.
func (r *Repository) ingressLease(ctx context.Context, exclusive bool) (func(), error) {
	if r.backend != "sqlite" {
		return nil, store.ErrNodeState
	}
	var path string
	if err := r.db.QueryRowContext(ctx, "SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil || path == "" {
		return nil, store.ErrNodeState
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path) + store.PublicIngressLeaseSuffix
	info, err := root.Lstat(name)
	if err == nil && (!info.Mode().IsRegular() || info.Size() != 0) {
		root.Close()
		return nil, store.ErrNodeState
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		root.Close()
		return nil, err
	}
	f, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		root.Close()
		return nil, err
	}
	opened, err := f.Stat()
	current, statErr := root.Lstat(name)
	if err != nil || statErr != nil || !current.Mode().IsRegular() || current.Size() != 0 || !os.SameFile(opened, current) || info != nil && !os.SameFile(info, opened) {
		f.Close()
		root.Close()
		return nil, store.ErrNodeState
	}
	release, err := filelease.Acquire(ctx, f, exclusive)
	if err != nil {
		root.Close()
		return nil, err
	}
	current, err = root.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || current.Size() != 0 || !os.SameFile(opened, current) {
		release()
		root.Close()
		return nil, store.ErrNodeState
	}
	var once sync.Once
	return func() { once.Do(func() { release(); root.Close() }) }, nil
}

func mysqlIngressBusy(err error) bool {
	var e *driver.MySQLError
	return errors.As(err, &e) && e.Number == 3572 // ER_LOCK_NOWAIT
}

// Row locks and rollback are only authoritative with a transactional engine.
// Check while the table's metadata lock is held, not just at process startup.
func verifyIngressEngine(ctx context.Context, q queryer) error {
	var engine sql.NullString
	if err := q.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='public_ingress_config'").Scan(&engine); err != nil {
		return err
	}
	if !engine.Valid || !strings.EqualFold(engine.String, "InnoDB") {
		return store.ErrNodeState
	}
	return nil
}

// Do not retain a pooled connection while waiting for an ingress row lock.
// Otherwise simultaneous selection attempts could occupy every connection
// needed by the handlers whose shared leases they are waiting to drain.
func waitIngressRetry(ctx context.Context) error {
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ingressWrite holds the exclusive gate in the SAME transaction as the
// mutation. It is always acquired before node or relationship row locks.
func (r *Repository) ingressWrite(ctx context.Context, fn func(queryer) error) error {
	if held, ok := ctx.Value(ownerControlContextKey{}).(*ownerControlContext); ok && held.repository == r {
		held.mu.RLock()
		defer held.mu.RUnlock()
		if held.closed {
			return store.ErrNodeState
		}
		if !validOwnerControlLease(held.lease) || held.lease.Check(ctx) != nil {
			return store.ErrNodeState
		}
		original := fn
		fn = func(q queryer) error {
			if err := r.checkOwnerControlMarker(ctx, q, held.lease); err != nil {
				return err
			}
			if err := original(q); err != nil {
				return err
			}
			if held.lease.Check(ctx) != nil {
				return store.ErrNodeState
			}
			return nil
		}
		return r.ingressWriteSQL(ctx, fn)
	}
	r.ownerControlMu.RLock()
	acquire := r.ownerControlAcquire
	r.ownerControlMu.RUnlock()
	if acquire != nil {
		lease, err := acquire(ctx, true)
		if err != nil || !validOwnerControlLease(lease) {
			if validOwnerControlLease(lease) {
				lease.Release()
			}
			return store.ErrNodeState
		}
		defer lease.Release()
		if lease.Check(ctx) != nil {
			return store.ErrNodeState
		}
		original := fn
		fn = func(q queryer) error {
			if err := r.checkOwnerControlMarker(ctx, q, lease); err != nil {
				return err
			}
			if err := original(q); err != nil {
				return err
			}
			if lease.Check(ctx) != nil {
				return store.ErrNodeState
			}
			return nil
		}
	} else {
		original := fn
		fn = func(q queryer) error {
			if err := r.checkOwnerControlMarker(ctx, q, nil); err != nil {
				return err
			}
			return original(q)
		}
	}
	return r.ingressWriteSQL(ctx, fn)
}

// checkOwnerControlMarker executes inside the same transaction as the writer.
// A configured fence with no durable marker is a partial initialization, not
// permission to write. An unconfigured process cannot mutate a marked node.
func (r *Repository) checkOwnerControlMarker(ctx context.Context, q queryer, lease store.OwnerControlLease) error {
	var tag string
	query := "SELECT fence_tag FROM sealed_tree_owner_fence WHERE singleton=1"
	if tx, ok := q.(*catalogWrite); ok && tx.mysql {
		// Avoid starting a stale MySQL consistent-read snapshot before the
		// protected writer acquires its business row locks.
		query += " FOR SHARE"
	}
	err := q.QueryRowContext(ctx, query).Scan(&tag)
	if errors.Is(err, sql.ErrNoRows) {
		if lease == nil {
			return nil
		}
		return store.ErrNodeState
	}
	if err != nil || !validOwnerControlLease(lease) {
		return store.ErrNodeState
	}
	if r.verifyOwnerFenceEngine(ctx, q) != nil {
		return store.ErrNodeState
	}
	current, err := lease.Binding(ctx)
	if err != nil || len(tag) != 64 || current != tag {
		return store.ErrNodeState
	}
	return nil
}

func (r *Repository) verifyOwnerFenceEngine(ctx context.Context, q queryer) error {
	if r.backend == "sqlite" {
		return nil
	}
	if r.backend != "mysql" {
		return store.ErrNodeState
	}
	var engine sql.NullString
	if err := q.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sealed_tree_owner_fence'").Scan(&engine); err != nil || !engine.Valid || !strings.EqualFold(engine.String, "InnoDB") {
		return store.ErrNodeState
	}
	return nil
}

func (r *Repository) ingressWriteSQL(ctx context.Context, fn func(queryer) error) error {
	if scope, present := ctx.Value(orderedIngressTreeKey{}).(*orderedIngressTreeScope); present {
		if scope == nil || scope.repo != r || r.backend != "sqlite" {
			return store.ErrNodeState
		}
		scope.mu.Lock()
		defer scope.mu.Unlock()
		if !scope.active || scope.tree == nil || scope.tree.Check(ctx) != nil {
			return store.ErrNodeState
		}
		return r.write(ctx, func(q queryer) error {
			if scope.tree.Check(ctx) != nil {
				return store.ErrNodeState
			}
			if err := fn(q); err != nil {
				return err
			}
			if scope.tree.Check(ctx) != nil {
				return store.ErrNodeState
			}
			return ctx.Err()
		})
	}
	if r.backend == "sqlite" {
		release, err := r.ingressLease(ctx, true)
		if err != nil {
			return err
		}
		defer release()
		return r.write(ctx, fn)
	}
	if r.backend != "mysql" {
		return store.ErrNodeState
	}
	for {
		err := r.write(ctx, func(q queryer) error {
			var singleton int
			err := q.QueryRowContext(ctx, "SELECT singleton FROM public_ingress_config WHERE singleton=1 FOR UPDATE NOWAIT").Scan(&singleton)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err := verifyIngressEngine(ctx, q); err != nil {
				return err
			}
			return fn(q)
		})
		if !mysqlIngressBusy(err) {
			return err
		}
		if err = waitIngressRetry(ctx); err != nil {
			return err
		}
	}
}

type ownerControlContextKey struct{}
type ownerControlContext struct {
	repository *Repository
	lease      store.OwnerControlLease
	mu         sync.RWMutex
	closed     bool
}

// borrowedOwnerControlLease cannot release the caller's exclusive fence. The
// parent token invalidates all borrows before that fence is released.
type borrowedOwnerControlLease struct {
	parent *ownerControlContext
	done   bool // protected by parent.mu
}

func (b *borrowedOwnerControlLease) Check(ctx context.Context) error {
	if b == nil || b.parent == nil || ctx == nil {
		return store.ErrNodeState
	}
	b.parent.mu.RLock()
	defer b.parent.mu.RUnlock()
	if b.parent.closed || b.done || !validOwnerControlLease(b.parent.lease) {
		return store.ErrNodeState
	}
	if b.parent.lease.Check(ctx) != nil || b.parent.repository.checkOwnerControlMarker(ctx, b.parent.repository.db, b.parent.lease) != nil || b.parent.lease.Check(ctx) != nil {
		return store.ErrNodeState
	}
	return nil
}

func (b *borrowedOwnerControlLease) Binding(ctx context.Context) (string, error) {
	if b == nil || b.parent == nil || ctx == nil {
		return "", store.ErrNodeState
	}
	b.parent.mu.RLock()
	defer b.parent.mu.RUnlock()
	if b.parent.closed || b.done || !validOwnerControlLease(b.parent.lease) {
		return "", store.ErrNodeState
	}
	if b.parent.lease.Check(ctx) != nil || b.parent.repository.checkOwnerControlMarker(ctx, b.parent.repository.db, b.parent.lease) != nil {
		return "", store.ErrNodeState
	}
	value, err := b.parent.lease.Binding(ctx)
	if err != nil || b.parent.lease.Check(ctx) != nil {
		return "", store.ErrNodeState
	}
	return value, nil
}

func (b *borrowedOwnerControlLease) Release() {
	if b != nil && b.parent != nil {
		b.parent.mu.Lock()
		b.done = true
		b.parent.mu.Unlock()
	}
}

func validOwnerControlLease(lease store.OwnerControlLease) bool {
	if lease == nil {
		return false
	}
	v := reflect.ValueOf(lease)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

// heldOwnerWrite is for legacy operations whose caller already holds the
// media-volume lock. It never tries to acquire owner control in reverse order.
// A marked or configured store requires this repository's live exclusive
// context; marker verification and the mutation share one SQL transaction.
func (r *Repository) heldOwnerWrite(ctx context.Context, fn func(queryer) error) error {
	if ctx == nil || fn == nil {
		return store.ErrNodeState
	}
	if held, present := ctx.Value(ownerControlContextKey{}).(*ownerControlContext); present {
		if held == nil || held.repository != r {
			return store.ErrNodeState
		}
		held.mu.RLock()
		defer held.mu.RUnlock()
		if held.closed || !validOwnerControlLease(held.lease) || held.lease.Check(ctx) != nil {
			return store.ErrNodeState
		}
		return r.write(ctx, func(q queryer) error {
			if r.checkOwnerControlMarker(ctx, q, held.lease) != nil {
				return store.ErrNodeState
			}
			if err := fn(q); err != nil {
				return err
			}
			if held.lease.Check(ctx) != nil {
				return store.ErrNodeState
			}
			return nil
		})
	}
	r.ownerControlMu.RLock()
	configured := r.ownerControlAcquire != nil
	r.ownerControlMu.RUnlock()
	if configured {
		return store.ErrNodeState
	}
	return r.write(ctx, func(q queryer) error {
		if r.checkOwnerControlMarker(ctx, q, nil) != nil {
			return store.ErrNodeState
		}
		return fn(q)
	})
}

// WithOwnerControlExclusive holds the same node-local lock as ingressWrite
// before a caller takes a media-volume lock. The context token is private to
// this repository and is checked on each use, including after release.
func (r *Repository) WithOwnerControlExclusive(ctx context.Context, fn func(context.Context) error) error {
	if ctx == nil || fn == nil {
		return store.ErrNodeState
	}
	if held, ok := ctx.Value(ownerControlContextKey{}).(*ownerControlContext); ok && held.repository == r {
		held.mu.RLock()
		closed := held.closed
		held.mu.RUnlock()
		if closed {
			return store.ErrNodeState
		}
		if !validOwnerControlLease(held.lease) || held.lease.Check(ctx) != nil {
			return store.ErrNodeState
		}
		if err := r.checkOwnerControlMarker(ctx, r.db, held.lease); err != nil {
			return err
		}
		return fn(ctx)
	}
	r.ownerControlMu.RLock()
	acquire := r.ownerControlAcquire
	r.ownerControlMu.RUnlock()
	if acquire == nil {
		if err := r.checkOwnerControlMarker(ctx, r.db, nil); err != nil {
			return err
		}
		return fn(ctx)
	}
	lease, err := acquire(ctx, true)
	if err != nil || !validOwnerControlLease(lease) {
		if validOwnerControlLease(lease) {
			lease.Release()
		}
		return store.ErrNodeState
	}
	defer lease.Release()
	if lease.Check(ctx) != nil {
		return store.ErrNodeState
	}
	if err := r.checkOwnerControlMarker(ctx, r.db, lease); err != nil {
		return err
	}
	held := &ownerControlContext{repository: r, lease: lease}
	defer func() {
		held.mu.Lock()
		held.closed = true
		held.mu.Unlock()
	}()
	derived := context.WithValue(ctx, ownerControlContextKey{}, held)
	if err := fn(derived); err != nil {
		return err
	}
	if lease.Check(derived) != nil {
		return store.ErrNodeState
	}
	return nil
}

// ConfigureOwnerControlFence is startup-only, before serving requests or
// starting any writer. No production startup installs it until all processes
// and recovery paths enforce the same local fence and DATA_ROOT ownership.
func (r *Repository) ConfigureOwnerControlFence(acquire func(context.Context, bool) (store.OwnerControlLease, error)) error {
	if acquire == nil {
		return store.ErrNodeState
	}
	r.ownerControlMu.Lock()
	defer r.ownerControlMu.Unlock()
	if r.ownerControlAcquire != nil {
		return store.ErrNodeState
	}
	r.ownerControlAcquire = acquire
	return nil
}

// InitializeOwnerControlMarker is an explicit offline-only operation. The
// caller must already hold the native maintenance fence with all writers
// stopped. It never creates the local lock or repairs a mismatched marker.
func (r *Repository) InitializeOwnerControlMarker(ctx context.Context) error {
	if ctx == nil {
		return store.ErrNodeState
	}
	r.ownerControlMu.RLock()
	acquire := r.ownerControlAcquire
	r.ownerControlMu.RUnlock()
	if acquire == nil {
		return store.ErrNodeState
	}
	lease, err := acquire(ctx, true)
	if err != nil || !validOwnerControlLease(lease) {
		if validOwnerControlLease(lease) {
			lease.Release()
		}
		return store.ErrNodeState
	}
	defer lease.Release()
	tag, err := lease.Binding(ctx)
	if err != nil || len(tag) != 64 {
		return store.ErrNodeState
	}
	return r.ingressWriteSQL(ctx, func(q queryer) error {
		var existing string
		err := q.QueryRowContext(ctx, "SELECT fence_tag FROM sealed_tree_owner_fence WHERE singleton=1").Scan(&existing)
		if engineErr := r.verifyOwnerFenceEngine(ctx, q); engineErr != nil {
			return engineErr
		}
		if errors.Is(err, sql.ErrNoRows) {
			if _, err = q.ExecContext(ctx, "INSERT INTO sealed_tree_owner_fence(singleton,fence_tag) VALUES(1,?)", tag); err != nil {
				return err
			}
		} else if err != nil || existing != tag {
			return store.ErrNodeState
		}
		current, err := lease.Binding(ctx)
		if err != nil || current != tag {
			return store.ErrNodeState
		}
		return nil
	})
}

// AcquireOwnerControlShared is available to the owner handler only after the
// caller has installed the local fence. The returned OS lease survives SQL
// connection loss; marker verification is not protection from raw SQL writers.
func (r *Repository) AcquireOwnerControlShared(ctx context.Context) (store.OwnerControlLease, error) {
	if ctx == nil {
		return nil, store.ErrNodeState
	}
	if held, ok := ctx.Value(ownerControlContextKey{}).(*ownerControlContext); ok {
		if held == nil || held.repository != r {
			return nil, store.ErrNodeState
		}
		borrow := &borrowedOwnerControlLease{parent: held}
		held.mu.RLock()
		if held.closed || !validOwnerControlLease(held.lease) {
			held.mu.RUnlock()
			return nil, store.ErrNodeState
		}
		tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err == nil {
			err = r.checkOwnerControlMarker(ctx, tx, held.lease)
			if err == nil {
				err = held.lease.Check(ctx)
			}
			if err == nil {
				err = tx.Commit()
			} else {
				_ = tx.Rollback()
			}
		}
		held.mu.RUnlock()
		if err != nil || borrow.Check(ctx) != nil {
			borrow.Release()
			return nil, store.ErrNodeState
		}
		return borrow, nil
	}
	r.ownerControlMu.RLock()
	acquire := r.ownerControlAcquire
	r.ownerControlMu.RUnlock()
	if acquire == nil {
		return nil, store.ErrNodeState
	}
	lease, err := acquire(ctx, false)
	if err != nil || !validOwnerControlLease(lease) {
		if validOwnerControlLease(lease) {
			lease.Release()
		}
		return nil, store.ErrNodeState
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err == nil {
		err = r.checkOwnerControlMarker(ctx, tx, lease)
		if err == nil {
			err = lease.Check(ctx)
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}
	if err != nil {
		lease.Release()
		return nil, store.ErrNodeState
	}
	return lease, nil
}

// Reserve at least half of a bounded pool for normal business work. Waiting
// readers do not take connections. A one-connection pool cannot safely serve a
// request while its lease is held and therefore fails closed.
func (r *Repository) reserveIngressReader(ctx context.Context) (func(), error) {
	for {
		r.ingressReadersMu.Lock()
		limit := 8
		if max := r.db.Stats().MaxOpenConnections; max > 0 && max/2 < limit {
			limit = max / 2
		}
		if limit == 0 {
			r.ingressReadersMu.Unlock()
			return nil, store.ErrNodeState
		}
		if r.ingressReaders < limit {
			r.ingressReaders++
			r.ingressReadersMu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					r.ingressReadersMu.Lock()
					r.ingressReaders--
					if r.ingressReadersWake != nil {
						close(r.ingressReadersWake)
						r.ingressReadersWake = nil
					}
					r.ingressReadersMu.Unlock()
				})
			}, nil
		}
		if r.ingressReadersWake == nil {
			r.ingressReadersWake = make(chan struct{})
		}
		wake := r.ingressReadersWake
		r.ingressReadersMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wake:
		}
	}
}

// mysqlIngressReadLease keeps the connection owning the shared row lock until
// the caller either commits the admission or abandons it. No SQL is executed
// on the transaction between its checked locking reads and Commit: a failed
// operation could otherwise roll the whole transaction back while leaving the
// session alive. Commit uses that same connection without database/sql retry.
type mysqlIngressReadLease struct {
	mu        sync.Mutex
	done      bool
	tx        *sql.Tx
	conn      *sql.Conn
	cancel    context.CancelFunc
	unreserve func()
}

func (l *mysqlIngressReadLease) Commit() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return store.ErrNodeState
	}
	l.done = true
	err := l.tx.Commit()
	l.cancel()
	_ = l.conn.Close()
	l.unreserve()
	return err
}

func (l *mysqlIngressReadLease) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return
	}
	l.done = true
	_ = l.tx.Rollback()
	l.cancel()
	_ = l.conn.Close()
	l.unreserve()
}

// The transaction's lifetime is detached from request cancellation once the
// lock is held: a disconnected client can still have a handler unwinding. The
// caller's deferred release ends the transaction; a process crash closes it.
func (r *Repository) acquireMySQLIngressLease(ctx context.Context) (store.PublicIngress, *mysqlIngressReadLease, error) {
	unreserve, err := r.reserveIngressReader(ctx)
	if err != nil {
		return store.PublicIngress{}, nil, err
	}
	if _, err = r.ExistingPublicIngress(ctx); err != nil {
		unreserve()
		return store.PublicIngress{}, nil, err
	}
	for {
		conn, err := r.db.Conn(ctx)
		if err != nil {
			unreserve()
			return store.PublicIngress{}, nil, err
		}
		txContext, cancel := context.WithCancel(context.WithoutCancel(ctx))
		stop := context.AfterFunc(ctx, cancel)
		tx, err := conn.BeginTx(txContext, nil)
		var current store.PublicIngress
		if err == nil {
			err = tx.QueryRowContext(ctx, "SELECT node_id,public_origin,generation FROM public_ingress_config WHERE singleton=1 FOR SHARE NOWAIT").Scan(&current.NodeID, &current.PublicOrigin, &current.Generation)
		}
		if err == nil {
			err = verifyIngressEngine(ctx, tx)
		}
		var identityID, role string
		if err == nil {
			err = tx.QueryRowContext(ctx, "SELECT node_id,`role` FROM node_identity WHERE singleton=1").Scan(&identityID, &role)
		}
		if err == nil && (role != "Master" || !nodeIDPattern.MatchString(identityID) || !nodeIDPattern.MatchString(current.NodeID) || !validPublicOrigin(current.PublicOrigin) || current.Generation < 1 || r.configuredPublicOrigin() == "" || current.NodeID == identityID && current.PublicOrigin != r.configuredPublicOrigin() || current.NodeID != identityID && !r.peerIngressEnabled.Load()) {
			err = store.ErrNodeState
		}
		if err == nil && current.NodeID != identityID {
			if validateActivePeerIngress(ctx, tx, current.NodeID, current.PublicOrigin) != nil {
				err = store.ErrNodeState
			}
		}
		stopped := stop()
		if err == nil && (!stopped || ctx.Err() != nil) {
			err = ctx.Err()
			if err == nil {
				err = context.Canceled
			}
		}
		if err == nil {
			return current, &mysqlIngressReadLease{tx: tx, conn: conn, cancel: cancel, unreserve: unreserve}, nil
		}
		if tx != nil {
			_ = tx.Rollback()
		}
		cancel()
		_ = conn.Close()
		if !mysqlIngressBusy(err) {
			unreserve()
			return store.PublicIngress{}, nil, err
		}
		if err = waitIngressRetry(ctx); err != nil {
			unreserve()
			return store.PublicIngress{}, nil, err
		}
	}
}

// A local file lease cannot be silently released by a database disconnect.
// Admission linearizes while the process still holds its shared OS lock.
type sqliteIngressReadLease struct {
	mu      sync.Mutex
	done    bool
	release func()
}

func (l *sqliteIngressReadLease) Commit() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return store.ErrNodeState
	}
	l.done = true
	l.release()
	return nil
}

func (l *sqliteIngressReadLease) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.done {
		l.done = true
		l.release()
	}
}
