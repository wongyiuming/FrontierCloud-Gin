// Package maintenance fences native processes sharing one local DATA_ROOT.
// It is not proof that legacy or remote database writers have stopped.
package maintenance

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
)

const Marker = ".frontiercloud-native-maintenance"

// OwnerImportHold prevents an ordinary resume or restart while a stopped
// storage Owner has an unfinished legacy-media import. It contains no paths,
// keys or other media metadata.
const OwnerImportHold = ".frontiercloud-owner-import-hold"
const markerContent = "frontiercloud-native-maintenance-v1\n"
const runtimeLock = ".native-runtime.lock"
const controlLock = ".native-maintenance-control.lock"

var ErrEnabled = errors.New("native runtime maintenance is enabled")
var ErrState = errors.New("unsafe native maintenance state")

type Gate struct{ root *os.Root }

func Open(directory string) (*Gate, error) {
	if directory == "" {
		return nil, ErrState
	}
	if err := os.MkdirAll(directory, 0750); err != nil {
		return nil, err
	}
	return OpenExisting(directory)
}

// OpenExisting only opens a previously initialized data directory.
func OpenExisting(directory string) (*Gate, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrState
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	return &Gate{root}, nil
}
func (g *Gate) Close() error { return g.root.Close() }

// SerializeBootstrap keeps fresh-state detection and initialization under the
// same lock before any serve process acquires a shared runtime lease.
func (g *Gate) SerializeBootstrap(ctx context.Context, bootstrap func(context.Context) error) error {
	release, err := g.lease(ctx, ".native-bootstrap.lock", true)
	if err != nil {
		return err
	}
	defer release()
	return bootstrap(ctx)
}

func (g *Gate) lease(ctx context.Context, name string, exclusive bool) (func(), error) {
	release, _, err := g.leaseChecked(ctx, name, exclusive)
	return release, err
}

func (g *Gate) leaseChecked(ctx context.Context, name string, exclusive bool) (func(), func() error, error) {
	return g.leaseCheckedFile(ctx, name, exclusive, false)
}

func (g *Gate) leaseCheckedFile(ctx context.Context, name string, exclusive, existing bool) (func(), func() error, error) {
	if info, err := g.root.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return nil, nil, ErrState
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	var f *os.File
	var err error
	if existing {
		f, err = g.root.Open(name)
	} else {
		f, err = g.root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	}
	if err != nil {
		return nil, nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	current, err := g.root.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		f.Close()
		return nil, nil, ErrState
	}
	if !existing {
		if err := fsutil.InheritOwner(f, g.root); err != nil {
			f.Close()
			return nil, nil, err
		}
	}
	release, err := filelease.Acquire(ctx, f, exclusive)
	if err != nil {
		return nil, nil, err
	}
	check := func() error {
		current, e := g.root.Lstat(name)
		if e != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
			return ErrState
		}
		actual, e := f.Stat()
		if e != nil || !actual.Mode().IsRegular() || !os.SameFile(opened, actual) {
			return ErrState
		}
		return nil
	}
	if err = check(); err != nil {
		release()
		return nil, nil, err
	}
	return release, check, nil
}

// Any unexpected marker type/content fails closed, including directories and
// inside-root symlinks. UI force-open flags are not consulted by this gate.
func (g *Gate) Enabled() (bool, error) {
	info, err := g.root.Lstat(Marker)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(markerContent)) {
		return true, ErrState
	}
	f, err := g.root.Open(Marker)
	if err != nil {
		return true, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return true, ErrState
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(len(markerContent))+1))
	if err != nil {
		return true, err
	}
	if string(data) != markerContent {
		return true, ErrState
	}
	return true, nil
}
func (g *Gate) enable() error {
	if enabled, err := g.Enabled(); err != nil {
		return err
	} else if enabled {
		f, err := g.root.OpenFile(Marker, os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		return errors.Join(f.Sync(), f.Close(), fsutil.SyncDirectory(g.root, "."))
	}
	f, err := g.root.OpenFile(Marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := fsutil.InheritOwner(f, g.root); err != nil {
		f.Close()
		return err
	}
	_, writeErr := f.WriteString(markerContent)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return errors.Join(writeErr, f.Close(), fsutil.SyncDirectory(g.root, "."))
}

// Enter persists the fence BEFORE waiting for runtime leases. Timeout/cancel or
// a failed callback leaves the fence enabled. Proof is valid only while the
// exclusive lease is held; no runtime can start between drain and callback.
func (g *Gate) Enter(ctx context.Context, offline func(context.Context) error) error {
	if offline == nil {
		return ErrState
	}
	release, err := g.lease(ctx, controlLock, true)
	if err != nil {
		return err
	}
	defer release()
	if err := g.enable(); err != nil {
		return err
	}
	return g.offline(ctx, offline)
}
func (g *Gate) Inspect(ctx context.Context, offline func(context.Context) error) error {
	release, err := g.lease(ctx, controlLock, true)
	if err != nil {
		return err
	}
	defer release()
	return g.offline(ctx, offline)
}

// InspectSQLite holds the existing offline maintenance fence while checking
// that a regular SQLite database belongs to this DATA_ROOT. It is a local
// cooperative-process fence, not protection against raw SQL or other hosts.
func (g *Gate) InspectSQLite(ctx context.Context, dataRoot, databasePath string, offline func(context.Context, func() error) error) error {
	return g.inspectSQLite(ctx, dataRoot, databasePath, offline, false)
}

// InspectExistingSQLite holds the same exclusive offline fence, opening only
// its existing lock files and leaving their contents untouched.
func (g *Gate) InspectExistingSQLite(ctx context.Context, dataRoot, databasePath string, offline func(context.Context, func() error) error) error {
	return g.inspectSQLite(ctx, dataRoot, databasePath, offline, true)
}

func (g *Gate) inspectSQLite(ctx context.Context, dataRoot, databasePath string, offline func(context.Context, func() error) error, existing bool) error {
	if offline == nil {
		return ErrState
	}
	return g.withSQLiteFence(ctx, dataRoot, databasePath, func(held context.Context, check func() error) error {
		if err := offline(held, check); err != nil {
			return err
		}
		return check()
	}, existing)
}

func (g *Gate) withSQLiteFence(ctx context.Context, dataRoot, databasePath string, offline func(context.Context, func() error) error, existing bool) error {
	if g == nil || g.root == nil || ctx == nil || offline == nil || dataRoot == "" || databasePath == "" {
		return ErrState
	}
	releaseControl, checkControl, err := g.leaseCheckedFile(ctx, controlLock, true, existing)
	if err != nil {
		return err
	}
	defer releaseControl()
	if enabled, e := g.Enabled(); e != nil || !enabled {
		return ErrState
	}
	releaseRuntime, checkRuntime, err := g.leaseCheckedFile(ctx, runtimeLock, true, existing)
	if err != nil {
		return err
	}
	defer releaseRuntime()
	var pinned, pinnedMarker os.FileInfo
	check := func() error {
		if checkControl() != nil || checkRuntime() != nil || ctx.Err() != nil {
			return ErrState
		}
		for _, name := range []string{controlLock, runtimeLock} {
			info, e := g.root.Lstat(name)
			if e != nil || !privateSingleLink(info) {
				return ErrState
			}
		}
		enabled, err := g.Enabled()
		if err != nil || !enabled {
			return ErrState
		}
		marker, err := g.root.Lstat(Marker)
		if err != nil || !privateSingleLink(marker) {
			return ErrState
		}
		if pinnedMarker == nil {
			pinnedMarker = marker
		} else if !os.SameFile(pinnedMarker, marker) {
			return ErrState
		}
		rootPath, err := filepath.Abs(g.root.Name())
		if err != nil {
			return ErrState
		}
		expectedRoot, err := filepath.Abs(dataRoot)
		if err != nil || filepath.Clean(expectedRoot) != filepath.Clean(rootPath) {
			return ErrState
		}
		rootInfo, err := os.Lstat(rootPath)
		if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
			return ErrState
		}
		openedRoot, err := g.root.Stat(".")
		if err != nil || !os.SameFile(rootInfo, openedRoot) {
			return ErrState
		}
		absolute, err := filepath.Abs(databasePath)
		if err != nil {
			return ErrState
		}
		relative, err := filepath.Rel(rootPath, absolute)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return ErrState
		}
		canonicalRoot, err := filepath.EvalSymlinks(rootPath)
		if err != nil {
			return ErrState
		}
		canonicalDB, err := filepath.EvalSymlinks(absolute)
		if err != nil || filepath.Clean(canonicalDB) != filepath.Join(canonicalRoot, relative) {
			return ErrState
		}
		info, err := os.Lstat(absolute)
		if err != nil || !privateSingleLink(info) {
			return ErrState
		}
		opened, err := g.root.Open(relative)
		if err != nil {
			return ErrState
		}
		defer opened.Close()
		current, err := opened.Stat()
		if err != nil || !privateSingleLink(current) || !os.SameFile(info, current) {
			return ErrState
		}
		if pinned == nil {
			pinned = current
		} else if !os.SameFile(pinned, current) {
			return ErrState
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	return offline(ctx, check)
}
func (g *Gate) offline(ctx context.Context, offline func(context.Context) error) error {
	if offline == nil {
		return ErrState
	}
	if enabled, err := g.Enabled(); err != nil {
		return err
	} else if !enabled {
		return ErrState
	}
	release, err := g.lease(ctx, runtimeLock, true)
	if err != nil {
		return err
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return err
	}
	return offline(ctx)
}

// Resume does not discard any intent or create recovery authority. Its check
// runs while stopped; rejection keeps the persistent fence closed.
func (g *Gate) Resume(ctx context.Context, check func(context.Context) error) error {
	release, err := g.lease(ctx, controlLock, true)
	if err != nil {
		return err
	}
	defer release()
	return g.offline(ctx, func(ctx context.Context) error {
		if check == nil {
			return ErrState
		}
		if err := g.checkResumeHolds(); err != nil {
			return err
		}
		if err := check(ctx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return g.clearOfflineMarker()
	})
}

// ResumeExistingSQLite verifies the pinned database and existing maintenance
// locks through native marker removal. The caller's check runs under both
// locks and must keep any dependent admission lease until this call returns.
func (g *Gate) ResumeExistingSQLite(ctx context.Context, dataRoot, databasePath string, validate func(context.Context, func() error) error) error {
	if validate == nil {
		return ErrState
	}
	return g.withSQLiteFence(ctx, dataRoot, databasePath, func(held context.Context, check func() error) error {
		if err := g.checkResumeHolds(); err != nil {
			return err
		}
		if err := validate(held, check); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		if err := g.checkResumeHolds(); err != nil {
			return err
		}
		return g.clearOfflineMarker()
	}, true)
}

func (g *Gate) checkResumeHolds() error {
	if held, err := g.ownerImportHeld(); err != nil || held {
		return ErrState
	}
	if held, err := g.TreeRecoveryHeld(); err != nil || held {
		return ErrState
	}
	return nil
}

func (g *Gate) clearOfflineMarker() error {
	if err := g.root.Remove(Marker); err != nil {
		return err
	}
	if err := fsutil.SyncDirectory(g.root, "."); err != nil {
		// A failed durability acknowledgement must not leave a knowingly open
		// gate. Best-effort re-fence and surface both failures.
		return errors.Join(err, g.enable())
	}
	return nil
}

type Runtime struct {
	gate     *Gate
	ctx      context.Context
	cancel   context.CancelCauseFunc
	release  func()
	done     chan struct{}
	mu       sync.Mutex
	stopping bool
	requests sync.WaitGroup
	once     sync.Once
}

// Runtime covers the ENTIRE native lifecycle, including initialization,
// startup recovery, HTTP, worker shutdown and resource closure. Caller must
// join workers and close resources before Close releases the process lease.
func (g *Gate) Runtime(parent context.Context) (*Runtime, error) {
	release, err := g.lease(parent, runtimeLock, false)
	if err != nil {
		return nil, err
	}
	if enabled, err := g.Enabled(); err != nil || enabled {
		release()
		if err != nil {
			return nil, err
		}
		return nil, ErrEnabled
	}
	if held, err := g.ownerImportHeld(); err != nil || held {
		release()
		return nil, ErrState
	}
	if held, err := g.TreeRecoveryHeld(); err != nil || held {
		release()
		return nil, ErrState
	}
	ctx, cancel := context.WithCancelCause(parent)
	r := &Runtime{gate: g, ctx: ctx, cancel: cancel, release: release, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		timer := time.NewTicker(100 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				enabled, err := g.Enabled()
				if err != nil {
					cancel(err)
					return
				}
				if enabled {
					cancel(ErrEnabled)
					return
				}
			}
		}
	}()
	return r, nil
}
func (r *Runtime) Context() context.Context { return r.ctx }
func (r *Runtime) Stop()                    { r.mu.Lock(); r.stopping = true; r.mu.Unlock(); r.cancel(context.Canceled) }
func (r *Runtime) WaitHTTP()                { r.requests.Wait() }
func (r *Runtime) Close()                   { r.once.Do(func() { r.Stop(); <-r.done; r.WaitHTTP(); r.release() }) }

func (r *Runtime) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.mu.Lock()
		enabled, err := r.gate.Enabled()
		blocked := r.stopping || r.ctx.Err() != nil || enabled || err != nil
		if !blocked {
			r.requests.Add(1)
		}
		r.mu.Unlock()
		if blocked {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "5")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "{\"detail\":\"Native runtime is in maintenance\"}\n")
			return
		}
		defer r.requests.Done()
		ctx, cancel := context.WithCancel(q.Context())
		stop := context.AfterFunc(r.ctx, cancel)
		defer stop()
		defer cancel()
		next.ServeHTTP(w, q.WithContext(ctx))
	})
}
