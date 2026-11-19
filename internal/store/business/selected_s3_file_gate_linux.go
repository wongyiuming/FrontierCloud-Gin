//go:build linux

package business

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const selectedS3LockDir = ".selected-s3-control"
const selectedS3Stripes = 16

// SelectedS3FileGate uses pre-existing, fixed inode locks on the Master's
// local data volume. It does not prove that pending provider work was
// reconciled; startup must supply a real liveness/recovery check and config
// mutations must separately reject unresolved durable S3 intents.
type SelectedS3FileGate struct {
	root         *os.Root
	tree         *sealedtree.SQLStore
	dir          *os.File
	dirInfo      os.FileInfo
	uid          uint32
	gid          uint32
	files        map[string]os.FileInfo
	live         func(context.Context) error
	proofMu      sync.RWMutex
	adminOrigin  string
	publicOrigin string
	proofs       map[string]selectedS3OriginProof
	modeMu       sync.Mutex
	recovery     *selectedS3Recovery
	closing      bool
	closed       bool
	starting     bool
	started      bool
	startDone    chan struct{}
}

type selectedS3OriginProof struct {
	location           store.S3Location
	credential         [32]byte
	credentialRevision int64
}

type selectedS3FileLease struct {
	gate     *SelectedS3FileGate
	files    []*selectedS3HeldFile
	once     sync.Once
	released bool
	mu       sync.Mutex
	borrow   *selectedS3RecoveryBorrow
}

type selectedS3HeldFile struct {
	name    string
	file    *os.File
	release func()
}

func selectedS3LockNames() []string {
	names := []string{"control.lock"}
	for n := 0; n < selectedS3Stripes; n++ {
		names = append(names, fmt.Sprintf("stripe-%02x.lock", n))
	}
	return names
}

func selectedS3Owned(info os.FileInfo, directory bool, uid, gid uint32) bool {
	if info == nil || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || directory && (!info.IsDir() || info.Mode().Perm() != 0700) || !directory && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600) {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid && st.Gid == gid && (directory || st.Nlink == 1)
}

func selectedS3RootOwner(root *os.Root) (uint32, uint32, error) {
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() {
		return 0, 0, store.ErrNodeState
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, store.ErrNodeState
	}
	return st.Uid, st.Gid, nil
}

// PrepareSelectedS3FileGate creates only the fixed lock inodes. It must run
// offline under the actual maintenance lock for the fresh Master data root;
// check must prove that authority before and after creation. Existing files
// are never replaced or unlinked, and an unexpected inode fails closed.
func PrepareSelectedS3FileGate(root *os.Root, check func() error) error {
	if root == nil || check == nil || check() != nil {
		return store.ErrNodeState
	}
	uid, gid, err := selectedS3RootOwner(root)
	if err != nil {
		return err
	}
	createErr := root.Mkdir(selectedS3LockDir, 0700)
	created := createErr == nil
	if createErr != nil && !os.IsExist(createErr) {
		return createErr
	}
	info, err := root.Lstat(selectedS3LockDir)
	if err != nil || !info.IsDir() {
		return store.ErrNodeState
	}
	dir, err := root.Open(selectedS3LockDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return store.ErrNodeState
	}
	if created {
		if err = fsutil.InheritOwner(dir, root); err != nil {
			return err
		}
		info, err = dir.Stat()
		if err != nil {
			return err
		}
	}
	if !selectedS3Owned(info, true, uid, gid) {
		return store.ErrNodeState
	}
	for _, name := range selectedS3LockNames() {
		file, e := root.OpenFile(path.Join(selectedS3LockDir, name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if os.IsExist(e) {
			current, statErr := root.Lstat(path.Join(selectedS3LockDir, name))
			if statErr != nil || !selectedS3Owned(current, false, uid, gid) {
				return store.ErrNodeState
			}
			continue
		}
		if e != nil {
			return e
		}
		e = fsutil.InheritOwner(file, root)
		var stat os.FileInfo
		if e == nil {
			stat, e = file.Stat()
		}
		if e == nil && !selectedS3Owned(stat, false, uid, gid) {
			e = store.ErrNodeState
		}
		if e == nil {
			e = file.Sync()
		}
		closeErr := file.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	parent, err := root.Open(".")
	if err != nil {
		return err
	}
	if err = parent.Sync(); err != nil {
		parent.Close()
		return err
	}
	if err = parent.Close(); err != nil {
		return err
	}
	current, err := root.Lstat(selectedS3LockDir)
	if err != nil || !os.SameFile(info, current) {
		return store.ErrNodeState
	}
	return check()
}

// OpenSelectedS3FileGate never creates locks. Its root and tree must be the
// exact runtime-owned fresh Master data root and fenced SQLStore.
func OpenSelectedS3FileGate(root *os.Root, tree *sealedtree.SQLStore, live func(context.Context) error) (*SelectedS3FileGate, error) {
	if root == nil || tree == nil || live == nil {
		return nil, store.ErrNodeState
	}
	uid, gid, err := selectedS3RootOwner(root)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(selectedS3LockDir)
	if err != nil || !selectedS3Owned(info, true, uid, gid) {
		return nil, store.ErrNodeState
	}
	dir, err := root.Open(selectedS3LockDir)
	if err != nil {
		return nil, err
	}
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(info, opened) {
		dir.Close()
		return nil, store.ErrNodeState
	}
	g := &SelectedS3FileGate{root: root, tree: tree, dir: dir, dirInfo: info, uid: uid, gid: gid, files: make(map[string]os.FileInfo), live: live}
	for _, name := range selectedS3LockNames() {
		current, e := root.Lstat(path.Join(selectedS3LockDir, name))
		if e != nil || !selectedS3Owned(current, false, uid, gid) {
			dir.Close()
			return nil, store.ErrNodeState
		}
		g.files[name] = current
	}
	return g, nil
}

func (g *SelectedS3FileGate) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return g.CloseContext(ctx)
}

// ConfigureSelectedS3Origins installs the effective configured browser
// origins once at startup. Proofs are process-local and deliberately start
// empty after every restart, regardless of durable legacy probe state.
func (g *SelectedS3FileGate) ConfigureSelectedS3Origins(adminOrigin, publicOrigin string) error {
	if g == nil || !validPublicOrigin(adminOrigin) || !validPublicOrigin(publicOrigin) {
		return store.ErrNodeState
	}
	g.proofMu.Lock()
	defer g.proofMu.Unlock()
	if g.adminOrigin != "" || g.publicOrigin != "" || g.proofs != nil {
		return store.ErrNodeState
	}
	g.adminOrigin, g.publicOrigin = adminOrigin, publicOrigin
	g.proofs = make(map[string]selectedS3OriginProof)
	return nil
}

func (g *SelectedS3FileGate) CheckSelectedS3Member(ctx context.Context, tree *sealedtree.SQLStore, member store.S3Member) error {
	if g.valid(ctx, tree) != nil || member.ID == "" || member.Kind != "S3" || member.Transport != "S3" || member.RelationshipID != nil || member.CleanupOnly || member.SealedCredentials == "" || member.CredentialRevision < 1 || member.Revision < 1 || member.ProbeState != "ready" || member.ProbeRevision != member.Revision || member.CredentialExpiresAt != 0 && member.CredentialExpiresAt <= time.Now().Unix() {
		return store.ErrNodeState
	}
	g.proofMu.RLock()
	proof, found := g.proofs[member.ID]
	configured := g.adminOrigin != "" && g.publicOrigin != ""
	g.proofMu.RUnlock()
	if !configured || !found || proof.location != member.Location || proof.credentialRevision != member.CredentialRevision || proof.credential != sha256.Sum256([]byte(member.SealedCredentials)) {
		return store.ErrNodeState
	}
	return nil
}

// WithSelectedS3Probe excludes new selected S3 grants while one durable
// journaled probe checks both trusted origins. No Owner lock is held across
// provider I/O. A failed, cancelled or interrupted probe leaves no in-process
// proof; the journal remains authoritative for cleanup/retry.
func (g *SelectedS3FileGate) WithSelectedS3Probe(ctx context.Context, tree *sealedtree.SQLStore, id, adminOrigin, publicOrigin string, work func(context.Context) (store.S3Member, error)) (store.S3Member, error) {
	var zero store.S3Member
	if g.valid(ctx, tree) != nil || !nodeIDPattern.MatchString(id) || work == nil {
		return zero, store.ErrNodeState
	}
	g.proofMu.RLock()
	validOrigins := g.proofs != nil && g.adminOrigin == adminOrigin && validPublicOrigin(publicOrigin)
	g.proofMu.RUnlock()
	if !validOrigins {
		return zero, store.ErrNodeState
	}
	borrow, recovering, err := g.borrowRecovery(ctx, tree)
	if err != nil {
		return zero, err
	}
	var held *selectedS3HeldFile
	if recovering {
		defer borrow.release()
		held = borrow.recovery.control
		if borrow.recovery.probeMember(ctx, id) != nil {
			return zero, store.ErrNodeState
		}
	} else {
		held, err = g.acquire(ctx, "control.lock", true, false)
		if err != nil {
			return zero, err
		}
		defer held.release()
	}
	g.proofMu.Lock()
	if g.publicOrigin != publicOrigin {
		clear(g.proofs)
		g.publicOrigin = publicOrigin
	}
	delete(g.proofs, id)
	g.proofMu.Unlock()
	member, err := work(ctx)
	if err != nil {
		return zero, err
	}
	if g.valid(ctx, tree) != nil || g.checkFile(held) != nil || recovering && borrow.check(ctx) != nil || member.ID != id || member.Kind != "S3" || member.Transport != "S3" || member.RelationshipID != nil || member.CleanupOnly || member.SealedCredentials == "" || member.CredentialRevision < 1 || member.Revision < 1 || member.ProbeState != "ready" || member.ProbeRevision != member.Revision || member.CredentialExpiresAt != 0 && member.CredentialExpiresAt <= time.Now().Unix() {
		return zero, store.ErrNodeState
	}
	proof := selectedS3OriginProof{location: member.Location, credential: sha256.Sum256([]byte(member.SealedCredentials)), credentialRevision: member.CredentialRevision}
	g.proofMu.Lock()
	g.proofs[id] = proof
	g.proofMu.Unlock()
	return member, nil
}

func (g *SelectedS3FileGate) CheckSelectedS3PublicOrigin(ctx context.Context, tree *sealedtree.SQLStore, member store.S3Member, origin string) error {
	if g == nil {
		return store.ErrNodeState
	}
	g.proofMu.RLock()
	matches := g.publicOrigin != "" && g.publicOrigin == origin
	g.proofMu.RUnlock()
	if !matches {
		return store.ErrNodeState
	}
	return g.CheckSelectedS3Member(ctx, tree, member)
}

func (g *SelectedS3FileGate) CheckSelectedS3AdminOrigin(ctx context.Context, tree *sealedtree.SQLStore, member store.S3Member, origin string) error {
	if g == nil {
		return store.ErrNodeState
	}
	g.proofMu.RLock()
	matches := g.adminOrigin != "" && g.adminOrigin == origin
	g.proofMu.RUnlock()
	if !matches {
		return store.ErrNodeState
	}
	return g.CheckSelectedS3Member(ctx, tree, member)
}

func (g *SelectedS3FileGate) valid(ctx context.Context, tree *sealedtree.SQLStore) error {
	if g == nil || ctx == nil || tree == nil || tree != g.tree || g.live(ctx) != nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	current, err := g.root.Lstat(selectedS3LockDir)
	opened, e := g.dir.Stat()
	uid, gid, ownerErr := selectedS3RootOwner(g.root)
	if err != nil || e != nil || ownerErr != nil || uid != g.uid || gid != g.gid || !selectedS3Owned(current, true, g.uid, g.gid) || !os.SameFile(g.dirInfo, current) || !os.SameFile(g.dirInfo, opened) {
		return store.ErrNodeState
	}
	return nil
}

func (g *SelectedS3FileGate) acquire(ctx context.Context, name string, exclusive, nonblocking bool) (*selectedS3HeldFile, error) {
	want, ok := g.files[name]
	if !ok {
		return nil, store.ErrNodeState
	}
	file, err := g.root.OpenFile(path.Join(selectedS3LockDir, name), os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	actual, err := file.Stat()
	if err != nil || !selectedS3Owned(actual, false, g.uid, g.gid) || !os.SameFile(want, actual) {
		file.Close()
		return nil, store.ErrNodeState
	}
	var release func()
	if nonblocking {
		release, err = filelease.Try(file, exclusive)
	} else {
		release, err = filelease.Acquire(ctx, file, exclusive)
	}
	if err != nil {
		return nil, err
	}
	held := &selectedS3HeldFile{name: name, file: file, release: release}
	if err = g.checkFile(held); err != nil {
		release()
		return nil, err
	}
	return held, nil
}

func (g *SelectedS3FileGate) checkFile(held *selectedS3HeldFile) error {
	if held == nil {
		return store.ErrNodeState
	}
	want, ok := g.files[held.name]
	actual, e := held.file.Stat()
	current, err := g.root.Lstat(path.Join(selectedS3LockDir, held.name))
	if !ok || e != nil || err != nil || !selectedS3Owned(actual, false, g.uid, g.gid) || !selectedS3Owned(current, false, g.uid, g.gid) || !os.SameFile(want, actual) || !os.SameFile(want, current) {
		return store.ErrNodeState
	}
	return nil
}

func (l *selectedS3FileLease) Check(ctx context.Context) error {
	if l == nil {
		return store.ErrNodeState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released || l.gate.valid(ctx, l.gate.tree) != nil {
		return store.ErrNodeState
	}
	if l.borrow != nil && l.borrow.check(ctx) != nil {
		return store.ErrNodeState
	}
	for _, held := range l.files {
		if l.gate.checkFile(held) != nil {
			return store.ErrNodeState
		}
	}
	return nil
}
func (l *selectedS3FileLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.released = true
		for i := len(l.files) - 1; i >= 0; i-- {
			l.files[i].release()
		}
		if l.borrow != nil {
			l.borrow.release()
		}
	})
}

func (g *SelectedS3FileGate) acquireOperation(ctx context.Context, tree *sealedtree.SQLStore, upload string, striped bool) (SelectedUploadRuntimeLease, error) {
	if g.valid(ctx, tree) != nil || !nodeIDPattern.MatchString(upload) {
		return nil, store.ErrNodeState
	}
	if !striped && g.recoveryBlocked() {
		return nil, store.ErrNodeState
	}
	borrow, recovering, err := g.borrowRecovery(ctx, tree)
	if err != nil {
		return nil, err
	}
	lease := &selectedS3FileLease{gate: g, borrow: borrow}
	if recovering && !striped {
		borrow.release()
		return nil, store.ErrNodeState
	}
	if !recovering {
		control, e := g.acquire(ctx, "control.lock", false, false)
		if e != nil {
			return nil, e
		}
		lease.files = append(lease.files, control)
	}
	if striped {
		sum := sha256.Sum256([]byte(upload))
		stripe, e := g.acquire(ctx, fmt.Sprintf("stripe-%02x.lock", int(sum[0])%selectedS3Stripes), true, false)
		if e != nil {
			lease.Release()
			return nil, e
		}
		lease.files = append(lease.files, stripe)
	}
	if lease.Check(ctx) != nil {
		lease.Release()
		return nil, store.ErrNodeState
	}
	return lease, nil
}
func (g *SelectedS3FileGate) AcquireSelectedS3(ctx context.Context, tree *sealedtree.SQLStore, upload string) (SelectedUploadRuntimeLease, error) {
	return g.acquireOperation(ctx, tree, upload, true)
}
func (g *SelectedS3FileGate) AcquireSelectedS3Admission(ctx context.Context, tree *sealedtree.SQLStore, upload string) (SelectedUploadRuntimeLease, error) {
	return g.acquireOperation(ctx, tree, upload, false)
}

// WithSelectedS3Startup excludes all S3 operations while the caller checks
// durable state and installs the runtime. The callback must not reenter this
// gate; its database work follows Owner -> ingress -> tree lock order.
func (g *SelectedS3FileGate) WithSelectedS3Startup(ctx context.Context, tree *sealedtree.SQLStore, work func(context.Context) error) error {
	if work == nil || g.recoveryBlocked() || g.valid(ctx, tree) != nil {
		return store.ErrNodeState
	}
	held, err := g.acquire(ctx, "control.lock", true, false)
	if err != nil {
		return err
	}
	defer held.release()
	if g.valid(ctx, tree) != nil || g.checkFile(held) != nil {
		return store.ErrNodeState
	}
	if err = work(ctx); err != nil {
		return err
	}
	if g.valid(ctx, tree) != nil || g.checkFile(held) != nil {
		return store.ErrNodeState
	}
	return ctx.Err()
}

// WithSelectedS3ManagementRead holds the same shared control lease for
// read-only member listing or adding an entirely new disabled member. It must
// not be used for credential/location changes, probing, deletion or recovery.
func (g *SelectedS3FileGate) WithSelectedS3ManagementRead(ctx context.Context, tree *sealedtree.SQLStore, work func(context.Context) error) error {
	if work == nil {
		return store.ErrNodeState
	}
	lease, err := g.acquireOperation(ctx, tree, "00000000000000000000000000000000", false)
	if err != nil {
		return err
	}
	defer lease.Release()
	if err = work(ctx); err != nil {
		return err
	}
	return lease.Check(ctx)
}

// WithSelectedS3Listing is reserved for authenticated, read-only member
// listing. It does not authorize adding or changing configuration.
func (g *SelectedS3FileGate) WithSelectedS3Listing(ctx context.Context, tree *sealedtree.SQLStore, work func(context.Context) error) error {
	if work == nil {
		return store.ErrNodeState
	}
	borrow, recovering, err := g.borrowRecovery(ctx, tree)
	if err != nil {
		return err
	}
	if !recovering {
		return g.WithSelectedS3ManagementRead(ctx, tree, work)
	}
	defer borrow.release()
	if err = work(ctx); err != nil {
		return err
	}
	if g.valid(ctx, tree) != nil || borrow.check(ctx) != nil {
		return store.ErrNodeState
	}
	return nil
}

// Read checks are nonblocking: public admission already owns Owner/tree and
// must never wait on a config writer that may later need those same locks.
func (g *SelectedS3FileGate) checkRead(ctx context.Context, tree *sealedtree.SQLStore) error {
	if g.recoveryBlocked() || g.valid(ctx, tree) != nil {
		return store.ErrNodeState
	}
	held, err := g.acquire(ctx, "control.lock", false, true)
	if err != nil {
		return store.ErrNodeState
	}
	defer held.release()
	if g.valid(ctx, tree) != nil || g.checkFile(held) != nil {
		return store.ErrNodeState
	}
	return nil
}
func (g *SelectedS3FileGate) AuthorizeSelectedS3Read(ctx context.Context, tree *sealedtree.SQLStore, member store.S3Member, deadline int64) error {
	if deadline <= time.Now().Unix() || deadline > time.Now().Unix()+store.S3GrantSeconds {
		return store.ErrNodeState
	}
	if g.checkRead(ctx, tree) != nil {
		return store.ErrNodeState
	}
	return g.CheckSelectedS3Member(ctx, tree, member)
}
func (g *SelectedS3FileGate) CheckSelectedS3Read(ctx context.Context, tree *sealedtree.SQLStore, member store.S3Member, deadline int64) error {
	if deadline <= time.Now().Unix() {
		return store.ErrNodeState
	}
	if g.checkRead(ctx, tree) != nil {
		return store.ErrNodeState
	}
	return g.CheckSelectedS3Member(ctx, tree, member)
}
func (g *SelectedS3FileGate) CheckSelectedS3Catalog(ctx context.Context, tree *sealedtree.SQLStore, member store.S3Member) error {
	if g.checkRead(ctx, tree) != nil {
		return store.ErrNodeState
	}
	return g.CheckSelectedS3Member(ctx, tree, member)
}

// WithConfigurationDrain blocks new S3 operations and waits a full maximum
// bearer lifetime using a monotonic timer before invoking mutation. A caller
// must still authenticate all pending/uncertain journals and acquire the
// normal Owner/ingress transaction inside mutation. Cancellation or a crash
// discards the wait; any retry starts a full new interval.
func (g *SelectedS3FileGate) WithConfigurationDrain(ctx context.Context, tree *sealedtree.SQLStore, mutation func(context.Context) error) error {
	return g.withDrain(ctx, tree, time.Duration(store.S3GrantSeconds)*time.Second, mutation)
}
func (g *SelectedS3FileGate) withDrain(ctx context.Context, tree *sealedtree.SQLStore, duration time.Duration, mutation func(context.Context) error) error {
	if g.recoveryBlocked() || g.valid(ctx, tree) != nil || mutation == nil || duration < 0 {
		return store.ErrNodeState
	}
	held, err := g.acquire(ctx, "control.lock", true, false)
	if err != nil {
		return err
	}
	defer held.release()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	if g.valid(ctx, tree) != nil || g.checkFile(held) != nil {
		return store.ErrNodeState
	}
	if err = mutation(ctx); err != nil {
		return err
	}
	if g.valid(ctx, tree) != nil || g.checkFile(held) != nil {
		return store.ErrNodeState
	}
	return ctx.Err()
}
