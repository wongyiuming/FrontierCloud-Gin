//go:build linux && ledger_fixture

package preprodimport

// Isolated fixture ONLY. This deliberately bounded in-memory prototype is not
// registered with the product and is not the size or resource contract for a
// future real import. It proves neither source identity nor final publication.
import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"modernc.org/sqlite/vfs"
)

const fixtureSnapshotLimit int64 = 64 << 20
const fixtureSnapshotSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE

type immutableSnapshotFixture struct {
	mu        sync.Mutex
	root      *os.Root
	directory string
	name      string
	info      os.FileInfo
	source    *os.File
	sealed    *os.File
	adapter   *vfs.FS
	db        *sql.DB
	size      int64
	digest    [32]byte
	closed    bool
}

type immutableSnapshotFS struct {
	file *os.File
	size int64
}
type immutableSnapshotFile struct {
	*io.SectionReader
	info os.FileInfo
}

func (f immutableSnapshotFS) Open(name string) (fs.File, error) {
	if name != "snapshot.db" || f.file == nil {
		return nil, fs.ErrNotExist
	}
	info, err := f.file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != f.size {
		return nil, fs.ErrInvalid
	}
	return &immutableSnapshotFile{SectionReader: io.NewSectionReader(f.file, 0, f.size), info: info}, nil
}
func (f *immutableSnapshotFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *immutableSnapshotFile) Close() error               { return nil }

func fixtureSnapshotDigest(ctx context.Context, f *os.File, size int64, dst io.Writer) ([32]byte, error) {
	var result [32]byte
	if ctx == nil || f == nil || size < 100 || size > fixtureSnapshotLimit {
		return result, invalid("fixture snapshot size")
	}
	h := sha256.New()
	reader := io.NewSectionReader(f, 0, size)
	buf := make([]byte, 64<<10)
	defer clear(buf)
	for remaining := size; remaining > 0; {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		want := min(int64(len(buf)), remaining)
		n, err := io.ReadFull(reader, buf[:want])
		if err != nil || n != int(want) {
			return result, invalid("fixture snapshot read")
		}
		if _, err = h.Write(buf[:n]); err != nil {
			return result, err
		}
		if dst != nil {
			if written, e := dst.Write(buf[:n]); e != nil || written != n {
				return result, invalid("fixture snapshot copy")
			}
		}
		remaining -= int64(n)
	}
	copy(result[:], h.Sum(nil))
	return result, nil
}

func fixtureSnapshotNoSidecars(root *os.Root, name string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := root.Lstat(name + suffix); !errors.Is(err, os.ErrNotExist) {
			return invalid("fixture snapshot sidecar")
		}
	}
	return nil
}

// openImmutableSnapshotFixture is unregistered test code. The caller must
// provide a separately authenticated expected digest of a fully closed SQLite
// backup, not an arbitrary caller-asserted source authority.
func openImmutableSnapshotFixture(ctx context.Context, directory, name string, expected [32]byte) (_ *immutableSnapshotFixture, err error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || expected == [32]byte{} {
		return nil, invalid("fixture snapshot input")
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory {
		return nil, invalid("fixture snapshot directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	p := &immutableSnapshotFixture{root: root, directory: directory, name: name, digest: expected}
	defer func() {
		if err != nil {
			_ = p.closeLocked()
		}
	}()
	dirInfo, err := os.Lstat(directory)
	if err != nil || !privateOwned(dirInfo, true) {
		return nil, invalid("fixture snapshot directory")
	}
	openedDir, err := root.Stat(".")
	if err != nil || !os.SameFile(dirInfo, openedDir) || fixtureSnapshotNoSidecars(root, name) != nil {
		return nil, invalid("fixture snapshot directory changed")
	}
	info, err := root.Lstat(name)
	if err != nil || !privateOwned(info, false) || info.Size() < 100 || info.Size() > fixtureSnapshotLimit {
		return nil, invalid("fixture snapshot file")
	}
	if n, ok := stagePublishLinkCount(info); !ok || n != 1 {
		return nil, invalid("fixture snapshot links")
	}
	p.source, err = root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := p.source.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, invalid("fixture snapshot replaced")
	}
	p.info, p.size = opened, opened.Size()
	fd, err := unix.MemfdCreate("frontiercloud-snapshot-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, invalid("fixture memfd")
	}
	p.sealed = os.NewFile(uintptr(fd), "snapshot-fixture")
	actual, err := fixtureSnapshotDigest(ctx, p.source, p.size, p.sealed)
	if err != nil || subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
		return nil, invalid("fixture snapshot digest")
	}
	header := make([]byte, 100)
	if _, err = p.sealed.ReadAt(header, 0); err != nil || string(header[:16]) != "SQLite format 3\x00" || header[18] != 1 || header[19] != 1 {
		return nil, invalid("fixture snapshot journal mode")
	}
	if _, err = unix.FcntlInt(p.sealed.Fd(), unix.F_ADD_SEALS, fixtureSnapshotSeals); err != nil {
		return nil, invalid("fixture snapshot seal")
	}
	if value, e := unix.FcntlInt(p.sealed.Fd(), unix.F_GET_SEALS, 0); e != nil || value&fixtureSnapshotSeals != fixtureSnapshotSeals {
		return nil, invalid("fixture snapshot seal")
	}
	if err = p.check(ctx); err != nil {
		return nil, err
	}
	vfsName, adapter, err := vfs.New(immutableSnapshotFS{file: p.sealed, size: p.size})
	if err != nil {
		return nil, err
	}
	p.adapter = adapter
	p.db, err = sql.Open("sqlite", "file:snapshot.db?vfs="+vfsName+"&mode=ro&immutable=1")
	if err != nil {
		return nil, err
	}
	p.db.SetMaxOpenConns(1)
	if _, err = p.db.ExecContext(ctx, `PRAGMA query_only=ON`); err != nil {
		return nil, invalid("fixture snapshot SQLite")
	}
	var check string
	if err = p.db.QueryRowContext(ctx, `PRAGMA quick_check(1)`).Scan(&check); err != nil || check != "ok" {
		return nil, invalid("fixture snapshot integrity")
	}
	if err = p.check(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *immutableSnapshotFixture) check(ctx context.Context) error {
	if p == nil || p.closed || p.root == nil || p.source == nil || p.sealed == nil || ctx == nil || ctx.Err() != nil {
		return invalid("fixture snapshot closed")
	}
	sealedInfo, err := p.sealed.Stat()
	if err != nil || !sealedInfo.Mode().IsRegular() || sealedInfo.Size() != p.size {
		return invalid("fixture snapshot seal")
	}
	if seals, e := unix.FcntlInt(p.sealed.Fd(), unix.F_GET_SEALS, 0); e != nil || seals&fixtureSnapshotSeals != fixtureSnapshotSeals {
		return invalid("fixture snapshot seal")
	}
	dir, err := os.Lstat(p.directory)
	if err != nil || !privateOwned(dir, true) {
		return invalid("fixture snapshot directory")
	}
	openedDir, err := p.root.Stat(".")
	if err != nil || !os.SameFile(dir, openedDir) || fixtureSnapshotNoSidecars(p.root, p.name) != nil {
		return invalid("fixture snapshot directory changed")
	}
	current, err := p.root.Lstat(p.name)
	if err != nil || !privateOwned(current, false) || !os.SameFile(current, p.info) || current.Size() != p.size {
		return invalid("fixture snapshot changed")
	}
	if n, ok := stagePublishLinkCount(current); !ok || n != 1 {
		return invalid("fixture snapshot links")
	}
	opened, err := p.source.Stat()
	if err != nil || !os.SameFile(opened, p.info) || opened.Size() != p.size {
		return invalid("fixture snapshot changed")
	}
	actual, err := fixtureSnapshotDigest(ctx, p.source, p.size, nil)
	if err != nil || subtle.ConstantTimeCompare(actual[:], p.digest[:]) != 1 {
		return invalid("fixture snapshot digest")
	}
	return nil
}

// inspect executes an isolated read with pre/post checks. It returns no runtime
// authorization and cannot substitute for source, owner or transaction fences.
func (p *immutableSnapshotFixture) inspect(ctx context.Context, read func(*sql.Tx) error) error {
	if p == nil || read == nil {
		return invalid("fixture snapshot read")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx); err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = read(tx); err != nil {
		return err
	}
	if err = p.check(ctx); err != nil {
		return err
	}
	return tx.Rollback()
}

func (p *immutableSnapshotFixture) closeLocked() error {
	if p == nil || p.closed {
		return nil
	}
	p.closed = true
	var errs []error
	if p.db != nil {
		errs = append(errs, p.db.Close())
	}
	if p.adapter != nil {
		errs = append(errs, p.adapter.Close())
	}
	if p.sealed != nil {
		errs = append(errs, p.sealed.Close())
	}
	if p.source != nil {
		errs = append(errs, p.source.Close())
	}
	if p.root != nil {
		errs = append(errs, p.root.Close())
	}
	return errors.Join(errs...)
}
func (p *immutableSnapshotFixture) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeLocked()
}
