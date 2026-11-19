package checkpoint

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

const maxFileBytes = int64(256 * 1024 * 1024)
const maxTotalBytes = int64(512 * 1024 * 1024)

// Source retains existing Master identity/key authority. Recovery points do not
// replace the separately protected deployment identity or media resources.
type Source struct {
	DB                           *sql.DB
	Tree                         *sealedtree.SQLStore
	Vault                        *vault.Vault
	MediaRoot, Scratch, MasterID string
}

func (s *Source) Write(ctx context.Context, generation int64, out io.Writer) error {
	if s == nil || s.DB == nil || s.Tree == nil || s.Vault == nil || !filepath.IsAbs(s.Scratch) || !filepath.IsAbs(s.MediaRoot) {
		return ErrCheckpoint
	}
	lease, e := s.Tree.AcquireReadFence(ctx)
	if e != nil {
		return e
	}
	defer lease.Release()
	if e = lease.Check(ctx); e != nil {
		return e
	}

	var pages, pageSize int64
	if s.DB.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil || s.DB.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize) != nil || pages < 1 || pageSize < 1 || pages > maxFileBytes/pageSize {
		return ErrCheckpoint
	}
	estimated := pages * pageSize
	if e = s.Tree.CheckpointLyricBlobs(ctx, lease, s.MasterID, func(p sealedtree.Placement) error {
		if estimated > maxTotalBytes-p.Bytes {
			return ErrCheckpoint
		}
		estimated += p.Bytes
		return nil
	}); e != nil {
		return e
	}
	scratchInfo, e := os.Lstat(s.Scratch)
	if e != nil || !scratchInfo.IsDir() || scratchInfo.Mode()&os.ModeSymlink != 0 || scratchInfo.Mode().Perm() != 0700 {
		return ErrCheckpoint
	}
	scratchRoot, e := os.OpenRoot(s.Scratch)
	if e != nil {
		return e
	}
	_, free, e := fsutil.DiskUsage(scratchRoot)
	scratchRoot.Close()
	if e != nil {
		return e
	}
	if free < 1024*1024*1024+2*estimated+64*1024*1024 {
		return store.ErrBackupBusy
	}
	// SQLite creates one consistent database image; no live database file/WAL is
	// copied. The shared tree fence keeps logical/blob publication stable.
	stage, e := os.MkdirTemp(s.Scratch, "checkpoint-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	snapshot := filepath.Join(stage, "database.sqlite")
	if _, e = s.DB.ExecContext(ctx, "VACUUM main INTO ?", snapshot); e != nil {
		return e
	}
	if e = os.Chmod(snapshot, 0600); e != nil {
		return e
	}
	check, e := sqlitestore.OpenReadOnly(ctx, snapshot)
	if e != nil {
		return e
	}
	state, stateErr := check.Maintenance().InspectMaintenance(ctx)
	if stateErr != nil {
		check.Close()
		return stateErr
	}
	for name, count := range state.Pending {
		if name != "sealed_tree_unrecoverable" && count != 0 {
			check.Close()
			return store.ErrBackupBusy
		}
	}
	for _, query := range []string{
		"SELECT COUNT(*) FROM selected_upload_intents WHERE state='pending'",
		"SELECT COUNT(*) FROM selected_s3_uploads WHERE state='pending'",
		"SELECT COUNT(*) FROM sealed_tree_pending_files",
		"SELECT COUNT(*) FROM sealed_tree_pending_facts",
	} {
		var count int64
		if e = check.Database().QueryRowContext(ctx, query).Scan(&count); e != nil {
			check.Close()
			return e
		}
		if count != 0 {
			check.Close()
			return store.ErrBackupBusy
		}
	}
	e = validateDatabase(ctx, check.Database(), s.MasterID, migrations.Generation)
	if e == nil {
		e = s.Tree.ValidateCheckpointDatabase(ctx, check.Database())
	}
	e = errors.Join(e, check.Close())
	if e != nil {
		return e
	}
	media, e := os.OpenRoot(s.MediaRoot)
	if e != nil {
		return e
	}
	defer media.Close()
	return seal(ctx, out, s.Vault, Header{MasterID: s.MasterID, Generation: generation, Schema: migrations.Generation}, func(w io.Writer) error {
		archive := tar.NewWriter(w)
		f, e := os.Open(snapshot)
		if e != nil {
			return e
		}
		e = copyMember(ctx, archive, "database.sqlite", f, "", maxFileBytes)
		e = errors.Join(e, f.Close())
		if e != nil {
			return e
		}
		snapshotInfo, e := os.Stat(snapshot)
		if e != nil {
			return e
		}
		total := snapshotInfo.Size()
		e = s.Tree.CheckpointLyricBlobs(ctx, lease, s.MasterID, func(p sealedtree.Placement) error {
			name, e := sealedtree.BlobPath(p.BlobID)
			if e != nil {
				return e
			}
			if p.Bytes > 4*1024*1024 || total > maxTotalBytes-p.Bytes {
				return ErrCheckpoint
			}
			total += p.Bytes
			info, e := media.Lstat(name)
			if e != nil || !info.Mode().IsRegular() || info.Size() != p.Bytes {
				return ErrCheckpoint
			}
			file, e := media.Open(name)
			if e != nil {
				return e
			}
			opened, e := file.Stat()
			if e != nil || !os.SameFile(info, opened) {
				file.Close()
				return ErrCheckpoint
			}
			e = copyMember(ctx, archive, "media/"+name, file, p.SHA256, 4*1024*1024)
			return errors.Join(e, file.Close())
		})
		if e != nil {
			return e
		}
		if e = lease.Check(ctx); e != nil {
			return e
		}
		return archive.Close()
	})
}
func copyMember(ctx context.Context, tw *tar.Writer, name string, file *os.File, expected string, limit int64) error {
	info, e := file.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return ErrCheckpoint
	}
	if e = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: info.Size(), Typeflag: tar.TypeReg}); e != nil {
		return e
	}
	hash := sha256.New()
	buffer := make([]byte, 64*1024)
	var size int64
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		n, read := file.Read(buffer)
		if n > 0 {
			if _, e = io.MultiWriter(tw, hash).Write(buffer[:n]); e != nil {
				return e
			}
			size += int64(n)
		}
		if read == io.EOF {
			break
		}
		if read != nil {
			return read
		}
	}
	after, e := file.Stat()
	if e != nil || size != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return ErrCheckpoint
	}
	if expected != "" && hex.EncodeToString(hash.Sum(nil)) != expected {
		return ErrCheckpoint
	}
	return nil
}
func validateDatabase(ctx context.Context, db *sql.DB, master string, schema int) error {
	var integrity, id, role string
	var generation int
	if db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity) != nil || integrity != "ok" {
		return ErrCheckpoint
	}
	if db.QueryRowContext(ctx, "SELECT generation FROM frontiercloud_schema WHERE singleton=1").Scan(&generation) != nil || generation != schema {
		return ErrCheckpoint
	}
	if db.QueryRowContext(ctx, "SELECT node_id,role FROM node_identity WHERE singleton=1").Scan(&id, &role) != nil || id != master || role != "Master" {
		return ErrCheckpoint
	}
	return nil
}
func safeMember(name string) bool {
	if name == "database.sqlite" {
		return true
	}
	if !strings.HasPrefix(name, "media/objects/") {
		return false
	}
	p := strings.TrimPrefix(name, "media/")
	parts := strings.Split(p, "/")
	if len(parts) != 4 || len(parts[1]) != 2 || len(parts[2]) != 2 || !strings.HasSuffix(parts[3], ".blob") {
		return false
	}
	id := strings.TrimSuffix(parts[3], ".blob")
	expected, e := sealedtree.BlobPath(id)
	return e == nil && p == expected
}

// Restore extracts privately into a new directory, verifies the independent
// stored checksum, SQLite integrity and namespace authentication. It never
// overwrites a live database or publishes a restored deployment.
func Restore(ctx context.Context, input io.Reader, expectedSHA string, expectedBytes int64, v *vault.Vault, master string, generation int64, target string, verify func(context.Context, *sql.DB) error) (Header, error) {
	var empty Header
	if ctx == nil || len(expectedSHA) != 64 || expectedBytes <= 0 || expectedBytes > maxTotalBytes+32*1024*1024 || verify == nil || !filepath.IsAbs(target) {
		return empty, ErrCheckpoint
	}
	if _, e := os.Lstat(target); !errors.Is(e, os.ErrNotExist) {
		return empty, ErrCheckpoint
	}
	if e := os.Mkdir(target, 0700); e != nil {
		return empty, e
	}
	success := false
	defer func() {
		if !success {
			os.RemoveAll(target)
		}
	}()
	root, e := os.OpenRoot(target)
	if e != nil {
		return empty, e
	}
	defer root.Close()
	hash := sha256.New()
	bounded := io.LimitReader(input, expectedBytes+1)
	counted := &countReader{input: bounded}
	reader := io.TeeReader(counted, hash)
	header, clear, e := open(reader, v, master, generation)
	if e != nil || header.Schema != migrations.Generation {
		return empty, ErrCheckpoint
	}
	tr := tar.NewReader(clear)
	seen := map[string]bool{}
	var total int64
	for {
		if e = ctx.Err(); e != nil {
			return empty, e
		}
		entry, read := tr.Next()
		if read == io.EOF {
			break
		}
		if read != nil || entry.Typeflag != tar.TypeReg || !safeMember(entry.Name) || seen[entry.Name] || entry.Size < 0 || entry.Size > maxFileBytes || total > maxTotalBytes-entry.Size {
			return empty, ErrCheckpoint
		}
		seen[entry.Name] = true
		total += entry.Size
		if e = root.MkdirAll(filepath.ToSlash(filepath.Dir(entry.Name)), 0700); e != nil {
			return empty, e
		}
		f, e := root.OpenFile(entry.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return empty, e
		}
		n, e := io.CopyBuffer(f, tr, make([]byte, 64*1024))
		if e == nil {
			e = f.Sync()
		}
		e = errors.Join(e, f.Close())
		if e != nil || n != entry.Size {
			return empty, ErrCheckpoint
		}
	}
	if _, e = io.Copy(io.Discard, clear); e != nil || !clear.ended || counted.bytes != expectedBytes || !seen["database.sqlite"] || hex.EncodeToString(hash.Sum(nil)) != expectedSHA {
		return empty, ErrCheckpoint
	}
	// LimitReader cannot prove an exact byte count by itself. The authenticated
	// terminal frame plus independent digest rejects both truncation and suffixes.
	db, e := sqlitestore.OpenReadOnly(ctx, filepath.Join(target, "database.sqlite"))
	if e != nil {
		return empty, e
	}
	e = validateDatabase(ctx, db.Database(), master, header.Schema)
	if e == nil {
		e = verify(ctx, db.Database())
	}
	e = errors.Join(e, db.Close())
	if e != nil {
		return empty, e
	}
	success = true
	return header, nil
}

type countReader struct {
	input io.Reader
	bytes int64
}

func (r *countReader) Read(p []byte) (int, error) {
	n, e := r.input.Read(p)
	r.bytes += int64(n)
	return n, e
}
