package business

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var coldFileName = regexp.MustCompile(`^(chunk\.[a-f0-9]{32}\.[0-9]+\.[0-9]+\.[a-f0-9]{64}|artifact\.[a-f0-9]{32}\.[0-9]+\.[a-f0-9]{64})$`)
var coldChunkMagic = []byte("FC-COLD-FILE-V1\x00")

// ConfigureFileBackups is startup-only. SQLite keeps tiny durable manifests
// and chunk digests; recovery payloads are immutable private files, not BLOBs.
func (r *Repository) ConfigureFileBackups(directory string) error {
	return r.configureFileBackups(directory, false)
}

// Inspection must work with an entirely read-only data mount. It never creates
// or repairs roots/leases, so absent legacy directories retain SQL fallback.
func (r *Repository) OpenFileBackupsReadOnly(directory string) error {
	return r.configureFileBackups(directory, true)
}

func (r *Repository) configureFileBackups(directory string, readOnly bool) error {
	if r.backend != "sqlite" || r.backupFiles != nil {
		return store.ErrBackupState
	}
	if !readOnly {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(directory)
	if readOnly && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return store.ErrBackupState
	}
	if readOnly {
		if info.Mode().Perm() != 0700 {
			return store.ErrBackupState
		}
	} else {
		if err := os.Chmod(directory, 0700); err != nil {
			return err
		}
	}
	root, err := os.OpenRoot(filepath.Clean(directory))
	if err != nil {
		return err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		root.Close()
		return store.ErrBackupState
	}
	r.backupFiles = root
	r.backupFilesReadOnly = readOnly
	return nil
}
func (r *Repository) CloseFileBackups() error {
	if r.backupFiles != nil {
		return r.backupFiles.Close()
	}
	return nil
}
func (r *Repository) backupFileLease(ctx context.Context, exclusive bool) (func(), error) {
	if r.backupFiles == nil {
		return func() {}, nil
	}
	if info, err := r.backupFiles.Lstat(".lock"); err == nil && !info.Mode().IsRegular() {
		return nil, store.ErrBackupState
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	flags := os.O_CREATE | os.O_RDWR
	if r.backupFilesReadOnly {
		if exclusive {
			return nil, store.ErrBackupState
		}
		flags = os.O_RDONLY
	}
	f, err := r.backupFiles.OpenFile(".lock", flags, 0600)
	if err != nil {
		return nil, err
	}
	return filelease.Acquire(ctx, f, exclusive)
}
func backupChunkName(master string, generation int64, index int, digest []byte) string {
	return fmt.Sprintf("chunk.%s.%d.%d.%s", master, generation, index, hex.EncodeToString(digest))
}
func backupArtifactName(m store.BackupManifest) string {
	return fmt.Sprintf("artifact.%s.%d.%s", m.MasterID, m.Generation, m.Checksum)
}
func (r *Repository) fileChunk(master string, generation int64, index int, chunk []byte) ([]byte, error) {
	if r.backupFiles == nil {
		return chunk, nil
	}
	hash := sha256.Sum256(chunk)
	_, free, err := fsutil.DiskUsage(r.backupFiles)
	if err != nil {
		return nil, err
	}
	if free < store.PhysicalReserve+int64(len(chunk)) {
		return nil, store.ErrStorageCapacity
	}
	name := backupChunkName(master, generation, index, hash[:])
	if err := r.publishBackupFile(name, bytes.NewReader(chunk)); err != nil {
		return nil, err
	}
	marker := append(append([]byte{}, coldChunkMagic...), hash[:]...)
	marker = binary.BigEndian.AppendUint32(marker, uint32(len(chunk)))
	return marker, nil
}
func (r *Repository) readFileChunk(master string, generation int64, index int, marker []byte) ([]byte, error) {
	if !bytes.HasPrefix(marker, coldChunkMagic) || len(marker) != len(coldChunkMagic)+36 {
		return marker, nil // Historical cold SQL payloads are never rewritten.
	}
	if r.backupFiles == nil {
		return nil, store.ErrBackupState
	}
	digest := marker[len(coldChunkMagic) : len(coldChunkMagic)+32]
	length := binary.BigEndian.Uint32(marker[len(coldChunkMagic)+32:])
	if length > store.MaxBackupChunk {
		return nil, store.ErrBackupState
	}
	f, err := r.openBackupFile(backupChunkName(master, generation, index, digest))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	payload, err := io.ReadAll(io.LimitReader(f, int64(length)+1))
	hash := sha256.Sum256(payload)
	if err != nil || len(payload) != int(length) || !bytes.Equal(hash[:], digest) {
		return nil, store.ErrBackupState
	}
	return payload, nil
}
func (r *Repository) openBackupFile(name string) (*os.File, error) {
	info, err := r.backupFiles.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, store.ErrBackupState
	}
	f, err := r.backupFiles.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		f.Close()
		return nil, store.ErrBackupState
	}
	return f, nil
}
func (r *Repository) publishBackupFile(name string, reader io.Reader) error {
	if !coldFileName.MatchString(name) {
		return store.ErrBackupState
	}
	if _, err := r.backupFiles.Lstat(name); err == nil {
		// Existing content is verified by readFileChunk/commit, never overwritten.
		f, err := r.openBackupFile(name)
		if err != nil {
			return err
		}
		defer f.Close()
		oldHash, incomingHash := sha256.New(), sha256.New()
		oldBytes, err := io.Copy(oldHash, f)
		if err != nil {
			return err
		}
		incomingBytes, err := io.Copy(incomingHash, reader)
		if err != nil {
			return err
		}
		if oldBytes != incomingBytes || !bytes.Equal(oldHash.Sum(nil), incomingHash.Sum(nil)) {
			return store.ErrBackupState
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp := name + ".receiving"
	if info, err := r.backupFiles.Lstat(temp); err == nil {
		if !info.Mode().IsRegular() {
			return store.ErrBackupState
		}
		if err := r.backupFiles.Remove(temp); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := r.backupFiles.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer r.backupFiles.Remove(temp)
	_, err = io.Copy(f, reader)
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	if err := r.backupFiles.Rename(temp, name); err != nil {
		return err
	}
	return fsutil.SyncDirectory(r.backupFiles, ".")
}

func (r *Repository) materializeBackup(ctx context.Context, q queryer, m store.BackupManifest) error {
	if r.backupFiles == nil {
		return nil
	}
	rows, err := q.QueryContext(ctx, "SELECT chunk_index,payload FROM cluster_business_backup_chunks WHERE master_id=? AND generation=? ORDER BY chunk_index", m.MasterID, m.Generation)
	if err != nil {
		return err
	}
	defer rows.Close()
	reader := &coldBackupReader{ctx: ctx, rows: rows, manifest: m, digest: sha256.New(), files: r}
	if err := r.publishBackupFile(backupArtifactName(m), reader); err != nil {
		return err
	}
	if !reader.verified || reader.failure != nil {
		return store.ErrBackupState
	}
	return errors.Join(rows.Err(), rows.Close())
}

// Caller holds the exclusive file lease through SQL commit and retention.
// Readers open immutable artifacts under a shared lease then retain the inode.
func (r *Repository) sweepBackupFiles(ctx context.Context) error {
	if r.backupFiles == nil {
		return nil
	}
	keep := map[string]bool{}
	rows, err := r.db.QueryContext(ctx, "SELECT master_id,generation,chunk_index,payload FROM cluster_business_backup_chunks")
	if err != nil {
		return err
	}
	for rows.Next() {
		var master string
		var gen int64
		var index int
		var marker []byte
		if err := rows.Scan(&master, &gen, &index, &marker); err != nil {
			rows.Close()
			return err
		}
		if bytes.HasPrefix(marker, coldChunkMagic) && len(marker) == len(coldChunkMagic)+36 {
			keep[backupChunkName(master, gen, index, marker[len(coldChunkMagic):len(coldChunkMagic)+32])] = true
		}
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	rows, err = r.db.QueryContext(ctx, "SELECT "+backupColumns+" FROM cluster_business_backups WHERE state='ready'")
	if err != nil {
		return err
	}
	for rows.Next() {
		m, err := scanBackup(rows)
		if err != nil {
			rows.Close()
			return err
		}
		keep[backupArtifactName(m)] = true
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	dir, err := r.backupFiles.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	for {
		entries, err := dir.ReadDir(128)
		for _, entry := range entries {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			name := entry.Name()
			// Under the exclusive lease no publisher is using a .receiving file;
			// interrupted private publishes are safe to reclaim, not arbitrary files.
			owned := coldFileName.MatchString(name) || strings.HasSuffix(name, ".receiving") && coldFileName.MatchString(strings.TrimSuffix(name, ".receiving"))
			if !owned || keep[name] {
				continue
			}
			info, err := r.backupFiles.Lstat(entry.Name())
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return store.ErrBackupState
			}
			if err := r.backupFiles.Remove(entry.Name()); err != nil {
				return err
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return fsutil.SyncDirectory(r.backupFiles, ".")
}
