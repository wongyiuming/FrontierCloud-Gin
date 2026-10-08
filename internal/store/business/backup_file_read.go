package business

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) readReadyFileBackup(ctx context.Context, master string, generation int64, consume func(store.BackupManifest, io.Reader) error) (store.BackupManifest, error) {
	var empty store.BackupManifest
	if !nodeIDPattern.MatchString(master) || generation <= 0 || consume == nil {
		return empty, store.ErrBackupState
	}
	release, err := r.backupFileLease(ctx, false)
	if err != nil {
		return empty, err
	}
	defer release()
	m, err := scanBackup(r.db.QueryRowContext(ctx, "SELECT "+backupColumns+" FROM cluster_business_backups WHERE master_id=? AND generation=?", master, generation))
	if err != nil || m.State != "ready" || !nodeHashPattern.MatchString(m.Checksum) || m.Bytes < 0 || m.Chunks < 1 || m.Chunks > store.MaxBackupChunkIndex+1 || m.Bytes > int64(m.Chunks)*store.MaxBackupChunk {
		return empty, store.ErrBackupState
	}
	name := backupArtifactName(m)
	if _, err := r.backupFiles.Lstat(name); errors.Is(err, os.ErrNotExist) {
		release()
		return r.readReadySQLBackup(ctx, master, generation, consume)
	}
	f, err := r.openBackupFile(name)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() != m.Bytes {
		return empty, store.ErrBackupState
	}
	release() // Retention may unlink the name; our immutable inode stays readable.
	reader := &coldFileReader{ctx: ctx, reader: f, manifest: m, digest: sha256.New()}
	if err := consume(m, reader); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if !reader.verified || reader.failure != nil {
		return empty, store.ErrBackupState
	}
	return m, nil
}

type coldFileReader struct {
	ctx      context.Context
	reader   io.Reader
	manifest store.BackupManifest
	digest   hash.Hash
	size     int64
	verified bool
	failure  error
}

func (r *coldFileReader) Read(p []byte) (n int, err error) {
	defer func() {
		if err != nil && err != io.EOF {
			r.failure = err
		}
	}()
	if r.failure != nil {
		return 0, r.failure
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.verified {
		return 0, io.EOF
	}
	n, err = r.reader.Read(p)
	r.size += int64(n)
	r.digest.Write(p[:n])
	if r.size > r.manifest.Bytes {
		return n, store.ErrBackupState
	}
	if err == io.EOF {
		if r.size != r.manifest.Bytes || hex.EncodeToString(r.digest.Sum(nil)) != r.manifest.Checksum {
			return n, store.ErrBackupState
		}
		r.verified = true
	}
	return n, err
}
