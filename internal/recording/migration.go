package recording

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"os"
	"path"
)

func (s *Storage) MigrationReceiver(ctx context.Context) (*migrationdata.Receiver, error) {
	n, e := s.nodes.ReadIdentity(ctx)
	if e != nil {
		return nil, e
	}
	if n.Role != "Follower" {
		return nil, store.ErrMigrationState
	}
	if e = s.Ready(ctx); e != nil {
		return nil, e
	}
	return migrationdata.New(s.root, n.ID, "recording")
}

func (s *Storage) MigrationRetireAnchor(ctx context.Context, spec migrationdata.Spec, admission func() error) (migrationdata.Checkpoint, error) {
	if spec.Recording == nil {
		return migrationdata.Checkpoint{}, store.ErrMigrationState
	}
	r, e := s.MigrationReceiver(ctx)
	if e != nil {
		return migrationdata.Checkpoint{}, e
	}
	return r.RetireAnchor(ctx, spec, admission, func(stage string, exists bool) error {
		release, e := s.acquire(ctx, false)
		if e != nil {
			return e
		}
		defer release()
		if e = s.ready(); e != nil {
			return e
		}
		target, e := s.info(spec.TargetPath)
		if e != nil {
			return e
		}
		if target.Size() != spec.Bytes {
			return store.ErrMigrationState
		}
		if exists {
			anchor, e := s.info(stage)
			if e != nil {
				return e
			}
			if !os.SameFile(anchor, target) {
				return store.ErrMigrationState
			}
		}
		v, e := s.repo.Recording(ctx, spec.LogicalID)
		if e != nil {
			return e
		}
		p := spec.Recording
		if v == nil || v.State != "ready" || v.UserID != p.UserID || v.Filename != p.Filename || v.ContentType != p.ContentType || v.Bytes != spec.Bytes || v.SHA256 == nil || *v.SHA256 != spec.SHA256 || !store.RecordingProofSnapshotMatches(*p, &store.RecordingMetadata{Title: v.Title, Lyrics: v.Lyrics, EncryptedLyrics: v.EncryptedLyrics}) {
			return store.ErrMigrationState
		}
		return nil
	})
}

// MigrationPublish adopts verified opaque recording bytes under the existing
// volume coordinator; it never copies an account, password or quota authority.
func (s *Storage) MigrationPublish(ctx context.Context, spec migrationdata.Spec, admission func() error, complete func(store.RecordingReceipt, int64) error) (migrationdata.Checkpoint, error) {
	if spec.Recording == nil || complete == nil {
		return migrationdata.Checkpoint{}, store.ErrMigrationState
	}
	proof := spec.Recording
	r, e := s.MigrationReceiver(ctx)
	if e != nil {
		return migrationdata.Checkpoint{}, e
	}
	return r.Publish(ctx, spec, admission, func(stage string) error {
		f, e := s.root.Open(stage)
		if e != nil {
			return e
		}
		metadata := Metadata(f, spec.Bytes)
		f.Close()
		if !store.RecordingProofSnapshotMatches(*proof, metadata) {
			return store.ErrMigrationState
		}
		receipt := store.RecordingReceipt{ID: spec.LogicalID, Bytes: spec.Bytes, SHA256: spec.SHA256, Metadata: metadata}
		release, e := s.acquire(ctx, true)
		if e != nil {
			return e
		}
		defer release()
		if e = s.ready(); e != nil {
			return e
		}
		if e = admission(); e != nil {
			return e
		}
		staged, e := s.info(stage)
		if e != nil {
			return e
		}
		target, e := s.info(spec.TargetPath)
		if e == nil {
			if !os.SameFile(staged, target) {
				return os.ErrExist
			}
		} else {
			if !errors.Is(e, os.ErrNotExist) {
				return e
			}
			if e = s.makeParents(spec.TargetPath); e != nil {
				return e
			}
			if e = s.root.Link(stage, spec.TargetPath); e != nil {
				return e
			}
		}
		if e = s.syncDir(path.Dir(spec.TargetPath)); e != nil {
			return e
		}
		file, e := s.root.OpenFile(spec.TargetPath, os.O_RDWR, 0)
		if e != nil {
			return e
		}
		e = file.Chmod(0640)
		if e == nil {
			e = file.Sync()
		}
		e = errors.Join(e, file.Close())
		if e != nil {
			return e
		}
		free, e := s.Free()
		if e != nil {
			return e
		}
		return complete(receipt, free)
	})
}
func (s *Storage) MigrationChunk(ctx context.Context, relationship, user, id string, expected, offset int64, length int) ([]byte, error) {
	if length < 1 || length > migrationdata.ChunkBytes || offset < 0 || offset > expected-int64(length) {
		return nil, store.ErrMigrationState
	}
	f, info, release, e := s.Open(ctx, relationship, user, id)
	if e != nil {
		return nil, e
	}
	defer release()
	if info.Size() != expected {
		return nil, store.ErrMigrationState
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	data := make([]byte, length)
	n, e := f.ReadAt(data, offset)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if n != length {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func (s *Storage) MigrationRecheck(ctx context.Context, spec migrationdata.Spec, id string, admission func() error) (migrationdata.Checkpoint, error) {
	if spec.Recording == nil {
		return migrationdata.Checkpoint{}, store.ErrMigrationState
	}
	r, e := s.MigrationReceiver(ctx)
	if e != nil {
		return migrationdata.Checkpoint{}, e
	}
	return r.Recheck(ctx, spec, id, admission, func(stage string) error {
		release, e := s.acquire(ctx, false)
		if e != nil {
			return e
		}
		defer release()
		if e = s.ready(); e != nil {
			return e
		}
		a, e := s.info(stage)
		if e != nil {
			return e
		}
		b, e := s.info(spec.TargetPath)
		if e != nil {
			return e
		}
		if !os.SameFile(a, b) || b.Size() != spec.Bytes {
			return store.ErrMigrationState
		}
		row, e := s.repo.Recording(ctx, spec.LogicalID)
		if e != nil {
			return e
		}
		p := spec.Recording
		if row == nil || row.State != "ready" || row.UserID != p.UserID || row.Filename != p.Filename || row.ContentType != p.ContentType || row.Bytes != spec.Bytes || row.SHA256 == nil || *row.SHA256 != spec.SHA256 || !store.RecordingProofSnapshotMatches(*p, &store.RecordingMetadata{Title: row.Title, Lyrics: row.Lyrics, EncryptedLyrics: row.EncryptedLyrics}) {
			return store.ErrMigrationState
		}
		return nil
	})
}
