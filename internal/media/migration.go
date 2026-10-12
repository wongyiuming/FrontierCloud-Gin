package media

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (s *Service) MigrationReceiver(ctx context.Context) (*migrationdata.Receiver, error) {
	if s.nodes == nil {
		return nil, ErrUnavailable
	}
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
	return migrationdata.New(s.root, n.ID, "media")
}

// The caller supplies a fenced post-cutover admission. This retires only the
// private publication anchor; metadata, business bytes and quota are unchanged.
func (s *Service) MigrationRetireAnchor(ctx context.Context, spec migrationdata.Spec, admission func() error) (migrationdata.Checkpoint, error) {
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
		target, e := s.safeInfo(spec.TargetPath)
		if e != nil {
			return e
		}
		if target.Size() != spec.Bytes {
			return store.ErrMigrationState
		}
		if exists {
			anchor, e := s.root.Lstat(stage)
			if e != nil {
				return e
			}
			if !anchor.Mode().IsRegular() || !os.SameFile(anchor, target) {
				return store.ErrMigrationState
			}
		}
		o, e := s.repository.ObjectByID(ctx, spec.ObjectID)
		if e != nil {
			return e
		}
		if o == nil || o.Path != spec.TargetPath || (o.Encryption == nil) != (spec.Encryption == nil) || o.Encryption != nil && *o.Encryption != *spec.Encryption {
			return store.ErrMigrationState
		}
		return nil
	})
}

// MigrationPublish adopts verified bytes without another file-sized copy or
// upload reservation. A private hard-link anchor remains until task cleanup.
func (s *Service) MigrationPublish(ctx context.Context, spec migrationdata.Spec, admission func() error, complete func(store.MediaObject, int64) error) (migrationdata.Checkpoint, error) {
	r, e := s.MigrationReceiver(ctx)
	if e != nil {
		return migrationdata.Checkpoint{}, e
	}
	kind := "audio"
	if strings.HasPrefix(spec.TargetPath, "vido/") {
		kind = "video"
	}
	o := store.MediaObject{ID: spec.ObjectID, Path: spec.TargetPath, Kind: kind, Encryption: spec.Encryption}
	if !managedObject(o.Path, false) || !ownedObjectID.MatchString(o.ID) || complete == nil {
		return migrationdata.Checkpoint{}, store.ErrMigrationState
	}
	return r.Publish(ctx, spec, admission, func(stage string) error {
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
		staged, e := s.root.Lstat(stage)
		if e != nil {
			return e
		}
		if !staged.Mode().IsRegular() || staged.Size() != spec.Bytes {
			return store.ErrMigrationState
		}
		target, e := s.safeInfo(o.Path)
		if e == nil {
			if !target.Mode().IsRegular() || !os.SameFile(staged, target) {
				return os.ErrExist
			}
		} else {
			if !errors.Is(e, os.ErrNotExist) {
				return e
			}
			if e = s.checkLayout(o); e != nil {
				return e
			}
			if e = s.makeParents(o.Path); e != nil {
				return e
			}
			if e = s.root.Link(stage, o.Path); e != nil {
				return e
			}
		}
		// Sync on replay as well: a previous process may have stopped after Link.
		if e = s.syncDirectory(path.Dir(o.Path)); e != nil {
			return e
		}
		// Direct Nginx reads through the media group, never the application UID.
		file, e := s.root.OpenFile(o.Path, os.O_RDWR, 0)
		if e != nil {
			return e
		}
		e = file.Chmod(0644)
		if e == nil {
			e = file.Sync()
		}
		e = errors.Join(e, file.Close())
		if e != nil {
			return e
		}
		_, free, e := fsutil.DiskUsage(s.root)
		if e != nil {
			return e
		}
		return complete(o, free)
	})
}
func (s *Service) MigrationChunk(ctx context.Context, id, name string, expected, offset int64, length int) ([]byte, error) {
	if length < 1 || length > migrationdata.ChunkBytes || offset < 0 || offset > expected-int64(length) {
		return nil, ErrPath
	}
	release, e := s.acquire(ctx, false)
	if e != nil {
		return nil, e
	}
	defer release()
	if e = s.ready(); e != nil {
		return nil, e
	}
	o, e := s.repository.ObjectByID(ctx, id)
	if e != nil {
		return nil, e
	}
	if o == nil || o.Path != name {
		return nil, store.ErrMigrationState
	}
	info, e := s.safeInfo(name)
	if e != nil {
		return nil, e
	}
	if info.Size() != expected {
		return nil, store.ErrMigrationState
	}
	f, e := s.root.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return nil, ErrRecovery
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

func (s *Service) MigrationRecheck(ctx context.Context, spec migrationdata.Spec, id string, admission func() error) (migrationdata.Checkpoint, error) {
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
		a, e := s.root.Lstat(stage)
		if e != nil {
			return e
		}
		b, e := s.safeInfo(spec.TargetPath)
		if e != nil {
			return e
		}
		if !b.Mode().IsRegular() || !os.SameFile(a, b) || b.Size() != spec.Bytes {
			return store.ErrMigrationState
		}
		o, e := s.repository.ObjectByID(ctx, spec.ObjectID)
		if e != nil {
			return e
		}
		if o == nil || o.Path != spec.TargetPath {
			return store.ErrMigrationState
		}
		if (o.Encryption == nil) != (spec.Encryption == nil) || o.Encryption != nil && *o.Encryption != *spec.Encryption {
			return store.ErrMigrationState
		}
		return nil
	})
}
