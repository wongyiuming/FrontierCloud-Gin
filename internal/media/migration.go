package media

import (
	"context"
	"io"
	"os"

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
