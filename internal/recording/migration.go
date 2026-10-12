package recording

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
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
