package media

import (
	"context"
	"io"
	"sync"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func plaintextContentDigest(etag string) (string, bool) {
	if len(etag) != 66 || etag[0] != '"' || etag[65] != '"' || !ownedObjectID.MatchString(etag[1:65]) {
		return "", false
	}
	return etag[1:65], true
}

// OpenVerifiedOwnedPlain holds the cross-process volume read lease across
// verification and the caller's bounded read. The expected digest must come
// from a Master-authorized, object-bound grant, not a browser assertion.
// Callers must close the file and invoke release on every successful return.
// This deliberately does not support X-Accel, which outlives this lease.
func (s *Service) OpenVerifiedOwnedPlain(ctx context.Context, id, digest string) (*Stream, io.ReadSeeker, func(), error) {
	if !ownedObjectID.MatchString(id) || !ownedObjectID.MatchString(digest) {
		return nil, nil, nil, store.ErrNodeState
	}
	slot, err := s.acquirePlainRead(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		slot()
		return nil, nil, nil, err
	}
	stream, err := s.ownedStreamLocked(ctx, id)
	if err != nil {
		release()
		slot()
		return nil, nil, nil, err
	}
	fail := func(err error) (*Stream, io.ReadSeeker, func(), error) {
		_ = stream.File.Close()
		release()
		slot()
		return nil, nil, nil, err
	}
	if stream.Encryption != nil || stream.Info.Size() <= 0 {
		return fail(store.ErrNodeState)
	}
	index, err := s.verifiedPlainIndex(ctx, stream.File, id, digest, stream.Info.Size())
	if err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	var once sync.Once
	reader := &verifiedPlainReader{ctx: ctx, file: stream.File, index: index, loaded: -1}
	return stream, reader, func() {
		once.Do(func() {
			release()
			slot()
		})
	}, nil
}
