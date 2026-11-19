package media

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const plainChunkBytes = 1 << 20
const plainIndexLimit = 16 << 20
const plainIndexCountLimit = 128
const plainReadLimit = 32

func (s *Service) acquirePlainRead(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.plainReadersOnce.Do(func() { s.plainReaders = make(chan struct{}, plainReadLimit) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case s.plainReaders <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-s.plainReaders
			return nil, err
		}
		var once sync.Once
		return func() { once.Do(func() { <-s.plainReaders }) }, nil
	}
}

type plainContentIndex struct {
	size   int64
	chunks [][sha256.Size]byte
}

func plainIndexKey(id, digest string, size int64) string {
	return id + ":" + digest + ":" + strconv.FormatInt(size, 10)
}

func (s *Service) plainIndex(key string) *plainContentIndex {
	s.plainIndexMu.RLock()
	defer s.plainIndexMu.RUnlock()
	return s.plainIndexes[key]
}

func (s *Service) rememberPlainIndex(key string, index *plainContentIndex) {
	bytes := len(index.chunks) * sha256.Size
	if bytes > plainIndexLimit {
		return
	}
	s.plainIndexMu.Lock()
	defer s.plainIndexMu.Unlock()
	if s.plainIndexes == nil || s.plainIndexBytes+bytes > plainIndexLimit || len(s.plainIndexes) >= plainIndexCountLimit {
		s.plainIndexes = make(map[string]*plainContentIndex)
		s.plainIndexBytes = 0
	}
	if _, exists := s.plainIndexes[key]; !exists {
		s.plainIndexes[key] = index
		s.plainIndexBytes += bytes
	}
}

// verifiedPlainIndex builds chunk proofs in the same pass as the full
// authorized SHA-256. A failed, short or cancelled scan is never cached.
func (s *Service) verifiedPlainIndex(ctx context.Context, file *os.File, id, digest string, size int64) (*plainContentIndex, error) {
	if size < 0 || size > 10*store.GiB {
		return nil, store.ErrNodeState
	}
	key := plainIndexKey(id, digest, size)
	if index := s.plainIndex(key); index != nil {
		return index, nil
	}
	for !s.plainIndexBuild.TryLock() {
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	defer s.plainIndexBuild.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if index := s.plainIndex(key); index != nil {
		return index, nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	count := (size + plainChunkBytes - 1) / plainChunkBytes
	index := &plainContentIndex{size: size, chunks: make([][sha256.Size]byte, 0, int(count))}
	whole := sha256.New()
	buffer := make([]byte, plainChunkBytes)
	remaining := size
	for remaining > 0 {
		want := int(min(remaining, int64(len(buffer))))
		if _, err := io.ReadFull(&contextReader{ctx, file}, buffer[:want]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, store.ErrNodeState
			}
			return nil, err
		}
		_, _ = whole.Write(buffer[:want])
		index.chunks = append(index.chunks, sha256.Sum256(buffer[:want]))
		remaining -= int64(want)
	}
	expected, _ := hex.DecodeString(digest)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() != size || subtle.ConstantTimeCompare(whole.Sum(nil), expected) != 1 {
		return nil, store.ErrNodeState
	}
	s.rememberPlainIndex(key, index)
	return index, nil
}

// verifiedPlainReader authenticates each requested chunk before copying any
// of its bytes to the caller. Its private buffer is never returned directly.
type verifiedPlainReader struct {
	ctx     context.Context
	file    *os.File
	index   *plainContentIndex
	pos     int64
	loaded  int64
	buffer  []byte
	failure error
}

func (r *verifiedPlainReader) Err() error { return r.failure }

func (r *verifiedPlainReader) fail(err error) (int, error) {
	if r.failure == nil {
		r.failure = err
	}
	return 0, r.failure
}

func (r *verifiedPlainReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.failure != nil {
		return 0, r.failure
	}
	if err := r.ctx.Err(); err != nil {
		return r.fail(err)
	}
	if r.pos >= r.index.size {
		return 0, io.EOF
	}
	chunk := r.pos / plainChunkBytes
	if r.loaded != chunk {
		start := chunk * plainChunkBytes
		length := int(min(int64(plainChunkBytes), r.index.size-start))
		if r.buffer == nil {
			r.buffer = make([]byte, plainChunkBytes)
		}
		n, err := r.file.ReadAt(r.buffer[:length], start)
		if n != length || err != nil {
			return r.fail(store.ErrNodeState)
		}
		sum := sha256.Sum256(r.buffer[:length])
		if subtle.ConstantTimeCompare(sum[:], r.index.chunks[chunk][:]) != 1 {
			return r.fail(store.ErrNodeState)
		}
		if err := r.ctx.Err(); err != nil {
			return r.fail(err)
		}
		r.loaded = chunk
	}
	start := int(r.pos % plainChunkBytes)
	available := int(min(int64(plainChunkBytes-start), r.index.size-r.pos))
	n := copy(p, r.buffer[start:start+available])
	r.pos += int64(n)
	return n, nil
}

func (r *verifiedPlainReader) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = r.pos
	case io.SeekEnd:
		base = r.index.size
	default:
		return 0, store.ErrNodeState
	}
	if offset < -base || offset > r.index.size-base {
		return 0, store.ErrNodeState
	}
	r.pos = base + offset
	return r.pos, nil
}
