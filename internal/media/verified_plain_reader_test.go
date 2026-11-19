package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestVerifiedPlainChunksRangesReplacementAndCancellation(t *testing.T) {
	ctx := context.Background()
	data := bytes.Repeat([]byte("0123456789abcdef"), (2*plainChunkBytes+32)/16)
	data = data[:2*plainChunkBytes+17]
	file, err := os.CreateTemp(t.TempDir(), "plain-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	whole := sha256.Sum256(data)
	digest := hex.EncodeToString(whole[:])
	id := strings.Repeat("a", 64)
	service := &Service{}
	if _, err := service.verifiedPlainIndex(ctx, file, id, digest, int64(len(data)+1)); !errors.Is(err, store.ErrNodeState) || len(service.plainIndexes) != 0 {
		t.Fatal("short full verification cached", err)
	}
	if _, err := service.verifiedPlainIndex(ctx, file, id, strings.Repeat("0", 64), int64(len(data))); !errors.Is(err, store.ErrNodeState) || len(service.plainIndexes) != 0 {
		t.Fatal("wrong complete digest cached", err)
	}
	index, err := service.verifiedPlainIndex(ctx, file, id, digest, int64(len(data)))
	if err != nil || len(index.chunks) != 3 {
		t.Fatal("verified index", err)
	}
	reader := &verifiedPlainReader{ctx: ctx, file: file, index: index, loaded: -1}
	for _, test := range []struct{ offset, length int }{{0, 33}, {plainChunkBytes - 9, 24}, {plainChunkBytes, 20}, {2*plainChunkBytes + 7, 10}} {
		if _, err := reader.Seek(int64(test.offset), io.SeekStart); err != nil {
			t.Fatal(err)
		}
		actual := make([]byte, test.length)
		if _, err := io.ReadFull(reader, actual); err != nil || !bytes.Equal(actual, data[test.offset:test.offset+test.length]) {
			t.Fatal("verified range", test, err)
		}
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	output := make([]byte, 8)
	if _, err := io.ReadFull(reader, output); err != nil {
		t.Fatal(err)
	}
	output[0] ^= 0xff
	_, _ = reader.Seek(0, io.SeekStart)
	if _, err := io.ReadFull(reader, output); err != nil || !bytes.Equal(output, data[:8]) {
		t.Fatal("caller modified the verified internal buffer", err)
	}
	if _, err := reader.Seek(-1, io.SeekStart); err == nil {
		t.Fatal("negative seek accepted")
	}
	if _, err := service.verifiedPlainIndex(ctx, file, id, digest, 10*store.GiB+1); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("oversize index admitted", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := service.verifiedPlainIndex(cancelled, file, id, strings.Repeat("1", 64), int64(len(data))); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled scan admitted", err)
	}
	reader.ctx = cancelled
	if n, err := reader.Read(output); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read emitted bytes", n, err)
	}
	// Cached proofs cannot be bypassed by replacing one same-length block.
	if _, err := file.WriteAt([]byte("x"), int64(plainChunkBytes+3)); err != nil {
		t.Fatal(err)
	}
	cached, err := service.verifiedPlainIndex(ctx, file, id, digest, int64(len(data)))
	if err != nil || cached != index {
		t.Fatal("verified index was not reused", err)
	}
	changed := &verifiedPlainReader{ctx: ctx, file: file, index: cached, loaded: -1}
	if n, err := changed.Read(output); n != len(output) || err != nil || !bytes.Equal(output, data[:len(output)]) {
		t.Fatal("unchanged requested chunk required a full rescan", n, err)
	}
	_, _ = changed.Seek(plainChunkBytes+3, io.SeekStart)
	if n, err := changed.Read(output); n != 0 || !errors.Is(err, store.ErrNodeState) {
		t.Fatal("modified chunk emitted bytes", n, err)
	}
	if _, err := file.WriteAt(data[plainChunkBytes+3:plainChunkBytes+4], int64(plainChunkBytes+3)); err != nil {
		t.Fatal(err)
	}
	if n, err := changed.Read(output); n != 0 || !errors.Is(err, store.ErrNodeState) || !errors.Is(changed.Err(), store.ErrNodeState) {
		t.Fatal("failed request resumed after bytes were restored", n, err)
	}
	if _, err := file.WriteAt([]byte("x"), int64(plainChunkBytes+3)); err != nil {
		t.Fatal(err)
	}
	replacement := append([]byte(nil), data...)
	replacement[plainChunkBytes+3] = 'x'
	replacementHash := sha256.Sum256(replacement)
	newIndex, err := service.verifiedPlainIndex(ctx, file, id, hex.EncodeToString(replacementHash[:]), int64(len(data)))
	if err != nil || newIndex == index {
		t.Fatal("different content version reused prior proof", err)
	}
	newReader := &verifiedPlainReader{ctx: ctx, file: file, index: newIndex, loaded: -1}
	_, _ = newReader.Seek(plainChunkBytes+3, io.SeekStart)
	if n, err := newReader.Read(output[:1]); n != 1 || err != nil || output[0] != 'x' {
		t.Fatal("new content version unavailable", n, err)
	}
	if err := file.Truncate(int64(plainChunkBytes)); err != nil {
		t.Fatal(err)
	}
	short := &verifiedPlainReader{ctx: ctx, file: file, index: cached, loaded: -1}
	_, _ = short.Seek(plainChunkBytes, io.SeekStart)
	if n, err := short.Read(output); n != 0 || !errors.Is(err, store.ErrNodeState) {
		t.Fatal("short chunk emitted bytes", n, err)
	}
}

func TestVerifiedPlainIndexConcurrentEvictionIsBounded(t *testing.T) {
	service := &Service{}
	tooLarge := &plainContentIndex{size: 1, chunks: make([][sha256.Size]byte, plainIndexLimit/sha256.Size+1)}
	service.rememberPlainIndex("oversize", tooLarge)
	if service.plainIndex("oversize") != nil {
		t.Fatal("oversize proof entered cache")
	}
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for i := 0; i < 256; i++ {
				key := plainIndexKey(strings.Repeat("a", 64), strings.Repeat("b", 64), int64(worker*256+i+1))
				service.rememberPlainIndex(key, &plainContentIndex{size: 1, chunks: make([][sha256.Size]byte, 1)})
				_ = service.plainIndex(key)
			}
		}(worker)
	}
	workers.Wait()
	if len(service.plainIndexes) > plainIndexCountLimit || service.plainIndexBytes > plainIndexLimit {
		t.Fatal("index cache exceeded its bounds")
	}
}

func TestVerifiedPlainReaderCapacityAndCancellation(t *testing.T) {
	service := &Service{}
	var releases []func()
	for i := 0; i < plainReadLimit; i++ {
		release, err := service.acquirePlainRead(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if release, err := service.acquirePlainRead(cancelled); !errors.Is(err, context.Canceled) || release != nil {
		t.Fatal("cancelled reader exceeded capacity", err)
	}
	deadline, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if release, err := service.acquirePlainRead(deadline); !errors.Is(err, context.DeadlineExceeded) || release != nil {
		t.Fatal("waiting reader ignored its deadline", err)
	}
	releases[0]()
	releases[0]()
	release, err := service.acquirePlainRead(context.Background())
	if err != nil {
		t.Fatal("released reader slot unavailable", err)
	}
	release()
	for _, free := range releases[1:] {
		free()
	}
}

func TestPlainReadinessUsesOnlySyntheticData(t *testing.T) {
	service := &Service{}
	if err := service.ProbeVerifiedPlain(context.Background()); err != nil {
		t.Fatal("synthetic reader probe", err)
	}
	if len(service.plainIndexes) != 0 {
		t.Fatal("probe polluted user-object proof cache")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.ProbeVerifiedPlain(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled synthetic probe accepted", err)
	}
}

func BenchmarkVerifiedPlainIndexAndRange(b *testing.B) {
	data := bytes.Repeat([]byte("0123456789abcdef"), (64<<20)/16)
	file, err := os.CreateTemp(b.TempDir(), "fixture-*")
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		b.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest, id := hex.EncodeToString(sum[:]), strings.Repeat("a", 64)
	service := &Service{}
	ctx := context.Background()
	b.Run("initial-64MiB", func(b *testing.B) {
		b.SetBytes(int64(len(data)))
		for i := 0; i < b.N; i++ {
			service.plainIndexMu.Lock()
			service.plainIndexes, service.plainIndexBytes = nil, 0
			service.plainIndexMu.Unlock()
			if _, err := service.verifiedPlainIndex(ctx, file, id, digest, int64(len(data))); err != nil {
				b.Fatal(err)
			}
		}
	})
	index, err := service.verifiedPlainIndex(ctx, file, id, digest, int64(len(data)))
	if err != nil {
		b.Fatal(err)
	}
	b.Run("cached-cross-chunk-range", func(b *testing.B) {
		b.SetBytes(128)
		buffer := make([]byte, 128)
		for i := 0; i < b.N; i++ {
			reader := &verifiedPlainReader{ctx: ctx, file: file, index: index, loaded: -1}
			if _, err := reader.Seek(plainChunkBytes-64, io.SeekStart); err != nil {
				b.Fatal(err)
			}
			if _, err := io.ReadFull(reader, buffer); err != nil {
				b.Fatal(err)
			}
		}
	})
}
