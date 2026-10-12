package migrationdata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func sha(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func fixture(t *testing.T, data []byte) (*Receiver, Spec, *os.Root) {
	t.Helper()
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	target := strings.Repeat("c", 32)
	r, e := New(root, target, "media")
	if e != nil {
		t.Fatal(e)
	}
	s := Spec{TaskID: strings.Repeat("d", 32), MasterID: strings.Repeat("a", 32), SourceID: strings.Repeat("b", 32), TargetID: target, LogicalID: strings.Repeat("e", 64), ObjectID: strings.Repeat("f", 64), Resource: "media", TargetPath: "music/private/track.mp3", SourceVersion: strings.Repeat("1", 64), Bytes: int64(len(data)), SHA256: sha(data)}
	return r, s, root
}

func TestLargeStreamUsesBoundedHeapAndActualDiskHash(t *testing.T) {
	chunk := bytes.Repeat([]byte{0x51}, ChunkBytes)
	r, s, root := fixture(t, chunk)
	s.Bytes = 64 << 20
	h := sha256.New()
	for i := int64(0); i < s.Bytes; i += ChunkBytes {
		h.Write(chunk)
	}
	s.SHA256 = hex.EncodeToString(h.Sum(nil))
	ctx := context.Background()
	if _, e := r.Begin(ctx, s); e != nil {
		t.Fatal(e)
	}
	runtime.GC()
	var baseline, stats runtime.MemStats
	runtime.ReadMemStats(&baseline)
	var peak uint64
	for offset := int64(0); offset < s.Bytes; offset += ChunkBytes {
		if _, e := r.Append(ctx, s, offset, chunk, sha(chunk)); e != nil {
			t.Fatal(e)
		}
		runtime.ReadMemStats(&stats)
		if stats.HeapAlloc > baseline.HeapAlloc {
			peak = max(peak, stats.HeapAlloc-baseline.HeapAlloc)
		}
	}
	c, e := r.Verify(ctx, s, nil)
	if e != nil || c.State != "verified" || c.PrefixSHA != s.SHA256 {
		t.Fatal(c, e)
	}
	name, _, _ := names(s)
	info, e := root.Stat(name)
	if e != nil || info.Size() != s.Bytes {
		t.Fatal(info, e)
	}
	if peak > 16<<20 {
		t.Fatalf("heap grew with stream instead of bounded chunks: %d", peak)
	}
	t.Logf("actual staged bytes=%d peak sampled additional Go heap=%d chunk limit=%d", s.Bytes, peak, ChunkBytes)
}

func TestAbortIsJournaledTaskBoundAndNeverDeletesBusinessPath(t *testing.T) {
	data := bytes.Repeat([]byte{9}, ChunkBytes+3)
	r, s, root := fixture(t, data)
	ctx := context.Background()
	if _, e := r.Begin(ctx, s); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Append(ctx, s, 0, data[:ChunkBytes], sha(data[:ChunkBytes])); e != nil {
		t.Fatal(e)
	}
	if e := root.MkdirAll("music/private", 0700); e != nil {
		t.Fatal(e)
	}
	if e := root.WriteFile(s.TargetPath, []byte("existing authority"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Abort(ctx, s, nil); !errors.Is(e, ErrState) {
		t.Fatal("unauthorized staging abort", e)
	}
	wrong := s
	wrong.SourceVersion = strings.Repeat("2", 64)
	if _, e := r.Abort(ctx, wrong, func() error { return nil }); !errors.Is(e, ErrState) {
		t.Fatal("wrong version removed staging", e)
	}
	c, e := r.Abort(ctx, s, func() error { return nil })
	if e != nil || c.State != "aborted" {
		t.Fatal(c, e)
	}
	c, e = r.Abort(ctx, s, func() error { return nil })
	if e != nil || c.State != "aborted" {
		t.Fatal("retry abort", c, e)
	}
	name, _, _ := names(s)
	if _, e = root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("private cleanup incomplete", e)
	}
	got, e := root.ReadFile(s.TargetPath)
	if e != nil || string(got) != "existing authority" {
		t.Fatal("business path changed", e)
	}
}
func TestActualBytesResumeDuplicateAndVerifiedDiskReader(t *testing.T) {
	data := bytes.Repeat([]byte("opaque-byte-stream"), ChunkBytes/2)
	r, s, root := fixture(t, data)
	ctx := context.Background()
	c, e := r.Begin(ctx, s)
	if e != nil || c.Offset != 0 {
		t.Fatal(c, e)
	}
	first := data[:ChunkBytes]
	c, e = r.Append(ctx, s, 0, first, sha(first))
	if e != nil || c.Offset != ChunkBytes {
		t.Fatal(c, e)
	}
	// Reconstruct the receiver over the same actual files, without memory.
	r, e = New(root, s.TargetID, s.Resource)
	if e != nil {
		t.Fatal(e)
	}
	c, e = r.Begin(ctx, s)
	if e != nil || c.Offset != ChunkBytes || c.PrefixSHA != sha(first) {
		t.Fatal("restart checkpoint", c, e)
	}
	c, e = r.Append(ctx, s, 0, first, sha(first))
	if e != nil || c.Offset != ChunkBytes {
		t.Fatal("duplicate chunk", c, e)
	}
	for offset := ChunkBytes; offset < len(data); offset += ChunkBytes {
		piece := data[offset:min(len(data), offset+ChunkBytes)]
		c, e = r.Append(ctx, s, int64(offset), piece, sha(piece))
		if e != nil {
			t.Fatal(e)
		}
	}
	if c.State != "received" || c.PrefixSHA != s.SHA256 {
		t.Fatal(c)
	}
	if _, _, e = r.VerifiedReader(ctx, s); !errors.Is(e, ErrState) {
		t.Fatal("received bytes published before disk verification", e)
	}
	c, e = r.Verify(ctx, s, nil)
	if e != nil || c.State != "verified" {
		t.Fatal(c, e)
	}
	f, release, e := r.VerifiedReader(ctx, s)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(f)
	release()
	if e != nil || !bytes.Equal(got, data) {
		t.Fatal("actual disk bytes", e)
	}
	if _, e = root.Lstat(s.TargetPath); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("private staging entered business namespace", e)
	}
}
func TestCiphertextDescriptorAndFinalReadDetectDiskCorruption(t *testing.T) {
	meta, e := mediacrypto.NewMetadata(ChunkBytes)
	if e != nil {
		t.Fatal(e)
	}
	data := bytes.Repeat([]byte{0xa7}, int(meta.CiphertextSize))
	r, s, root := fixture(t, data)
	s.Encryption = &meta
	ctx := context.Background()
	if _, e = r.Begin(ctx, s); e != nil {
		t.Fatal(e)
	}
	for offset := 0; offset < len(data); offset += ChunkBytes {
		piece := data[offset:min(len(data), offset+ChunkBytes)]
		if _, e = r.Append(ctx, s, int64(offset), piece, sha(piece)); e != nil {
			t.Fatal(e)
		}
	}
	name, _, _ := names(s)
	if _, e = r.Verify(ctx, s, nil); e != nil {
		t.Fatal(e)
	}
	f, e := root.OpenFile(name, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.WriteAt([]byte{0}, 0)
	f.Close()
	if _, _, e = r.VerifiedReader(ctx, s); !errors.Is(e, ErrState) {
		t.Fatal("corrupt disk exposed as verified", e)
	}
	wrong := s
	wrong.Encryption = nil
	if _, e = r.Begin(ctx, wrong); !errors.Is(e, ErrState) {
		t.Fatal("descriptor rebound", e)
	}
}
func TestCrashTailAndTemporaryJournalAreRecoveredWithoutBlindOffset(t *testing.T) {
	data := bytes.Repeat([]byte{7}, ChunkBytes+19)
	r, s, root := fixture(t, data)
	ctx := context.Background()
	if _, e := r.Begin(ctx, s); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Append(ctx, s, 0, data[:ChunkBytes], sha(data[:ChunkBytes])); e != nil {
		t.Fatal(e)
	}
	name, journal, _ := names(s)
	f, e := root.OpenFile(name, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.WriteAt([]byte("uncommitted tail"), ChunkBytes)
	f.Sync()
	f.Close()
	if e = root.WriteFile(journal+".tmp", []byte("interrupted journal"), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := r.Begin(ctx, s)
	if e != nil || c.Offset != ChunkBytes {
		t.Fatal(c, e)
	}
	c, e = r.Append(ctx, s, ChunkBytes, data[ChunkBytes:], sha(data[ChunkBytes:]))
	if e != nil || c.State != "received" {
		t.Fatal("tail recovery", c, e)
	}
	info, e := root.Stat(name)
	if e != nil || info.Size() != s.Bytes {
		t.Fatal("tail not replaced safely", info, e)
	}
	if _, e = r.Verify(ctx, s, nil); e != nil {
		t.Fatal(e)
	}
}
func TestConcurrentRequestsAndAdmissionCannotAdvanceWrongTask(t *testing.T) {
	data := bytes.Repeat([]byte{4}, ChunkBytes)
	r, s, _ := fixture(t, data)
	ctx := context.Background()
	if _, e := r.Begin(ctx, s); e != nil {
		t.Fatal(e)
	}
	if _, e := r.AppendAdmitted(ctx, s, 0, data, sha(data), func() error { return store.ErrMigrationLease }); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal(e)
	}
	c, e := r.Begin(ctx, s)
	if e != nil || c.Offset != 0 {
		t.Fatal("rejected epoch wrote bytes", c, e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, e := r.Append(ctx, s, 0, data, sha(data)); errs <- e })
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	wrong := s
	wrong.SourceVersion = strings.Repeat("9", 64)
	if _, e = r.Begin(ctx, wrong); !errors.Is(e, ErrState) {
		t.Fatal("new source version adopted old prefix", e)
	}
	wrong = s
	wrong.TargetID = s.SourceID
	if _, e = r.Begin(ctx, wrong); !errors.Is(e, ErrState) {
		t.Fatal("wrong recipient", e)
	}
	wrong = s
	wrong.TargetPath = "../escape.mp3"
	if _, e = r.Begin(ctx, wrong); !errors.Is(e, ErrState) {
		t.Fatal("path traversal", e)
	}
}

func TestVerificationCancellationAndCrashBeforeInitialJournal(t *testing.T) {
	data := bytes.Repeat([]byte{3}, ChunkBytes)
	r, s, root := fixture(t, data)
	ctx := context.Background()
	name, _, _ := names(s)
	if e := root.WriteFile(name, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Begin(ctx, s); e != nil {
		t.Fatal("initial empty crash artifact", e)
	}
	if _, e := r.Append(ctx, s, 0, data, sha(data)); e != nil {
		t.Fatal(e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := r.Verify(cancelled, s, nil); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled verification", e)
	}
	c, e := r.Begin(ctx, s)
	if e != nil || c.State != "received" {
		t.Fatal("verification cancellation lost durable bytes", c, e)
	}
	calls := 0
	if _, e = r.Verify(ctx, s, func() error {
		calls++
		if calls == 2 {
			return store.ErrMigrationLease
		}
		return nil
	}); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal("verification ignored new task epoch", e)
	}
	c, e = r.Begin(ctx, s)
	if e != nil || c.State != "received" {
		t.Fatal("stale verifier persisted authority", c, e)
	}
	if _, e = r.Verify(ctx, s, nil); e != nil {
		t.Fatal(e)
	}
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.Write([]byte{0})
	f.Close()
	if _, _, e = r.VerifiedReader(ctx, s); !errors.Is(e, ErrState) {
		t.Fatal("extra disk tail ignored", e)
	}
}

func TestCheckpointJSONDoesNotExposePrivateHashState(t *testing.T) {
	data := bytes.Repeat([]byte("private tail"), 50)
	r, s, _ := fixture(t, data)
	ctx := context.Background()
	if _, e := r.Begin(ctx, s); e != nil {
		t.Fatal(e)
	}
	c, e := r.Append(ctx, s, 0, data, sha(data))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(c)
	if e != nil || bytes.Contains(raw, []byte("hash_state")) {
		t.Fatal("internal hash state serialized", e)
	}
}

func TestAbortBeforeBeginPreservesUnknownUnjournaledBytes(t *testing.T) {
	for _, material := range []string{"absent", "empty", "unknown"} {
		t.Run(material, func(t *testing.T) {
			r, s, root := fixture(t, []byte("expected"))
			name, _, _ := names(s)
			if material != "absent" {
				data := []byte{}
				if material == "unknown" {
					data = []byte("unknown")
				}
				if e := root.WriteFile(name, data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			cp, e := r.Abort(context.Background(), s, func() error { return nil })
			if material == "unknown" {
				if !errors.Is(e, ErrState) {
					t.Fatal(cp, e)
				}
				if data, e := root.ReadFile(name); e != nil || string(data) != "unknown" {
					t.Fatal("unknown bytes lost", e)
				}
				return
			}
			if e != nil || cp.State != "aborted" {
				t.Fatal(cp, e)
			}
			r, e = New(root, s.TargetID, s.Resource)
			if e != nil {
				t.Fatal(e)
			}
			if cp, e = r.Abort(context.Background(), s, func() error { return nil }); e != nil || cp.State != "aborted" {
				t.Fatal("restart replay", cp, e)
			}
			if _, e = r.Begin(context.Background(), s); !errors.Is(e, ErrState) {
				t.Fatal("cancelled staging resurrected", e)
			}
		})
	}
}
