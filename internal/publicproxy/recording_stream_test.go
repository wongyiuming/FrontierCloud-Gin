package publicproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type recordingShortWriter struct{ bytes.Buffer }

func (w *recordingShortWriter) Write(p []byte) (int, error) {
	return w.Buffer.Write(p[:min(len(p), 7)])
}

type recordingCancelReader struct {
	cancel context.CancelFunc
	reader io.Reader
}

func (r recordingCancelReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.cancel()
	return n, err
}

type recordingCancelWriter struct {
	cancel context.CancelFunc
	calls  int
}

func (w *recordingCancelWriter) Write(p []byte) (int, error) {
	w.calls++
	w.cancel()
	return min(len(p), 1), nil
}

func TestRecordingStreamStopsAfterCancellationDuringIO(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	ctx, cancel := context.WithCancel(context.Background())
	var wire bytes.Buffer
	source := recordingCancelReader{cancel: cancel, reader: bytes.NewReader([]byte("abc"))}
	if err := encodeRecordingStream(ctx, &wire, source, key, 3); !errors.Is(err, context.Canceled) || wire.Len() != 0 {
		t.Fatalf("canceled read emitted a frame: bytes=%d err=%v", wire.Len(), err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	w := &recordingCancelWriter{cancel: cancel}
	if err := encodeRecordingStream(ctx, w, bytes.NewReader([]byte("abc")), key, 3); !errors.Is(err, context.Canceled) || w.calls != 1 {
		t.Fatalf("canceled write continued: calls=%d err=%v", w.calls, err)
	}
}

func TestRecordingStreamHandlesShortNetworkIO(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	content := bytes.Repeat([]byte("short-io"), 9000)
	wire := &recordingShortWriter{}
	if err := encodeRecordingStream(context.Background(), wire, iotest.HalfReader(bytes.NewReader(content)), key, int64(len(content))); err != nil {
		t.Fatal(err)
	}
	reader, err := newRecordingStreamReader(context.Background(), iotest.HalfReader(bytes.NewReader(wire.Bytes())), key, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("short network IO", len(got), err)
	}
}

func TestRecordingStreamAuthenticatesBeforeFinalBytes(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	for _, size := range []int{1, recordingFrameSize - 1, recordingFrameSize, recordingFrameSize + 1, 2*recordingFrameSize + 3} {
		content := bytes.Repeat([]byte("a"), size)
		var wire bytes.Buffer
		if err := encodeRecordingStream(context.Background(), &wire, bytes.NewReader(content), key, int64(size)); err != nil {
			t.Fatal(size, err)
		}
		r, err := newRecordingStreamReader(context.Background(), bytes.NewReader(wire.Bytes()), key, int64(size))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(decoded, content) {
			t.Fatalf("size %d: decoded %d, %v", size, len(decoded), err)
		}
		if r.key != [32]byte{} {
			t.Fatal("completed stream retained its private key")
		}
		bad := append([]byte(nil), wire.Bytes()...)
		bad[len(bad)-1] ^= 1 // Corrupt only the terminal authenticator.
		r, _ = newRecordingStreamReader(context.Background(), bytes.NewReader(bad), key, int64(size))
		decoded, err = io.ReadAll(r)
		if err == nil || len(decoded) >= size || len(decoded) > (size-1)/recordingFrameSize*recordingFrameSize {
			t.Fatalf("size %d: unauthenticated final block escaped (%d, %v)", size, len(decoded), err)
		}
		if r.key != [32]byte{} {
			t.Fatal("rejected stream retained its private key")
		}
		r, _ = newRecordingStreamReader(context.Background(), bytes.NewReader(bad), key, int64(size))
		if n, err := io.ReadFull(r, make([]byte, size)); err == nil || n >= size {
			t.Fatalf("size %d: exact-length consumer accepted invalid trailer", size)
		}
		truncated := wire.Bytes()[:wire.Len()-1]
		r, _ = newRecordingStreamReader(context.Background(), bytes.NewReader(truncated), key, int64(size))
		decoded, err = io.ReadAll(r)
		if err == nil || len(decoded) >= size {
			t.Fatalf("size %d: truncated stream exposed last byte", size)
		}
	}
}

func TestRecordingStreamRejectsTamperLengthsAndCancellation(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	content := bytes.Repeat([]byte("r"), recordingFrameSize+10)
	var wire bytes.Buffer
	if err := encodeRecordingStream(context.Background(), &wire, bytes.NewReader(content), key, int64(len(content))); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		wire []byte
		key  []byte
	}{
		{"payload", func() []byte { b := bytes.Clone(wire.Bytes()); b[5] ^= 1; return b }(), key},
		{"length", func() []byte { b := bytes.Clone(wire.Bytes()); b[0] = 0xff; return b }(), key},
		{"trailing", append(bytes.Clone(wire.Bytes()), 0), key},
		{"key", bytes.Clone(wire.Bytes()), bytes.Repeat([]byte{8}, 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := newRecordingStreamReader(context.Background(), bytes.NewReader(tc.wire), tc.key, int64(len(content)))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := io.ReadAll(r)
			if err == nil || len(decoded) >= len(content) {
				t.Fatal("tampered stream completed", len(decoded), err)
			}
		})
	}
	if err := encodeRecordingStream(context.Background(), io.Discard, bytes.NewReader(content), key, int64(len(content)-1)); err == nil {
		t.Fatal("extra source byte accepted")
	}
	if err := encodeRecordingStream(context.Background(), io.Discard, bytes.NewReader(content[:2]), key, 3); err == nil {
		t.Fatal("short source accepted")
	}
	if _, err := newRecordingStreamReader(context.Background(), bytes.NewReader(nil), key, store.MaxRecordingBytes+1); err == nil {
		t.Fatal("oversized reservation accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r, err := newRecordingStreamReader(ctx, bytes.NewReader(wire.Bytes()), key, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	if n, err := r.Read(one); n != 1 || err != nil {
		t.Fatal("first byte", n, err)
	}
	cancel()
	if _, err := r.Read(one); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled stream continued", err)
	}
	if r.key != [32]byte{} {
		t.Fatal("canceled stream retained its private key")
	}
	r, _ = newRecordingStreamReader(context.Background(), bytes.NewReader(wire.Bytes()), key, int64(len(content)))
	if err := r.Close(); err != nil || r.key != [32]byte{} {
		t.Fatal("early close retained its private key", err)
	}
	if _, err := r.Read(one); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("closed stream continued", err)
	}
}

func TestRecordingStreamRejectsReplayedFrame(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	content := bytes.Repeat([]byte("x"), 2*recordingFrameSize)
	var encoded bytes.Buffer
	if err := encodeRecordingStream(context.Background(), &encoded, bytes.NewReader(content), key, int64(len(content))); err != nil {
		t.Fatal(err)
	}
	frameLength := 4 + recordingFrameSize + 32
	first := encoded.Bytes()[:frameLength]
	replayed := append(bytes.Clone(first), first...)
	replayed = append(replayed, encoded.Bytes()[2*frameLength:]...)
	reader, err := newRecordingStreamReader(context.Background(), bytes.NewReader(replayed), key, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err == nil || len(got) != recordingFrameSize {
		t.Fatalf("replayed block accepted: %d %v", len(got), err)
	}
}
