package publicproxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This framing primitive is not installed on an HTTP route. A future caller
// must authenticate a fresh, request-specific key and exact reserved byte
// count in the peer proof, enforce upload deadlines and join cancellation.
// The receiver withholds the complete final block until it has authenticated
// the terminal frame and EOF: an HTTP client that reads exactly Content-Length
// cannot publish an upload whose trailer has not been verified.
const recordingFrameSize = 64 << 10

var errRecordingFrame = errors.New("invalid authenticated recording stream")

func recordingFrameMAC(key []byte, index uint64, previous []byte, length uint32, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("frontiercloud-recording-stream-v1\x00"))
	var header [12]byte
	binary.BigEndian.PutUint64(header[:8], index)
	binary.BigEndian.PutUint32(header[8:], length)
	_, _ = mac.Write(header[:])
	_, _ = mac.Write(previous)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func writeRecordingFrame(ctx context.Context, dst io.Writer, key []byte, index uint64, previous, payload []byte) ([]byte, error) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	mac := recordingFrameMAC(key, index, previous, uint32(len(payload)), payload)
	for _, part := range [][]byte{length[:], payload, mac} {
		for len(part) != 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			n, err := dst.Write(part)
			if n < 0 || n > len(part) {
				return nil, errRecordingFrame
			}
			part = part[n:]
			if err != nil {
				return nil, err
			}
			if n == 0 {
				return nil, io.ErrShortWrite
			}
		}
	}
	return mac, nil
}

func encodeRecordingStream(ctx context.Context, dst io.Writer, src io.Reader, key []byte, expected int64) error {
	if ctx == nil || dst == nil || src == nil || len(key) != 32 || expected < 1 || expected > store.MaxRecordingBytes {
		return errRecordingFrame
	}
	buffer := make([]byte, recordingFrameSize)
	var previous []byte
	var index uint64
	remaining := expected
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		length := int(min(remaining, int64(len(buffer))))
		if _, err := io.ReadFull(src, buffer[:length]); err != nil {
			return errRecordingFrame
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		previous, err = writeRecordingFrame(ctx, dst, key, index, previous, buffer[:length])
		if err != nil {
			return err
		}
		index++
		remaining -= int64(length)
	}
	var extra [1]byte
	if n, err := io.ReadFull(src, extra[:]); n != 0 || err != io.EOF {
		return errRecordingFrame
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := writeRecordingFrame(ctx, dst, key, index, previous, nil)
	return err
}

type recordingStreamReader struct {
	ctx       context.Context
	src       io.Reader
	key       [32]byte
	expected  int64
	consumed  int64
	index     uint64
	previous  []byte
	available []byte
	done      bool
	err       error
}

func newRecordingStreamReader(ctx context.Context, src io.Reader, key []byte, expected int64) (*recordingStreamReader, error) {
	if ctx == nil || src == nil || len(key) != 32 || expected < 1 || expected > store.MaxRecordingBytes {
		return nil, errRecordingFrame
	}
	r := &recordingStreamReader{ctx: ctx, src: src, expected: expected}
	copy(r.key[:], key)
	return r, nil
}

func (r *recordingStreamReader) frame() ([]byte, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	var raw [4]byte
	if _, err := io.ReadFull(r.src, raw[:]); err != nil {
		return nil, errRecordingFrame
	}
	length := binary.BigEndian.Uint32(raw[:])
	remaining := r.expected - r.consumed
	want := uint32(min(remaining, int64(recordingFrameSize)))
	if length != want {
		return nil, errRecordingFrame
	}
	payload := make([]byte, length)
	var signature [sha256.Size]byte
	if _, err := io.ReadFull(r.src, payload); err != nil {
		return nil, errRecordingFrame
	}
	if _, err := io.ReadFull(r.src, signature[:]); err != nil || !hmac.Equal(signature[:], recordingFrameMAC(r.key[:], r.index, r.previous, length, payload)) {
		return nil, errRecordingFrame
	}
	r.previous = append(r.previous[:0], signature[:]...)
	r.index++
	r.consumed += int64(length)
	return payload, nil
}

func (r *recordingStreamReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if err := r.ctx.Err(); err != nil {
		r.fail(err)
		return 0, err
	}
	if len(r.available) == 0 {
		if r.done {
			return 0, io.EOF
		}
		payload, err := r.frame()
		if err != nil || len(payload) == 0 {
			r.fail(errRecordingFrame)
			return 0, r.err
		}
		if err := r.ctx.Err(); err != nil {
			r.fail(err)
			return 0, err
		}
		if r.consumed == r.expected {
			terminal, err := r.frame()
			if err != nil || len(terminal) != 0 {
				r.fail(errRecordingFrame)
				return 0, r.err
			}
			var extra [1]byte
			if n, err := io.ReadFull(r.src, extra[:]); n != 0 || err != io.EOF || r.ctx.Err() != nil {
				r.fail(errRecordingFrame)
				return 0, r.err
			}
			r.done = true
			clear(r.key[:])
		}
		r.available = payload
	}
	n := copy(dst, r.available)
	r.available = r.available[n:]
	return n, nil
}

func (r *recordingStreamReader) fail(err error) {
	clear(r.key[:])
	r.err = err
}

// Close clears the decoder's copy if a consumer stops before the terminal
// frame; the caller owns and must separately close the underlying HTTP body.
func (r *recordingStreamReader) Close() error {
	clear(r.available)
	r.available = nil
	r.fail(io.ErrClosedPipe)
	return nil
}
