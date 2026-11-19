// Package checkpoint implements bounded, Master-key-encrypted business recovery
// points. Storage peers hold opaque bytes and never receive a decryption key.
package checkpoint

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

var ErrCheckpoint = errors.New("invalid or incomplete business recovery point")

const magic = "FC-BUSINESS-POINT-1\n"
const chunkBytes = 64 * 1024

type Header struct {
	MasterID   string `json:"master_id"`
	Generation int64  `json:"generation"`
	Schema     int    `json:"schema"`
	WrappedKey string `json:"wrapped_key"`
}
type frameWriter struct {
	out      io.Writer
	aead     cipher.AEAD
	aad      [32]byte
	sequence uint64
}

func nonce(sequence uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], sequence)
	return n
}
func frameAAD(hash [32]byte, sequence uint64, final bool) []byte {
	a := make([]byte, 41)
	copy(a, hash[:])
	binary.BigEndian.PutUint64(a[32:], sequence)
	if final {
		a[40] = 1
	}
	return a
}
func (w *frameWriter) frame(clear []byte, final bool) error {
	if w.sequence == ^uint64(0) {
		return ErrCheckpoint
	}
	raw := w.aead.Seal(nil, nonce(w.sequence), clear, frameAAD(w.aad, w.sequence, final))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	if n, e := w.out.Write(size[:]); e != nil || n != len(size) {
		if e == nil {
			e = io.ErrShortWrite
		}
		return e
	}
	if n, e := w.out.Write(raw); e != nil || n != len(raw) {
		if e == nil {
			e = io.ErrShortWrite
		}
		return e
	}
	w.sequence++
	return nil
}
func (w *frameWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), chunkBytes)
		if e := w.frame(p[:n], false); e != nil {
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func seal(ctx context.Context, out io.Writer, v *vault.Vault, h Header, write func(io.Writer) error) error {
	if ctx == nil || out == nil || v == nil || h.Generation <= 0 || len(h.MasterID) != 32 || h.Schema <= 0 || write == nil {
		return ErrCheckpoint
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return e
	}
	defer clear(key)
	wrapped, e := v.Seal(base64.RawStdEncoding.EncodeToString(key))
	if e != nil {
		return e
	}
	h.WrappedKey = wrapped
	raw, e := json.Marshal(h)
	if e != nil || len(raw) > 4096 {
		return ErrCheckpoint
	}
	if n, err := io.WriteString(out, magic); err != nil || n != len(magic) {
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if n, err := out.Write(append(raw, '\n')); err != nil || n != len(raw)+1 {
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	f := &frameWriter{out: out, aead: aead, aad: sha256.Sum256(raw)}
	if e = write(f); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return f.frame(nil, true)
}

type frameReader struct {
	input    *bufio.Reader
	aead     cipher.AEAD
	aad      [32]byte
	sequence uint64
	pending  []byte
	ended    bool
}

func (r *frameReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	if r.ended {
		return 0, io.EOF
	}
	var size [4]byte
	if _, e := io.ReadFull(r.input, size[:]); e != nil {
		return 0, ErrCheckpoint
	}
	n := binary.BigEndian.Uint32(size[:])
	if n < uint32(r.aead.Overhead()) || n > chunkBytes+uint32(r.aead.Overhead()) {
		return 0, ErrCheckpoint
	}
	raw := make([]byte, n)
	if _, e := io.ReadFull(r.input, raw); e != nil {
		return 0, ErrCheckpoint
	}
	final := int(n) == r.aead.Overhead()
	clear, e := r.aead.Open(nil, nonce(r.sequence), raw, frameAAD(r.aad, r.sequence, final))
	if e != nil || r.sequence == ^uint64(0) {
		return 0, ErrCheckpoint
	}
	r.sequence++
	if final {
		if _, e = r.input.ReadByte(); e != io.EOF {
			return 0, ErrCheckpoint
		}
		r.ended = true
		return 0, io.EOF
	}
	r.pending = clear
	return r.Read(p)
}
func open(input io.Reader, v *vault.Vault, master string, generation int64) (Header, *frameReader, error) {
	var h Header
	if input == nil || v == nil {
		return h, nil, ErrCheckpoint
	}
	r := bufio.NewReaderSize(input, chunkBytes+4096)
	prefix := make([]byte, len(magic))
	if _, e := io.ReadFull(r, prefix); e != nil || string(prefix) != magic {
		return h, nil, ErrCheckpoint
	}
	raw, e := r.ReadSlice('\n')
	if e != nil || len(raw) > 4096 {
		return h, nil, ErrCheckpoint
	}
	raw = raw[:len(raw)-1]
	if json.Unmarshal(raw, &h) != nil || h.MasterID != master || h.Generation != generation || h.Schema <= 0 {
		return h, nil, ErrCheckpoint
	}
	keyText, e := v.Unseal(h.WrappedKey)
	if e != nil {
		return h, nil, ErrCheckpoint
	}
	key, e := base64.RawStdEncoding.DecodeString(keyText)
	if e != nil || len(key) != 32 {
		return h, nil, ErrCheckpoint
	}
	defer clear(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		return h, nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return h, nil, e
	}
	return h, &frameReader{input: r, aead: aead, aad: sha256.Sum256(raw)}, nil
}
