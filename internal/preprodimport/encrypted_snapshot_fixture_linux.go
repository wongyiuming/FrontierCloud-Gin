//go:build linux && ledger_fixture

package preprodimport

// Test-only streaming cryptographic primitive: no source identity, signed
// manifest, crash-recovery journal, database capture or product integration.
// Never use its descriptor as an import or publication authorization.
import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
)

const fixtureEncryptedChunkSize int64 = 64 << 10
const fixtureEncryptedReadLimit = 1 << 20

type encryptedSnapshotFixtureDescriptor struct {
	key      [32]byte
	id       [16]byte
	nonce    [8]byte
	plainSHA [32]byte
	size     int64
}

func fixtureEncryptedChunkCount(size int64) (uint64, error) {
	if size <= 0 {
		return 0, invalid("fixture encrypted snapshot size")
	}
	count := (uint64(size)-1)/uint64(fixtureEncryptedChunkSize) + 1
	if count > uint64(1)<<32 {
		return 0, invalid("fixture encrypted snapshot chunk count")
	}
	return count, nil
}

func (d encryptedSnapshotFixtureDescriptor) nonceFor(index uint32) []byte {
	out := make([]byte, 12)
	copy(out, d.nonce[:])
	binary.BigEndian.PutUint32(out[8:], index)
	return out
}

func (d encryptedSnapshotFixtureDescriptor) aad(index uint32) []byte {
	out := append([]byte("frontiercloud:fixture-encrypted-snapshot:v1\x00"), d.id[:]...)
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(d.size))
	binary.BigEndian.PutUint32(b[8:12], uint32(fixtureEncryptedChunkSize))
	binary.BigEndian.PutUint32(b[12:], index)
	return append(out, b[:]...)
}

// captureEncryptedSnapshotFixture streams plaintext through one fixed-size
// buffer and writes only authenticated ciphertext. Every invocation creates a
// fresh key and nonce prefix; retrying a partial output must start afresh.
func captureEncryptedSnapshotFixture(ctx context.Context, dst io.Writer, src io.Reader, size int64) (result encryptedSnapshotFixtureDescriptor, err error) {
	var d encryptedSnapshotFixtureDescriptor
	count, err := fixtureEncryptedChunkCount(size)
	if err != nil || ctx == nil || dst == nil || src == nil || ctx.Err() != nil {
		return d, invalid("fixture encrypted snapshot input")
	}
	d.size = size
	defer func() {
		clear(d.key[:])
		if err != nil {
			clear(result.key[:])
			result = encryptedSnapshotFixtureDescriptor{}
		}
	}()
	if _, err = rand.Read(d.key[:]); err != nil {
		return d, err
	}
	if _, err = rand.Read(d.id[:]); err != nil {
		return d, err
	}
	if _, err = rand.Read(d.nonce[:]); err != nil {
		return d, err
	}
	block, err := aes.NewCipher(d.key[:])
	if err != nil {
		return d, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return d, err
	}
	buf := make([]byte, fixtureEncryptedChunkSize)
	defer clear(buf)
	hash := sha256.New()
	for i := uint64(0); i < count; i++ {
		if err = ctx.Err(); err != nil {
			return d, err
		}
		length := min(fixtureEncryptedChunkSize, size-int64(i)*fixtureEncryptedChunkSize)
		if _, err = io.ReadFull(src, buf[:length]); err != nil {
			return d, invalid("fixture encrypted source truncated")
		}
		if _, err = hash.Write(buf[:length]); err != nil {
			return d, err
		}
		ciphertext := aead.Seal(nil, d.nonceFor(uint32(i)), buf[:length], d.aad(uint32(i)))
		written, e := dst.Write(ciphertext)
		clear(ciphertext)
		if e != nil || written != int(length)+aead.Overhead() {
			return d, invalid("fixture encrypted snapshot write")
		}
	}
	var extra [1]byte
	if n, e := src.Read(extra[:]); n != 0 || !errors.Is(e, io.EOF) {
		return d, invalid("fixture encrypted source length")
	}
	if err = ctx.Err(); err != nil {
		return d, err
	}
	copy(d.plainSHA[:], hash.Sum(nil))
	return d, nil
}

type encryptedSnapshotFixtureReader struct {
	mu     sync.Mutex
	file   *os.File
	desc   encryptedSnapshotFixtureDescriptor
	aead   cipher.AEAD
	closed bool
}

// The caller retains the file handle; Close destroys this reader's private
// descriptor copy and disables it, but does not close the caller's handle.
func openEncryptedSnapshotFixture(file *os.File, desc encryptedSnapshotFixtureDescriptor) (*encryptedSnapshotFixtureReader, error) {
	count, err := fixtureEncryptedChunkCount(desc.size)
	if err != nil || file == nil || desc.key == [32]byte{} || desc.id == [16]byte{} || desc.nonce == [8]byte{} || desc.plainSHA == [32]byte{} || count > uint64((int64(^uint64(0)>>1)-desc.size)/16) {
		return nil, invalid("fixture encrypted snapshot descriptor")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != desc.size+int64(count)*16 {
		return nil, invalid("fixture encrypted snapshot file")
	}
	block, err := aes.NewCipher(desc.key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &encryptedSnapshotFixtureReader{file: file, desc: desc, aead: aead}, nil
}

// ReadAt publishes no output until every requested encrypted chunk verifies.
// The bounded limit applies only to this test reader, not a product size limit.
func (r *encryptedSnapshotFixtureReader) ReadAt(out []byte, offset int64) (int, error) {
	if r == nil || offset < 0 || len(out) > fixtureEncryptedReadLimit {
		return 0, invalid("fixture encrypted snapshot read")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.file == nil || r.aead == nil {
		return 0, invalid("fixture encrypted snapshot closed")
	}
	if len(out) == 0 {
		return 0, nil
	}
	if offset >= r.desc.size {
		return 0, io.EOF
	}
	length := min(int64(len(out)), r.desc.size-offset)
	stage := make([]byte, int(length))
	defer clear(stage)
	for copied := int64(0); copied < length; {
		absolute := offset + copied
		index := uint32(absolute / fixtureEncryptedChunkSize)
		start := int64(index) * fixtureEncryptedChunkSize
		plainSize := min(fixtureEncryptedChunkSize, r.desc.size-start)
		ciphertext := make([]byte, int(plainSize)+r.aead.Overhead())
		cipherOffset := int64(index) * (fixtureEncryptedChunkSize + int64(r.aead.Overhead()))
		if n, e := r.file.ReadAt(ciphertext, cipherOffset); e != nil || n != len(ciphertext) {
			clear(ciphertext)
			return 0, invalid("fixture encrypted chunk read")
		}
		plain, err := r.aead.Open(nil, r.desc.nonceFor(index), ciphertext, r.desc.aad(index))
		clear(ciphertext)
		if err != nil || int64(len(plain)) != plainSize {
			clear(plain)
			return 0, invalid("fixture encrypted chunk authentication")
		}
		within := absolute - start
		take := min(plainSize-within, length-copied)
		copy(stage[copied:copied+take], plain[within:within+take])
		clear(plain)
		copied += take
	}
	copy(out, stage)
	if length < int64(len(out)) {
		return int(length), io.EOF
	}
	return int(length), nil
}

func (r *encryptedSnapshotFixtureReader) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.desc.key[:])
	r.aead = nil
	r.file = nil
	r.closed = true
}
