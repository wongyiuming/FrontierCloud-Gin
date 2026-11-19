package preprodimport

// Internal v2 stream primitives. A valid header or successful decryption is
// not an import permit; callers must first authenticate the signed manifest,
// target scope, capture intent, completeness and owner commitments.
import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const sourceStreamChunk int64 = 64 << 10

type sourceStreamHeader struct {
	Version     int    `json:"version"`
	CaptureID   string `json:"capture_id"`
	SourceNode  string `json:"source_node"`
	TargetNode  string `json:"target_node"`
	SourceKeyID string `json:"source_key_id"`
	Challenge   string `json:"challenge"`
	ScopeDigest string `json:"scope_sha256"`
	Receiver    string `json:"receiver_x25519"`
	Ephemeral   string `json:"ephemeral_x25519"`
	Salt        string `json:"salt"`
	Nonce       string `json:"nonce_prefix"`
	PlainSize   int64  `json:"plain_size"`
	ChunkSize   int64  `json:"chunk_size"`
}

func sourceStreamHeaderDigest(h sourceStreamHeader) ([32]byte, error) {
	var zero [32]byte
	if h.Version != 2 || !id32.MatchString(h.CaptureID) || !id32.MatchString(h.SourceNode) || !id32.MatchString(h.TargetNode) || h.SourceNode == h.TargetNode || !id64.MatchString(h.SourceKeyID) || !id64.MatchString(h.Challenge) || !id64.MatchString(h.ScopeDigest) || !id64.MatchString(h.Receiver) || !id64.MatchString(h.Ephemeral) || !id64.MatchString(h.Salt) || len(h.Nonce) != 16 || h.ChunkSize != sourceStreamChunk || h.PlainSize <= 0 || (uint64(h.PlainSize)-1)/uint64(sourceStreamChunk)+1 > uint64(1)<<32 {
		return zero, invalid("source stream header")
	}
	if _, err := hex.DecodeString(h.Nonce); err != nil {
		return zero, invalid("source stream nonce")
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return zero, err
	}
	defer clear(raw)
	return sha256.Sum256(append([]byte("frontiercloud:source-stream-header:v2\x00"), raw...)), nil
}

func newSourceStreamHeader(intent sourceCaptureIntent, receiver []byte, size int64) (sourceStreamHeader, *ecdh.PrivateKey, error) {
	var h sourceStreamHeader
	if !validSourceCaptureIntent(intent) || len(receiver) != 32 {
		return h, nil, invalid("source stream recipient")
	}
	if _, err := ecdh.X25519().NewPublicKey(receiver); err != nil {
		return h, nil, invalid("source stream recipient")
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return h, nil, err
	}
	var salt [32]byte
	var nonce [8]byte
	if _, err = io.ReadFull(rand.Reader, salt[:]); err != nil {
		return h, nil, err
	}
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return h, nil, err
	}
	h = sourceStreamHeader{Version: 2, CaptureID: intent.CaptureID, SourceNode: intent.SourceNode, TargetNode: intent.TargetNode, SourceKeyID: intent.SourceKeyID, Challenge: intent.Challenge, ScopeDigest: intent.ScopeDigest, Receiver: hex.EncodeToString(receiver), Ephemeral: hex.EncodeToString(private.PublicKey().Bytes()), Salt: hex.EncodeToString(salt[:]), Nonce: hex.EncodeToString(nonce[:]), PlainSize: size, ChunkSize: sourceStreamChunk}
	if _, err = sourceStreamHeaderDigest(h); err != nil {
		return sourceStreamHeader{}, nil, err
	}
	return h, private, nil
}

func sourceStreamAEAD(h sourceStreamHeader, private *ecdh.PrivateKey, sending bool) (cipher.AEAD, [32]byte, error) {
	var zero [32]byte
	digest, err := sourceStreamHeaderDigest(h)
	if err != nil || private == nil {
		return nil, zero, invalid("source stream key")
	}
	peerHex, ownHex := h.Ephemeral, h.Receiver
	if sending {
		peerHex, ownHex = h.Receiver, h.Ephemeral
	}
	own, err := hex.DecodeString(ownHex)
	if err != nil || subtle.ConstantTimeCompare(own, private.PublicKey().Bytes()) != 1 {
		return nil, zero, invalid("source stream private identity")
	}
	peerRaw, err := hex.DecodeString(peerHex)
	if err != nil {
		return nil, zero, invalid("source stream peer")
	}
	peer, err := ecdh.X25519().NewPublicKey(peerRaw)
	if err != nil {
		return nil, zero, err
	}
	shared, err := private.ECDH(peer)
	if err != nil {
		return nil, zero, invalid("source stream shared secret")
	}
	defer clear(shared)
	salt, err := hex.DecodeString(h.Salt)
	if err != nil {
		return nil, zero, err
	}
	key, err := hkdf.Key(sha256.New, shared, salt, "frontiercloud:source-stream-key:v2:"+hex.EncodeToString(digest[:]), 32)
	if err != nil {
		return nil, zero, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, zero, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, digest, err
}

func sourceStreamNonce(h sourceStreamHeader, index uint32) ([]byte, error) {
	prefix, err := hex.DecodeString(h.Nonce)
	if err != nil || len(prefix) != 8 {
		return nil, invalid("source stream nonce")
	}
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], index)
	return nonce, nil
}
func sourceStreamAAD(digest [32]byte, index uint32, length uint32) []byte {
	aad := append([]byte("frontiercloud:source-stream-chunk:v2\x00"), digest[:]...)
	var suffix [8]byte
	binary.BigEndian.PutUint32(suffix[:4], index)
	binary.BigEndian.PutUint32(suffix[4:], length)
	return append(aad, suffix[:]...)
}

// sealSourceStreamV2 never buffers more than one plaintext chunk and writes
// only ciphertext. A failed/partial stage must never be resumed with this key.
func sealSourceStreamV2(ctx context.Context, h sourceStreamHeader, private *ecdh.PrivateKey, dst io.Writer, src io.Reader) (plainSHA, cipherSHA [32]byte, err error) {
	if ctx == nil || dst == nil || src == nil || ctx.Err() != nil {
		return plainSHA, cipherSHA, invalid("source stream input")
	}
	aead, digest, err := sourceStreamAEAD(h, private, true)
	if err != nil {
		return plainSHA, cipherSHA, err
	}
	plainHash, cipherHash := sha256.New(), sha256.New()
	buf := make([]byte, sourceStreamChunk)
	defer clear(buf)
	count := (uint64(h.PlainSize)-1)/uint64(sourceStreamChunk) + 1
	for i := uint64(0); i < count; i++ {
		if err = ctx.Err(); err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		length := min(sourceStreamChunk, h.PlainSize-int64(i)*sourceStreamChunk)
		if _, err = io.ReadFull(src, buf[:length]); err != nil {
			return [32]byte{}, [32]byte{}, invalid("source stream truncated")
		}
		_, _ = plainHash.Write(buf[:length])
		nonce, e := sourceStreamNonce(h, uint32(i))
		if e != nil {
			return [32]byte{}, [32]byte{}, e
		}
		sealed := aead.Seal(nil, nonce, buf[:length], sourceStreamAAD(digest, uint32(i), uint32(length)))
		_, _ = cipherHash.Write(sealed)
		n, e := dst.Write(sealed)
		clear(sealed)
		if e != nil || n != int(length)+aead.Overhead() {
			return [32]byte{}, [32]byte{}, invalid("source stream output")
		}
	}
	var extra [1]byte
	if n, e := src.Read(extra[:]); n != 0 || !errors.Is(e, io.EOF) {
		return [32]byte{}, [32]byte{}, invalid("source stream length")
	}
	if err = ctx.Err(); err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	copy(plainSHA[:], plainHash.Sum(nil))
	copy(cipherSHA[:], cipherHash.Sum(nil))
	return plainSHA, cipherSHA, nil
}

// openSourceStreamV2 requires expected digests from an independently verified
// signed manifest. Plaintext emitted to dst is provisional until this returns
// nil; the caller must roll back its isolated import transaction on any error.
func openSourceStreamV2(ctx context.Context, h sourceStreamHeader, receiver *ecdh.PrivateKey, src *os.File, dst io.Writer, expectedPlain, expectedCipher [32]byte) error {
	if ctx == nil || src == nil || dst == nil || ctx.Err() != nil || expectedPlain == [32]byte{} || expectedCipher == [32]byte{} {
		return invalid("source stream receiver input")
	}
	aead, digest, err := sourceStreamAEAD(h, receiver, false)
	if err != nil {
		return err
	}
	count := (uint64(h.PlainSize)-1)/uint64(sourceStreamChunk) + 1
	if count > uint64((int64(^uint64(0)>>1)-h.PlainSize)/int64(aead.Overhead())) {
		return invalid("source stream ciphertext size")
	}
	size := h.PlainSize + int64(count)*int64(aead.Overhead())
	info, err := src.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return invalid("source stream ciphertext file")
	}
	cipherHash := sha256.New()
	buffer := make([]byte, sourceStreamChunk)
	defer clear(buffer)
	reader := io.NewSectionReader(src, 0, size)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, e := reader.Read(buffer)
		if n > 0 {
			_, _ = cipherHash.Write(buffer[:n])
		}
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return e
		}
	}
	if subtle.ConstantTimeCompare(cipherHash.Sum(nil), expectedCipher[:]) != 1 {
		return invalid("source stream ciphertext digest")
	}
	plainHash := sha256.New()
	var offset int64
	for i := uint64(0); i < count; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		length := min(sourceStreamChunk, h.PlainSize-int64(i)*sourceStreamChunk)
		ciphertext := make([]byte, int(length)+aead.Overhead())
		n, e := src.ReadAt(ciphertext, offset)
		offset += int64(len(ciphertext))
		if e != nil || n != len(ciphertext) {
			clear(ciphertext)
			return invalid("source stream ciphertext read")
		}
		nonce, e := sourceStreamNonce(h, uint32(i))
		if e != nil {
			clear(ciphertext)
			return e
		}
		plain, e := aead.Open(nil, nonce, ciphertext, sourceStreamAAD(digest, uint32(i), uint32(length)))
		clear(ciphertext)
		if e != nil || int64(len(plain)) != length {
			clear(plain)
			return invalid("source stream authentication")
		}
		_, _ = plainHash.Write(plain)
		n, e = dst.Write(plain)
		clear(plain)
		if e != nil {
			return errors.Join(invalid("source stream plaintext output"), e)
		}
		if int64(n) != length {
			return invalid("source stream plaintext output")
		}
	}
	if subtle.ConstantTimeCompare(plainHash.Sum(nil), expectedPlain[:]) != 1 {
		return invalid("source stream plaintext digest")
	}
	return ctx.Err()
}
