package mediacrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

func TestBrowserSessionWrapMultipleFilesFixedExpiryAndRevocation(t *testing.T) {
	manager, _ := New(bytes.Repeat([]byte{1}, 32))
	now := time.Unix(1800000000, 0)
	manager.now = func() time.Time { return now }
	client, _ := ecdh.P256().GenerateKey(rand.Reader)
	grant, err := manager.NewSession("cookie-session", base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := base64.StdEncoding.DecodeString(grant.PublicKey)
	server, _ := ecdh.P256().NewPublicKey(encoded)
	shared, _ := client.ECDH(server)
	salt, _ := base64.StdEncoding.DecodeString(grant.Salt)
	wrapping := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte("frontiercloud:browser-wrap:v1:"+grant.SessionID)), wrapping); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(wrapping)
	aead, _ := cipher.NewGCM(block)
	for _, size := range []int64{1, ChunkSize, ChunkSize + 1} {
		meta, _ := NewMetadata(size)
		wrapped, err := manager.Wrap("cookie-session", grant.SessionID, meta)
		if err != nil || wrapped.ExpiresAt != grant.ExpiresAt {
			t.Fatal(wrapped, err)
		}
		iv, _ := base64.StdEncoding.DecodeString(wrapped.IV)
		data, _ := base64.StdEncoding.DecodeString(wrapped.WrappedKey)
		key, err := aead.Open(nil, iv, data, []byte("frontiercloud:key-envelope:v1:"+grant.SessionID+":"+meta.FileID))
		expected, _ := manager.FileKey(meta)
		if err != nil || !bytes.Equal(key, expected) {
			t.Fatal("browser HKDF/envelope mismatch", err)
		}
		if _, err = manager.Wrap("different-cookie", grant.SessionID, meta); !errors.Is(err, ErrSession) {
			t.Fatal("cross-session key disclosure", err)
		}
		now = now.Add(time.Minute)
	}
	meta, _ := NewMetadata(10)
	now = time.Unix(grant.ExpiresAt, 0)
	if _, err = manager.Wrap("cookie-session", grant.SessionID, meta); !errors.Is(err, ErrSession) {
		t.Fatal("expired grant accepted", err)
	}
	grant, err = manager.NewSession("cookie-session", base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	manager.RevokeBinding("cookie-session")
	if _, err = manager.Wrap("cookie-session", grant.SessionID, meta); !errors.Is(err, ErrSession) {
		t.Fatal("revoked grant accepted", err)
	}
}

func TestChunkIdentitySizeOrderAndIntegrityAuthentication(t *testing.T) {
	manager, _ := New(bytes.Repeat([]byte{9}, 32))
	meta, _ := NewMetadata(ChunkSize + 3)
	key, _ := manager.FileKey(meta)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	plain := bytes.Repeat([]byte{0x41}, int(meta.PlaintextSize))
	var stored []byte
	for index := uint32(0); int64(index)*ChunkSize < meta.PlaintextSize; index++ {
		nonce, _ := meta.ChunkNonce(index)
		start := int64(index) * ChunkSize
		end := min(start+ChunkSize, meta.PlaintextSize)
		chunk := aead.Seal(nil, nonce, plain[start:end], meta.ChunkAAD(index))
		stored = append(stored, chunk...)
		decoded, err := aead.Open(nil, nonce, chunk, meta.ChunkAAD(index))
		if err != nil || !bytes.Equal(decoded, plain[start:end]) {
			t.Fatal(err)
		}
		chunk[len(chunk)-1] ^= 1
		if _, err = aead.Open(nil, nonce, chunk, meta.ChunkAAD(index)); err == nil {
			t.Fatal("corrupted tag accepted")
		}
		chunk[len(chunk)-1] ^= 1
		if _, err = aead.Open(nil, nonce, chunk, meta.ChunkAAD(index+1)); err == nil {
			t.Fatal("reordered chunk accepted")
		}
		wrong := meta
		wrong.PlaintextSize++
		if _, err = aead.Open(nil, nonce, chunk, wrong.ChunkAAD(index)); err == nil {
			t.Fatal("changed size accepted")
		}
	}
	if int64(len(stored)) != meta.CiphertextSize {
		t.Fatal("cipher size mismatch")
	}
	if _, err := meta.ChunkNonce(2); !errors.Is(err, ErrMetadata) {
		t.Fatal("out-of-range counter", err)
	}
}

func TestPreparationAuthenticatedBoundedAndPersistentPremaster(t *testing.T) {
	directory := t.TempDir()
	manager, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	meta, _ := NewMetadata(10)
	token, err := manager.SignPreparation("binding", meta)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.VerifyPreparation("binding", token, meta); err != nil {
		t.Fatal(err)
	}
	changed := meta
	changed.NoncePrefix = base64.StdEncoding.EncodeToString(make([]byte, 8))
	if manager.VerifyPreparation("binding", token, changed) == nil || manager.VerifyPreparation("other", token, meta) == nil {
		t.Fatal("modified preparation accepted")
	}
	reopened, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := manager.FileKey(meta)
	second, _ := reopened.FileKey(meta)
	if !bytes.Equal(first, second) {
		t.Fatal("premaster changed on restart")
	}
	if err = os.WriteFile(filepath.Join(directory, "media-premaster.key"), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(directory); err == nil {
		t.Fatal("malformed premaster regenerated")
	}
	manager.now = func() time.Time { return time.Now().Add(SessionLifetime + time.Second) }
	if manager.VerifyPreparation("binding", token, meta) == nil {
		t.Fatal("expired preparation accepted")
	}
}

func TestMissingPremasterWithEncryptedDataFailsClosed(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if _, err := OpenForData(directory, true); err == nil {
		t.Fatal("missing directory initialized despite encrypted data")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenForData(directory, true); err == nil {
		t.Fatal("missing key initialized despite encrypted data")
	}
	if _, err := OpenForData(directory, false); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenForData(directory, true); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMetadata(MaxPlaintextSize + 1); err == nil {
		t.Fatal("prepare allowed ciphertext above storage capacity limit")
	}
	meta, err := NewMetadata(MaxPlaintextSize)
	if err != nil || meta.CiphertextSize > MaxCiphertextSize {
		t.Fatal("maximum plaintext calculation", meta, err)
	}
}

func TestPremasterFingerprintMatchesOnlyOriginalSecret(t *testing.T) {
	a, err := New(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	restored, _ := New(bytes.Repeat([]byte{1}, 32))
	other, _ := New(bytes.Repeat([]byte{2}, 32))
	if len(a.KeyID()) != 64 || a.KeyID() != restored.KeyID() || a.KeyID() == other.KeyID() {
		t.Fatal("fingerprint does not identify durable secret")
	}
}

func TestPremasterRejectsSymlinkAndNonRegularFile(t *testing.T) {
	t.Run("nonregular", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Mkdir(filepath.Join(directory, "media-premaster.key"), 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenForData(directory, false); err == nil {
			t.Fatal("nonregular premaster accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(target, make([]byte, 32), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, "media-premaster.key")); err != nil {
			t.Skip("host does not support unprivileged symlinks")
		}
		if _, err := OpenForData(directory, false); err == nil {
			t.Fatal("symlink premaster accepted")
		}
	})
}
