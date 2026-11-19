package media

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestOpaqueBrowserCipherUsesBoundedAEADAndRejectsDowngrade(t *testing.T) {
	root, _, service, _ := ownedFixture(t)
	ctx := context.Background()
	plaintext := []byte("synthetic encrypted playback")
	metadata, err := mediacrypto.NewMetadata(int64(len(plaintext)))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(bytes.Repeat([]byte{7}, 32))
	aead, _ := cipher.NewGCM(block)
	nonce, _ := metadata.ChunkNonce(0)
	ciphertext := aead.Seal(nil, nonce, plaintext, metadata.ChunkAAD(0))
	alias, blob := strings.Repeat("a", 64), strings.Repeat("b", 64)
	name, _ := sealedtree.BlobPath(blob)
	full := filepath.Join(root, filepath.FromSlash(name))
	if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(full, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ciphertext)
	digest := hex.EncodeToString(sum[:])
	descriptor, _ := protocol.IngressMediaDescriptor(int64(len(ciphertext)), &metadata)
	revision, _ := protocol.OpaquePlacementRevision(alias, blob, digest, int64(len(ciphertext)), &metadata)
	binding := OpaqueOwnerBinding{MasterID: strings.Repeat("1", 32), OwnerID: strings.Repeat("2", 32), RelationshipID: strings.Repeat("3", 32), Alias: alias, Blob: blob, Revision: revision, Digest: digest, Descriptor: descriptor, Size: int64(len(ciphertext))}
	if _, err = service.OpenAuthorizedOpaqueBrowserCipher(ctx, binding); err == nil {
		t.Fatal("unregistered owner admitted")
	}
	if err = service.RegisterOpaqueOwnerBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	wrong := binding
	wrong.OwnerID = strings.Repeat("4", 32)
	if _, err = service.OpenAuthorizedOpaqueBrowserCipher(ctx, wrong); err == nil {
		t.Fatal("different owner admitted")
	}
	plain := binding
	plain.Descriptor, _ = protocol.IngressMediaDescriptor(plain.Size, nil)
	plain.Revision, _ = protocol.OpaquePlacementRevisionFromDescriptor(alias, blob, digest, plain.Descriptor, plain.Size)
	if _, err = service.OpenAuthorizedOpaqueBrowserCipher(ctx, plain); err == nil {
		t.Fatal("plaintext descriptor admitted to browser ciphertext path")
	}
	// A malicious storage node may corrupt its ciphertext after registration.
	// The browser must reject the changed GCM block before delivering plaintext.
	ciphertext[1] ^= 1
	if err = os.WriteFile(full, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	opened, err := service.OpenAuthorizedOpaqueBrowserCipher(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(opened.Reader)
	opened.Close()
	if err != nil || len(service.plainIndexes) != 0 {
		t.Fatal("cipher range required an entire-file index", err)
	}
	if decoded, err := aead.Open(nil, nonce, got, metadata.ChunkAAD(0)); err == nil || len(decoded) != 0 {
		t.Fatal("changed ciphertext authenticated as plaintext")
	}
	if verified, err := service.OpenAuthorizedOpaqueBlob(ctx, binding); err == nil {
		verified.Close()
		t.Fatal("server-side complete verifier accepted the corrupt blob")
	}
}

func TestVerifiedOpaqueBlobReadAndReplacement(t *testing.T) {
	root, _, service, _ := ownedFixture(t)
	ctx := context.Background()
	blob := strings.Repeat("a", 64)
	name, err := sealedtree.BlobPath(blob)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("abcde"), plainChunkBytes/5+10)
	if err := os.WriteFile(full, content, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if got, err := service.OpenVerifiedOpaqueBlob(ctx, blob, strings.Repeat("0", 64), int64(len(content))); err == nil || got != nil {
		t.Fatal("incorrect digest admitted")
	}
	if got, err := service.OpenVerifiedOpaqueBlob(ctx, "../../outside", digest, int64(len(content))); err == nil || got != nil {
		t.Fatal("path accepted as blob")
	}
	if got, err := service.OpenVerifiedOpaqueBlob(ctx, blob, digest, int64(len(content)-1)); err == nil || got != nil {
		t.Fatal("wrong size admitted")
	}
	opened, err := service.OpenVerifiedOpaqueBlob(ctx, blob, digest, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	written := make(chan error, 1)
	go func() {
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		unlock, err := service.acquire(wait, true)
		if err == nil {
			unlock()
		}
		written <- err
	}()
	select {
	case err := <-written:
		t.Fatal("writer bypassed blob read fence", err)
	case <-time.After(100 * time.Millisecond):
	}
	start := int64(plainChunkBytes - 3)
	if _, err = opened.Reader.Seek(start, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 10)
	if _, err = io.ReadFull(opened.Reader, got); err != nil || !bytes.Equal(got, content[start:start+10]) {
		t.Fatal("cross-block range", err)
	}
	opened.Close()
	opened.Close()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blob writer deadlocked")
	}
	// Same-length replacement after a warm cache must not expose any changed byte.
	content[plainChunkBytes] ^= 0xff
	if err := os.WriteFile(full, content, 0600); err != nil {
		t.Fatal(err)
	}
	replaced, err := service.OpenVerifiedOpaqueBlob(ctx, blob, digest, int64(len(content)))
	if err != nil && !errors.Is(err, store.ErrNodeState) {
		t.Fatal(err)
	}
	if err == nil {
		defer replaced.Close()
		if _, err := replaced.Reader.Seek(plainChunkBytes, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if n, err := replaced.Reader.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatal("changed cached blob byte was exposed")
		}
	}
}

func TestOpaqueReadinessUsesOnlySyntheticBlob(t *testing.T) {
	_, _, service, _ := ownedFixture(t)
	if err := service.ProbeVerifiedOpaqueBlob(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.ProbeVerifiedOpaqueBlob(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled probe admitted", err)
	}
}

func TestVerifiedOpaqueEmptyBlobRejectsTruncationAndWrongDigest(t *testing.T) {
	root, _, service, _ := ownedFixture(t)
	ctx := context.Background()
	blob := strings.Repeat("b", 64)
	name, err := sealedtree.BlobPath(blob)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, nil, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nil)
	digest := hex.EncodeToString(sum[:])
	opened, err := service.OpenVerifiedOpaqueBlob(ctx, blob, digest, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(opened.Reader); err != nil || len(got) != 0 {
		t.Fatal("empty blob read", len(got), err)
	}
	opened.Close()
	if got, err := service.OpenVerifiedOpaqueBlob(ctx, blob, strings.Repeat("f", 64), 0); err == nil || got != nil {
		t.Fatal("empty blob accepted wrong digest")
	}
	if got, err := service.OpenVerifiedOpaqueBlob(ctx, blob, digest, 1); err == nil || got != nil {
		t.Fatal("truncated nonempty object accepted as empty")
	}
	if err := os.WriteFile(full, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := service.OpenVerifiedOpaqueBlob(ctx, blob, digest, 0); err == nil || got != nil {
		t.Fatal("nonempty object accepted as empty")
	}
}
