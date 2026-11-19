package migrationdata

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
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

func opaqueTestBinding(t *testing.T, legacy Spec, data []byte, meta *mediacrypto.Metadata) OpaqueMediaBinding {
	t.Helper()
	descriptor, err := protocol.IngressMediaDescriptor(int64(len(data)), meta)
	if err != nil {
		t.Fatal(err)
	}
	owner := func(id, relationship, alias, blob string) protocol.OpaqueOwnerBinding {
		revision, err := protocol.OpaquePlacementRevisionFromDescriptor(alias, blob, sha(data), descriptor, int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		return protocol.OpaqueOwnerBinding{
			MasterID: legacy.MasterID, OwnerID: id, RelationshipID: relationship,
			Alias: alias, Blob: blob, Revision: revision, Digest: sha(data), Descriptor: descriptor, Size: int64(len(data)),
		}
	}
	return OpaqueMediaBinding{
		TaskID: legacy.TaskID,
		Source: owner(legacy.SourceID, strings.Repeat("1", 32), legacy.LogicalID, strings.Repeat("2", 64)),
		Target: owner(legacy.TargetID, strings.Repeat("3", 32), strings.Repeat("4", 64), strings.Repeat("5", 64)),
	}
}

func TestOpaqueMediaResumesOnlyExactCiphertextBinding(t *testing.T) {
	ctx := context.Background()
	plain := bytes.Repeat([]byte{0x4d}, ChunkBytes+3)
	meta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte("opaque migration fixture AES key"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := meta.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	data := aead.Seal(nil, nonce, plain, meta.ChunkAAD(0))
	legacy, spec, root := fixture(t, data)
	binding := opaqueTestBinding(t, spec, data, &meta)
	var blocked error
	guard := func(context.Context) error { return blocked }
	if _, err := OpenOpaqueMediaTransfer(root, spec.TargetID, opaqueTestBinding(t, spec, data, nil), guard); !errors.Is(err, ErrState) {
		t.Fatalf("nonempty plaintext descriptor accepted: %v", err)
	}
	if _, err := legacy.Begin(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root, spec.TargetID, opaqueMediaResource); !errors.Is(err, ErrState) {
		t.Fatalf("legacy constructor opened opaque transfer: %v", err)
	}
	open := func(value OpaqueMediaBinding) *OpaqueMediaTransfer {
		t.Helper()
		transfer, err := OpenOpaqueMediaTransfer(root, spec.TargetID, value, guard)
		if err != nil {
			t.Fatal(err)
		}
		return transfer
	}
	transfer := open(binding)
	if state, err := transfer.Begin(ctx); err != nil || state.State != "receiving" {
		t.Fatal(state, err)
	}
	first, last := data[:ChunkBytes], data[ChunkBytes:]
	if state, err := transfer.Append(ctx, 0, first, sha(first)); err != nil || state.Offset != ChunkBytes {
		t.Fatal(state, err)
	}
	changed := binding
	changed.Target.RelationshipID = strings.Repeat("6", 32)
	if _, err := open(changed).Begin(ctx); !errors.Is(err, ErrState) {
		t.Fatalf("changed target relationship reused checkpoint: %v", err)
	}
	transfer = open(binding)
	if state, err := transfer.Begin(ctx); err != nil || state.Offset != ChunkBytes || state.PrefixSHA != sha(first) {
		t.Fatal(state, err)
	}
	if state, err := transfer.Append(ctx, 0, first, sha(first)); err != nil || state.Offset != ChunkBytes {
		t.Fatal(state, err)
	}
	if _, err := transfer.Append(ctx, ChunkBytes, last, sha(first)); !errors.Is(err, ErrState) {
		t.Fatalf("wrong chunk hash accepted: %v", err)
	}
	blocked = errors.New("admission revoked")
	if _, err := transfer.Status(ctx); !errors.Is(err, blocked) {
		t.Fatalf("revoked transfer exposed status: %v", err)
	}
	if _, err := transfer.Append(ctx, ChunkBytes, last, sha(last)); !errors.Is(err, blocked) {
		t.Fatalf("revoked transfer accepted a write: %v", err)
	}
	blocked = nil
	if state, err := transfer.Status(ctx); err != nil || state.Offset != ChunkBytes {
		t.Fatal(state, err)
	}
	if state, err := transfer.Append(ctx, ChunkBytes, last, sha(last)); err != nil || state.State != "received" {
		t.Fatal(state, err)
	}
	if state, err := transfer.Verify(ctx); err != nil || state.State != "verified" || state.PrefixSHA != sha(data) {
		t.Fatal(state, err)
	}
	reader, closeReader, err := transfer.receiver.VerifiedReader(ctx, transfer.spec)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(reader)
	closeReader()
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatalf("verified reader returned different bytes: %v", err)
	}
	stage, journal, _ := names(transfer.spec)
	saved, err := root.ReadFile(journal)
	if err != nil || bytes.Contains(saved, []byte(spec.TargetPath)) || bytes.Contains(saved, []byte(meta.FileID)) ||
		bytes.Contains(saved, []byte(meta.NoncePrefix)) || bytes.Contains(saved, []byte(hex.EncodeToString(key[:]))) ||
		bytes.Contains(saved, []byte(`"encryption"`)) {
		t.Fatalf("checkpoint should contain only opaque identities: %v", err)
	}
	if _, err := transfer.Abort(ctx, nil); !errors.Is(err, ErrState) {
		t.Fatalf("cleanup accepted without unpublished proof: %v", err)
	}
	if state, err := transfer.Abort(ctx, func() error { return nil }); err != nil || state.State != "aborted" {
		t.Fatal(state, err)
	}
	if _, err := root.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging bytes survived accepted abort: %v", err)
	}
	if checkpoint, err := legacy.Status(ctx, spec); err != nil || checkpoint.Offset != 0 || checkpoint.State != "receiving" {
		t.Fatal(checkpoint, err)
	}
}

func TestOpaqueMediaVerifiesCanonicalEmptyObject(t *testing.T) {
	ctx := context.Background()
	_, spec, root := fixture(t, nil)
	binding := opaqueTestBinding(t, spec, nil, nil)
	transfer, err := OpenOpaqueMediaTransfer(root, spec.TargetID, binding, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if state, err := transfer.Begin(ctx); err != nil || state.State != "received" || state.Offset != 0 || state.PrefixSHA != sha(nil) {
		t.Fatal(state, err)
	}
	if state, err := transfer.Verify(ctx); err != nil || state.State != "verified" {
		t.Fatal(state, err)
	}
}

func TestOpaqueMediaPublicationReopensAfterInterruptedInstall(t *testing.T) {
	ctx := context.Background()
	_, spec, root := fixture(t, nil)
	binding := opaqueTestBinding(t, spec, nil, nil)
	guard := func(context.Context) error { return nil }
	open := func() *OpaqueMediaTransfer {
		t.Helper()
		transfer, err := OpenOpaqueMediaTransfer(root, spec.TargetID, binding, guard)
		if err != nil {
			t.Fatal(err)
		}
		return transfer
	}
	transfer := open()
	if _, err := transfer.Begin(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := transfer.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	admission := func() error { return nil }
	interrupted := errors.New("interrupted before local install receipt")
	if state, err := transfer.Publish(ctx, admission, func(_ string, _ *os.File, _ os.FileInfo) error {
		return interrupted
	}); !errors.Is(err, interrupted) || state.State != "publishing" {
		t.Fatal(state, err)
	}
	transfer = open()
	if _, err := transfer.Abort(ctx, admission); !errors.Is(err, ErrState) {
		t.Fatalf("generic abort accepted after publication started: %v", err)
	}
	stage, _, _ := names(transfer.spec)
	if state, err := transfer.Publish(ctx, admission, func(name string, file *os.File, before os.FileInfo) error {
		actual, statErr := file.Stat()
		named, nameErr := root.Lstat(name)
		if statErr != nil || nameErr != nil || name != stage || !os.SameFile(before, actual) || !os.SameFile(before, named) {
			t.Fatalf("installation received a different inode: %v %v", statErr, nameErr)
		}
		return nil
	}); err != nil || state.State != "published" {
		t.Fatal(state, err)
	}
}
