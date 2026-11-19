//go:build linux

package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestOpaqueMasterLocalDeletionPinsCiphertextAndRecoversLostReply(t *testing.T) {
	ctx := context.Background()
	root, db, svc := masterFixture(t)
	owner := db.Nodes().(recoveryOwnerFixtureRepo)
	recoveryProofOwnerFence(t, root, svc, owner)
	lease, err := owner.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()

	meta, cipher := encryptedFixtureBytes(t, "authenticated media")
	sum := sha256.Sum256(cipher)
	placement := sealedtree.Placement{
		ObjectID: strings.Repeat("a", 64), NativeObjectID: strings.Repeat("a", 64), OwnerID: svc.identity.ID,
		BlobID: strings.Repeat("b", 64), ReadAlias: strings.Repeat("c", 64), State: "active",
		SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(cipher)), Encryption: &meta,
	}
	blob, err := sealedtree.BlobPath(placement.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(root, filepath.FromSlash(blob))
	if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	op := strings.Repeat("d", 32)
	journal := filepath.Join(root, filepath.FromSlash(opaqueRegistryFile(placement.BlobID, ".master-local-delete")))
	allow := func(context.Context) error { return nil }
	prepare := func(operation string) *OpaqueMasterLocalDeleteProof {
		t.Helper()
		p, err := svc.PrepareOpaqueMasterLocalDeletion(ctx, operation, placement)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	assertCipher := func() {
		t.Helper()
		if data, err := os.ReadFile(full); err != nil || !bytes.Equal(data, cipher) {
			t.Fatal("ciphertext was changed", err)
		}
	}
	missing := prepare(op)
	if err = svc.DeleteOpaqueMasterLocalBlob(ctx, lease, op, placement, missing, allow); err == nil {
		t.Fatal("absence was accepted before a durable local intent")
	}
	if err = os.WriteFile(full, cipher, 0600); err != nil {
		t.Fatal(err)
	}
	wrong := placement
	wrong.SHA256 = strings.Repeat("f", 64)
	if bad, err := svc.PrepareOpaqueMasterLocalDeletion(ctx, op, wrong); err == nil || bad != nil {
		t.Fatal("ciphertext digest mismatch was accepted")
	}
	extra := filepath.Join(root, "cipher-extra-link")
	if err = os.Link(full, extra); err != nil {
		t.Fatal(err)
	}
	if bad, err := svc.PrepareOpaqueMasterLocalDeletion(ctx, op, placement); err == nil || bad != nil {
		t.Fatal("multiply linked ciphertext was accepted")
	}
	if err = os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(full); err != nil {
		t.Fatal(err)
	}
	publication := strings.Repeat("7", 64)
	publisher, err := sealedtree.NewBlobPublisher(svc.root)
	if err != nil {
		t.Fatal(err)
	}
	if err = publisher.Publish(ctx, publication, placement.BlobID, placement.Bytes, placement.SHA256, bytes.NewReader(cipher)); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "staging", publication+".part")
	if bad, err := svc.PrepareOpaqueMasterLocalDeletion(ctx, op, placement); err == nil || bad != nil {
		t.Fatal("publisher's hard-linked blob admitted before exact stage cleanup")
	}
	if err = os.Link(full, extra); err != nil {
		t.Fatal(err)
	}
	if err = svc.ClearOpaqueMasterLocalDeletionStage(ctx, lease, publication, placement, allow); err == nil {
		t.Fatal("stage cleanup accepted an unrelated third link")
	}
	if _, err = os.Stat(stage); err != nil {
		t.Fatal("refused cleanup removed the stage", err)
	}
	if err = os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err = svc.ClearOpaqueMasterLocalDeletionStage(ctx, lease, publication, placement, allow); err != nil {
		t.Fatal("exact completed publication stage was not cleaned", err)
	}
	if _, err = os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed publication stage still links the blob", err)
	}
	if err = svc.ClearOpaqueMasterLocalDeletionStage(ctx, lease, publication, placement, allow); err != nil {
		t.Fatal("exact stage cleanup was not idempotent", err)
	}
	assertCipher()
	proof := prepare(op)
	if err = svc.DeleteOpaqueMasterLocalBlob(ctx, lease, strings.Repeat("e", 32), placement, proof, allow); err == nil {
		t.Fatal("proof accepted another operation")
	}
	reader, err := svc.acquire(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.DeleteOpaqueMasterLocalBlob(ctx, lease, op, placement, proof, allow)
	reader()
	if !errors.Is(err, filelease.ErrBusy) {
		t.Fatal("deletion failed to leave an admitted stream alone", err)
	}
	assertCipher()
	if err = os.WriteFile(journal+".prepare", []byte("partial owner journal"), 0600); err != nil {
		t.Fatal(err)
	}
	revoked := errors.New("the committed intent check was revoked")
	checks := 0
	if err = svc.DeleteOpaqueMasterLocalBlob(ctx, lease, op, placement, proof, func(context.Context) error {
		checks++
		if checks == 2 {
			return revoked
		}
		return nil
	}); !errors.Is(err, revoked) {
		t.Fatal("lost authority did not stop physical deletion", err)
	}
	assertCipher()
	if _, err = os.Lstat(journal + ".prepare"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial journal was not reclaimed", err)
	}
	if raw, err := os.ReadFile(journal); err != nil || bytes.Contains(raw, []byte(op)) || bytes.Contains(raw, []byte(placement.ObjectID)) {
		t.Fatal("durable local intent missing or exposes identity", err)
	}
	checks = 0
	if err = svc.DeleteOpaqueMasterLocalBlob(ctx, lease, op, placement, proof, func(context.Context) error {
		checks++
		if checks == 3 {
			return revoked
		}
		return nil
	}); !errors.Is(err, revoked) {
		t.Fatal("a lost final acknowledgement returned success", err)
	}
	if err = proof.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(full); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ciphertext was not removed", err)
	}
	if err = svc.DeleteOpaqueMasterLocalBlob(ctx, lease, op, placement, prepare(op), allow); err != nil {
		t.Fatal("lost acknowledgement retry failed", err)
	}
	otherOperation := strings.Repeat("e", 32)
	if err = svc.DeleteOpaqueMasterLocalBlob(ctx, lease, otherOperation, placement, prepare(otherOperation), allow); err == nil {
		t.Fatal("different operation accepted the prior physical removal")
	}
	if err = os.WriteFile(full, cipher, 0600); err != nil {
		t.Fatal(err)
	}
	if err = svc.DeleteOpaqueMasterLocalBlob(ctx, lease, op, placement, prepare(op), allow); err == nil {
		t.Fatal("replayed intent accepted a replacement inode with identical bytes")
	}
	assertCipher()
}
