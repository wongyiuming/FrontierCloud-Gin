//go:build linux

package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestOpaqueOwnerDeletionRequiresDurableRevocationAndSingleLink(t *testing.T) {
	root, _, service, _ := ownedFixture(t)
	ctx := context.Background()
	data := []byte("synthetic deletion fixture")
	alias, blob := strings.Repeat("a", 64), strings.Repeat("b", 64)
	name, err := sealedtree.BlobPath(blob)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	descriptor, err := protocol.IngressMediaDescriptor(int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := protocol.OpaquePlacementRevision(alias, blob, digest, int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	binding := OpaqueOwnerBinding{MasterID: strings.Repeat("1", 32), OwnerID: strings.Repeat("2", 32), RelationshipID: strings.Repeat("3", 32), Alias: alias, Blob: blob, Revision: revision, Digest: digest, Descriptor: descriptor, Size: int64(len(data))}
	if err := service.RegisterOpaqueOwnerBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Dir(full)
	heldLeaf := leaf + "-held"
	for _, directory := range []string{filepath.Join(root, "objects"), filepath.Dir(leaf), leaf} {
		held := directory + "-held"
		if err := os.Rename(directory, held); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(held, directory); err != nil {
			t.Fatal(err)
		}
		if stream, err := service.OpenAuthorizedOpaqueBlob(ctx, binding); err == nil || stream != nil {
			t.Fatal("root-internal symlinked blob parent accepted")
		}
		if err := os.Remove(directory); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(held, directory); err != nil {
			t.Fatal(err)
		}
	}
	op := strings.Repeat("4", 32)
	receipt := protocol.OpaqueDeletionReceipt{Kind: "opaque-blob-delete-v1", OperationID: op, MasterID: binding.MasterID, OwnerID: binding.OwnerID, RelationshipID: binding.RelationshipID, Alias: alias, Blob: blob, Revision: revision, State: "deleted"}
	if err := service.DeleteOpaqueOwnerBlob(ctx, receipt); err == nil {
		t.Fatal("delete without revoked alias accepted")
	}
	if err := service.RevokeOpaqueOwnerBinding(ctx, op, binding); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(leaf, heldLeaf); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(heldLeaf, leaf); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteOpaqueOwnerBlob(ctx, receipt); err == nil {
		t.Fatal("symlinked parent authorized deletion")
	}
	if err := os.Remove(leaf); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(heldLeaf, leaf); err != nil {
		t.Fatal(err)
	}
	otherLink := filepath.Join(root, "fixture-extra-link")
	if err := os.Link(full, otherLink); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteOpaqueOwnerBlob(ctx, receipt); err == nil {
		t.Fatal("multiple linked blob falsely reported deleted")
	}
	if _, err := os.Stat(full); err != nil {
		t.Fatal("refusal modified blob", err)
	}
	if err := os.Remove(otherLink); err != nil {
		t.Fatal(err)
	}
	wrong := receipt
	wrong.OperationID = strings.Repeat("5", 32)
	if err := service.DeleteOpaqueOwnerBlob(ctx, wrong); err == nil {
		t.Fatal("wrong operation accepted")
	}
	if err := service.DeleteOpaqueOwnerBlob(ctx, receipt); err != nil {
		t.Fatal("delete", err)
	}
	if _, err := os.Stat(full); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("blob remains at owner path", err)
	}
	// Simulate unlink and intent surviving while the result record did not.
	if err := os.Remove(filepath.Join(root, opaqueRegistryDirectory, alias+".deleted")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(leaf, heldLeaf); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteOpaqueOwnerBlob(ctx, receipt); err == nil {
		t.Fatal("replacement directory produced a deletion proof")
	}
	if err := os.Remove(leaf); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(heldLeaf, leaf); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteOpaqueOwnerBlob(ctx, receipt); err != nil {
		t.Fatal("unlink crash recovery", err)
	}
	if err := service.DeleteOpaqueOwnerBlob(ctx, receipt); err != nil {
		t.Fatal("delete receipt replay", err)
	}
	// A restored path cannot be ignored when replaying the deletion receipt.
	if err := os.WriteFile(full, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteOpaqueOwnerBlob(ctx, receipt); err == nil {
		t.Fatal("receipt replay ignored reappearing blob")
	}
	if _, err := os.Stat(full); err != nil {
		t.Fatal("replay destroyed unexpected restored data", err)
	}
}
