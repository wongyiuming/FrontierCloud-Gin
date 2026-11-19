//go:build linux

package migrationdata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestOpaqueMediaTransferInstallsVerifiedBlobAndReplays(t *testing.T) {
	ctx := context.Background()
	meta, err := mediacrypto.NewMetadata(24)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0x73}, int(meta.CiphertextSize))
	_, legacy, root := fixture(t, data)
	binding := opaqueTestBinding(t, legacy, data, &meta)
	transfer, err := OpenOpaqueMediaTransfer(root, binding.Target.OwnerID, binding, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transfer.Begin(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = transfer.Append(ctx, 0, data, sha(data)); err != nil {
		t.Fatal(err)
	}
	if _, err = transfer.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	publisher, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	install := func(stage string, file *os.File, preHash os.FileInfo) error {
		return publisher.InstallVerifiedMigrationBlob(ctx, stage, binding.Target.Blob, binding.Target.Size, file, preHash)
	}
	admit := func() error { return nil }
	interrupted := errors.New("test interruption after the opaque link")
	progress, err := transfer.Publish(ctx, admit, func(stage string, file *os.File, preHash os.FileInfo) error {
		if err := install(stage, file, preHash); err != nil {
			return err
		}
		return interrupted
	})
	if !errors.Is(err, interrupted) || progress.State != "publishing" {
		t.Fatalf("interrupted install lost its durable publishing state: %+v, %v", progress, err)
	}
	if _, err = transfer.Abort(ctx, admit); !errors.Is(err, ErrState) {
		t.Fatalf("generic abort accepted an installed target: %v", err)
	}
	transfer, err = OpenOpaqueMediaTransfer(root, binding.Target.OwnerID, binding, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if progress, err = transfer.Publish(ctx, admit, install); err != nil || progress.State != "published" {
		t.Fatalf("same-bound recovery failed: %+v, %v", progress, err)
	}
	stage, _, _ := names(transfer.spec)
	stageInfo, err := root.Lstat(stage)
	if err != nil {
		t.Fatal(err)
	}
	dest, err := sealedtree.BlobPath(binding.Target.Blob)
	if err != nil {
		t.Fatal(err)
	}
	destInfo, err := root.Lstat(dest)
	if err != nil || !os.SameFile(stageInfo, destInfo) {
		t.Fatalf("recovered publication does not share the original inode: %v", err)
	}
	if body, err := root.ReadFile(dest); err != nil || !bytes.Equal(body, data) {
		t.Fatalf("recovered opaque bytes differ: %v", err)
	}
}
