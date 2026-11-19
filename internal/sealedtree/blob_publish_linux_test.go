//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestBlobPublicationAndRecovery(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p, _ := NewBlobPublisher(root)
	operation := strings.Repeat("a", 64)
	blob := strings.Repeat("b", 64)
	content := []byte("synthetic bytes with no business path")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if err := p.Publish(context.Background(), operation, blob, int64(len(content)), digest, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	dest, _ := BlobPath(blob)
	if err := verifyBlob(context.Background(), root, dest, int64(len(content)), digest); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyBlob(cancelled, root, dest, int64(len(content)), digest); !errors.Is(err, ErrBlobIncomplete) {
		t.Fatal("cancelled verification accepted", err)
	}
	// Repeating after a crash does not require the stream again.
	if err := p.Publish(context.Background(), operation, blob, int64(len(content)), digest, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	// Another operation cannot replace the existing destination.
	other := []byte("other bytes")
	otherSum := sha256.Sum256(other)
	if err := p.Publish(context.Background(), strings.Repeat("c", 64), blob, int64(len(other)), hex.EncodeToString(otherSum[:]), bytes.NewReader(other)); !errors.Is(err, ErrBlobIncomplete) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if err := verifyBlob(context.Background(), root, dest, int64(len(content)), digest); err != nil {
		t.Fatal(err)
	}
}

func TestBlobPublicationIncompleteNeverActivates(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p, _ := NewBlobPublisher(root)
	operation := strings.Repeat("d", 64)
	blob := strings.Repeat("e", 64)
	content := []byte("complete content")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if err := p.Publish(context.Background(), operation, blob, int64(len(content)), digest, bytes.NewReader(content[:4])); !errors.Is(err, ErrBlobIncomplete) {
		t.Fatalf("expected incomplete, got %v", err)
	}
	dest, _ := BlobPath(blob)
	if _, err := root.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected published blob: %v", err)
	}
	if err := p.Publish(context.Background(), operation, blob, int64(len(content)), digest, bytes.NewReader(content)); !errors.Is(err, ErrBlobIncomplete) {
		t.Fatalf("partial stage was reused: %v", err)
	}
	// Fresh operation ID permits an explicitly reconciled retry.
	if err := p.Publish(context.Background(), strings.Repeat("f", 64), blob, int64(len(content)), digest, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
}

func TestBlobPublicationRecoversCompleteStageWithoutPublishingUnverifiedData(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.MkdirAll("staging", 0700); err != nil {
		t.Fatal(err)
	}
	op := strings.Repeat("1", 64)
	blob := strings.Repeat("2", 64)
	content := []byte("complete staged bytes")
	stage, _ := stagePath(op)
	file, err := root.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	p, _ := NewBlobPublisher(root)
	if err := p.Publish(context.Background(), op, blob, int64(len(content)), hex.EncodeToString(sum[:]), bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	dest, _ := BlobPath(blob)
	if err := verifyBlob(context.Background(), root, dest, int64(len(content)), hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
}

func TestBlobPublicationRejectsInvalidIdentityAndCancelledContext(t *testing.T) {
	root, _ := os.OpenRoot(t.TempDir())
	defer root.Close()
	p, _ := NewBlobPublisher(root)
	id := strings.Repeat("a", 64)
	digest := sha256.Sum256(nil)
	if err := p.Publish(context.Background(), id, id, 0, hex.EncodeToString(digest[:]), bytes.NewReader(nil)); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Publish(ctx, id, strings.Repeat("b", 64), 0, hex.EncodeToString(digest[:]), bytes.NewReader(nil)); !errors.Is(err, ErrBlobIncomplete) {
		t.Fatal(err)
	}
}
