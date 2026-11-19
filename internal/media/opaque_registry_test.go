package media

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestOpaqueOwnerRevocationFencesReadAndSurvivesRestart(t *testing.T) {
	root, db, service, _ := ownedFixture(t)
	ctx := context.Background()
	content := []byte("synthetic owner data")
	alias, blob := strings.Repeat("a", 64), strings.Repeat("b", 64)
	name, err := sealedtree.BlobPath(blob)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, content, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	descriptor, err := protocol.IngressMediaDescriptor(int64(len(content)), nil)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := protocol.OpaquePlacementRevision(alias, blob, digest, int64(len(content)), nil)
	if err != nil {
		t.Fatal(err)
	}
	binding := OpaqueOwnerBinding{MasterID: strings.Repeat("1", 32), OwnerID: strings.Repeat("2", 32), RelationshipID: strings.Repeat("3", 32), Alias: alias, Blob: blob, Revision: revision, Digest: digest, Descriptor: descriptor, Size: int64(len(content))}
	if stream, err := service.OpenAuthorizedOpaqueBlob(ctx, binding); err == nil || stream != nil {
		t.Fatal("unregistered owner binding admitted")
	}
	if err := service.RegisterOpaqueOwnerBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(filepath.Join(root, opaqueRegistryDirectory, alias+".active"))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{binding.MasterID, binding.OwnerID, binding.RelationshipID, binding.Alias, binding.Blob, binding.Digest, binding.Revision, binding.Descriptor} {
		if bytes.Contains(sealed, []byte(private)) {
			t.Fatal("owner registry wrote sensitive index fields in plaintext")
		}
	}
	swapped := opaqueRegistryFile(strings.Repeat("f", 64), ".active")
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(swapped)), sealed, 0600); err != nil {
		t.Fatal(err)
	}
	var swappedBinding OpaqueOwnerBinding
	if err := service.readOpaqueRecord(swapped, &swappedBinding); err == nil {
		t.Fatal("ciphertext moved to another registry path was accepted")
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(swapped)), sealed[:len(sealed)/2], 0600); err != nil {
		t.Fatal(err)
	}
	if err := service.readOpaqueRecord(swapped, &swappedBinding); err == nil {
		t.Fatal("truncated registry record accepted")
	}
	// A crash during the first active-record write leaves a damaged record.
	// Retrying may not silently overwrite it or authorize any data.
	interrupted := binding
	interrupted.Alias, interrupted.Blob = strings.Repeat("f", 64), strings.Repeat("9", 64)
	interrupted.Revision, err = protocol.OpaquePlacementRevision(interrupted.Alias, interrupted.Blob, digest, int64(len(content)), nil)
	if err != nil {
		t.Fatal(err)
	}
	interruptedPath, _ := sealedtree.BlobPath(interrupted.Blob)
	interruptedFull := filepath.Join(root, filepath.FromSlash(interruptedPath))
	if err := os.MkdirAll(filepath.Dir(interruptedFull), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(interruptedFull, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := service.RegisterOpaqueOwnerBinding(ctx, interrupted); err == nil {
		t.Fatal("interrupted encrypted binding was overwritten")
	}
	if stream, err := service.OpenAuthorizedOpaqueBlob(ctx, interrupted); err == nil || stream != nil {
		t.Fatal("interrupted encrypted binding authorized a read")
	}
	if _, err := os.Stat(interruptedFull); err != nil {
		t.Fatal("interrupted binding changed object data", err)
	}
	if err := service.RegisterOpaqueOwnerBinding(ctx, binding); err != nil {
		t.Fatal("identical registration did not replay", err)
	}
	other := binding
	other.RelationshipID = strings.Repeat("4", 32)
	if stream, err := service.OpenAuthorizedOpaqueBlob(ctx, other); err == nil || stream != nil {
		t.Fatal("different relationship admitted")
	}
	if err := service.RegisterOpaqueOwnerBinding(ctx, other); err == nil {
		t.Fatal("alias reassignment accepted")
	}
	duplicateBlob := binding
	duplicateBlob.Alias = strings.Repeat("c", 64)
	duplicateBlob.Revision, err = protocol.OpaquePlacementRevision(duplicateBlob.Alias, blob, digest, int64(len(content)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RegisterOpaqueOwnerBinding(ctx, duplicateBlob); err == nil {
		t.Fatal("one blob was activated under two aliases")
	}
	stream, err := service.OpenAuthorizedOpaqueBlob(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	read, err := io.ReadAll(stream.Reader)
	if err != nil || string(read) != string(content) {
		stream.Close()
		t.Fatal("authorized owner read", err)
	}
	operation := strings.Repeat("5", 32)
	wait, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if err := service.RevokeOpaqueOwnerBinding(wait, operation, binding); !errors.Is(err, context.DeadlineExceeded) {
		stream.Close()
		t.Fatal("revoke bypassed held read", err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestOpaqueOwnerRevokeChild$", "-test.v")
	child.Env = append(os.Environ(), "FC_OPAQUE_REVOKE_ROOT="+root)
	pipe, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = io.Discard
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _, _ = child.Process.Wait() })
	lines := make(chan string, 8)
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	waitFor := func(want string) {
		t.Helper()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case line, open := <-lines:
				if !open {
					t.Fatal("revoke child exited before", want)
				}
				if line == want {
					return
				}
			case <-timer.C:
				t.Fatal("timed out waiting for revoke child", want)
			}
		}
	}
	waitFor("opaque-revoke-started")
	select {
	case line := <-lines:
		if line == "opaque-revoke-done" {
			t.Fatal("separate process bypassed held owner read")
		}
	case <-time.After(150 * time.Millisecond):
	}
	stream.Close()
	waitFor("opaque-revoke-done")
	if err := child.Wait(); err != nil {
		t.Fatal("revoke child", err)
	}
	if err := service.RevokeOpaqueOwnerBinding(ctx, operation, binding); err != nil {
		t.Fatal(err)
	}
	sealedRevocation, err := os.ReadFile(filepath.Join(root, opaqueRegistryDirectory, alias+".revoked"))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{binding.MasterID, binding.OwnerID, binding.RelationshipID, binding.Alias, binding.Blob, binding.Digest, binding.Revision, binding.Descriptor, operation} {
		if bytes.Contains(sealedRevocation, []byte(private)) {
			t.Fatal("owner revocation index wrote sensitive fields in plaintext")
		}
	}
	if err := service.RevokeOpaqueOwnerBinding(ctx, operation, binding); err != nil {
		t.Fatal("revoke retry failed", err)
	}
	if err := service.RevokeOpaqueOwnerBinding(ctx, strings.Repeat("6", 32), binding); err == nil {
		t.Fatal("different operation overwrote tombstone")
	}
	if stream, err := service.OpenAuthorizedOpaqueBlob(ctx, binding); err == nil || stream != nil {
		t.Fatal("revoked binding admitted")
	}
	if err := service.RegisterOpaqueOwnerBinding(ctx, binding); err == nil {
		t.Fatal("revoked alias reactivated")
	}
	restarted, err := New(root, db.Media(), service.identity)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if stream, err := restarted.OpenAuthorizedOpaqueBlob(ctx, binding); err == nil || stream != nil {
		t.Fatal("revocation lost on restart")
	}
	// A malformed tombstone is denial evidence, not permission to recreate.
	if err := os.WriteFile(filepath.Join(root, opaqueRegistryDirectory, alias+".revoked"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if stream, err := restarted.OpenAuthorizedOpaqueBlob(ctx, binding); !errors.Is(err, store.ErrNodeState) || stream != nil {
		t.Fatal("corrupt tombstone admitted", err)
	}
}

func TestOpaqueOwnerRevokeChild(t *testing.T) {
	rootPath := os.Getenv("FC_OPAQUE_REVOKE_ROOT")
	if rootPath == "" {
		t.Skip("only used as a subprocess")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	service := &Service{root: root}
	fmt.Println("opaque-revoke-started")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := service.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	release()
	fmt.Println("opaque-revoke-done")
}
