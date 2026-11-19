//go:build linux

package selectedupload

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestSelectedOperationLeaseCrossProcess(t *testing.T) {
	if dir := os.Getenv("FC_SELECTED_LEASE_CHILD"); dir != "" {
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
		defer cancel()
		lease, err := acquireOperationLease(ctx, root, strings.Repeat("a", 64))
		if lease != nil {
			lease.Release()
			t.Fatal("another process acquired the held operation")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("expected bounded contention", err)
		}
		return
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	op := strings.Repeat("a", 64)
	lease, err := acquireOperationLease(context.Background(), root, op)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	other, err := acquireOperationLease(context.Background(), root, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal("different operation blocked", err)
	}
	other.Release()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSelectedOperationLeaseCrossProcess$")
	cmd.Env = append(os.Environ(), "FC_SELECTED_LEASE_CHILD="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	if err := lease.Check(context.Background()); err != nil {
		t.Fatal("lease not retained", err)
	}
	// A replaced lock inode is never accepted as the same cooperative lock.
	name := filepath.Join(dir, ".selected-upload-locks", op+".lock")
	if err = os.Rename(name, name+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = lease.Check(context.Background()); err == nil {
		t.Fatal("replaced lock accepted")
	}
}

func TestSelectedOperationCancellationHoldsBothLeasesUntilWriterExit(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := &testLease{}
	body := &testBody{closed: make(chan struct{})}
	started, allowExit, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var published, cleaned atomic.Bool
	op := strings.Repeat("c", 64)
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	claim := protocol.SelectedStorageUpload{Master: strings.Repeat("1", 32), Owner: strings.Repeat("2", 32), Relationship: strings.Repeat("3", 32), RelationshipBinding: strings.Repeat("4", 64), Generation: strings.Repeat("5", 64), StageID: strings.Repeat("6", 64), ObjectID: strings.Repeat("7", 64), ContentSHA256: strings.Repeat("8", 64), PublishChallenge: strings.Repeat("9", 64), CleanupChallenge: strings.Repeat("a", 64), OperationID: op, Size: 1}
	go func() {
		done <- RunOperationStaged(context.Background(), policy, &testDeadline{}, body, 100*time.Millisecond, root, v, claim, false, func(c context.Context) (func(), error) {
			close(started)
			<-c.Done()
			<-allowExit
			return func() { cleaned.Store(true) }, nil
		}, func(context.Context) error { published.Store(true); return nil })
	}()
	<-started
	<-body.closed
	if policy.released.Load() {
		t.Fatal("policy released while writer active")
	}
	blocked, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	other, err := acquireOperationLease(blocked, root, op)
	cancel()
	if other != nil {
		other.Release()
		t.Fatal("operation lock released while writer active")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("operation wait did not time out", err)
	}
	close(allowExit)
	if err = <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expected stream deadline", err)
	}
	if !policy.released.Load() || !cleaned.Load() || published.Load() {
		t.Fatal("invalid cancellation or cleanup order")
	}
	again, err := acquireOperationLease(context.Background(), root, op)
	if err != nil {
		t.Fatal("operation lock not released", err)
	}
	again.Release()
}

func TestSelectedOwnerIntentSurvivesRestartAndRejectsChangedBinding(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	claim := protocol.SelectedStorageUpload{Master: strings.Repeat("1", 32), Owner: strings.Repeat("2", 32), Relationship: strings.Repeat("3", 32), RelationshipBinding: strings.Repeat("4", 64), Generation: strings.Repeat("5", 64), StageID: strings.Repeat("6", 64), ObjectID: strings.Repeat("7", 64), ContentSHA256: strings.Repeat("8", 64), PublishChallenge: strings.Repeat("9", 64), CleanupChallenge: strings.Repeat("a", 64), OperationID: strings.Repeat("c", 64), Size: 1, AdminBinding: strings.Repeat("d", 64), ExpiresAt: 1}
	lease, err := acquireOperationLease(context.Background(), root, claim.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if err = persistOwnerIntent(context.Background(), root, v, claim, true, false); err == nil {
		t.Fatal("recovery created an absent intent")
	}
	if err = persistOwnerIntent(context.Background(), root, v, claim, false, false); err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	root, err = os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lease, err = acquireOperationLease(context.Background(), root, claim.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	claim.AdminBinding, claim.ExpiresAt = strings.Repeat("e", 64), 2
	if err = persistOwnerIntent(context.Background(), root, v, claim, true, false); err != nil {
		t.Fatal("authenticated retry changed only session", err)
	}
	changed := claim
	changed.StageID = strings.Repeat("b", 64)
	if err = persistOwnerIntent(context.Background(), root, v, changed, true, false); err == nil {
		t.Fatal("changed scope accepted")
	}
	data, err := root.ReadFile(".selected-upload-intents/" + claim.OperationID + ".intent")
	if err != nil || bytes.Contains(data, []byte(claim.ContentSHA256)) || bytes.Contains(data, []byte(claim.ObjectID)) {
		t.Fatal("owner intent was not encrypted", err)
	}
}

func TestRecordingOwnerIntentSurvivesDirectReapplicationOnSamePair(t *testing.T) {
	ctx := context.Background()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(1)
	if err != nil {
		t.Fatal(err)
	}
	claim := protocol.SelectedStorageUpload{
		Master: strings.Repeat("1", 32), Owner: strings.Repeat("2", 32), Relationship: strings.Repeat("3", 32),
		RelationshipBinding: strings.Repeat("4", 64), Generation: strings.Repeat("5", 64), StageID: strings.Repeat("6", 64),
		ObjectID: strings.Repeat("7", 64), ContentSHA256: strings.Repeat("8", 64), PublishChallenge: strings.Repeat("9", 64),
		CleanupChallenge: strings.Repeat("a", 64), OperationID: strings.Repeat("b", 64), MediaID: strings.Repeat("c", 64),
		UploadID: strings.Repeat("d", 32), AdminBinding: strings.Repeat("e", 64),
		Policy: "Direct", Revision: 1, ResourceOrigin: "https://original-owner.test", AdminOrigin: "https://master.test",
		RecordingIngressNode: strings.Repeat("1", 32), RecordingIngressGeneration: 1,
		Encryption: &meta, Size: meta.CiphertextSize, ExpiresAt: 160,
	}
	lease, err := acquireOperationLease(ctx, root, claim.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	credential := protocol.Encode(bytes.Repeat([]byte{7}, 48))
	uploadToken, err := protocol.SignSelectedRecordingUpload(credential, claim, 100)
	if err != nil {
		t.Fatal(err)
	}
	upload, err := protocol.VerifySelectedRecordingUpload(credential, uploadToken, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = persistOwnerIntent(ctx, root, v, upload, false, false); err != nil {
		t.Fatal(err)
	}
	claim.Revision, claim.ResourceOrigin = 2, "https://current-owner.test"
	claim.AdminOrigin, claim.RecordingIngressNode, claim.RecordingIngressGeneration = "https://ingress.test", claim.Owner, 2
	cleanupToken, err := protocol.SignSelectedRecordingCleanup(credential, claim, 100)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := protocol.VerifySelectedRecordingCleanup(credential, cleanupToken, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = persistOwnerIntent(ctx, root, v, cleanup, true, true); err != nil {
		t.Fatal("same durable operation rejected after Direct reapplication", err)
	}
	cleanup.RelationshipBinding = strings.Repeat("f", 64)
	if err = persistOwnerIntent(ctx, root, v, cleanup, true, true); err == nil {
		t.Fatal("different durable relationship binding accepted")
	}
}

func TestSelectedCleanupDrainsWriterAndTombstoneRejectsReplay(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	claim := protocol.SelectedStorageUpload{Master: strings.Repeat("1", 32), Owner: strings.Repeat("2", 32), Relationship: strings.Repeat("3", 32), RelationshipBinding: strings.Repeat("4", 64), Generation: strings.Repeat("5", 64), StageID: strings.Repeat("6", 64), ObjectID: strings.Repeat("7", 64), ContentSHA256: strings.Repeat("8", 64), PublishChallenge: strings.Repeat("9", 64), CleanupChallenge: strings.Repeat("a", 64), OperationID: strings.Repeat("c", 64), Size: 1}
	started, finish, uploadDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		uploadDone <- RunOperationStaged(context.Background(), &testLease{}, &testDeadline{}, &testBody{closed: make(chan struct{})}, 3*time.Second, root, v, claim, false, func(context.Context) (func(), error) { close(started); <-finish; return nil, nil }, func(context.Context) error { return nil })
	}()
	<-started
	cleanupDone := make(chan error, 1)
	var signed atomic.Bool
	go func() {
		cleanupDone <- RunOperationCleanup(context.Background(), &testLease{}, &testDeadline{}, &testBody{closed: make(chan struct{})}, 3*time.Second, root, v, claim, func(context.Context) error { signed.Store(true); return nil })
	}()
	select {
	case err := <-cleanupDone:
		t.Fatal("cleanup did not wait for writer", err)
	case <-time.After(150 * time.Millisecond):
	}
	if signed.Load() {
		t.Fatal("cleanup signed before writer drained")
	}
	close(finish)
	if err = <-uploadDone; err != nil {
		t.Fatal("upload drain", err)
	}
	if err = <-cleanupDone; err != nil || !signed.Load() {
		t.Fatal("cleanup after drain", err)
	}
	var staged atomic.Bool
	err = RunOperationStaged(context.Background(), &testLease{}, &testDeadline{}, &testBody{closed: make(chan struct{})}, time.Second, root, v, claim, false, func(context.Context) (func(), error) { staged.Store(true); return nil, nil }, func(context.Context) error { return nil })
	if err == nil || staged.Load() {
		t.Fatal("cancelled operation restarted", err)
	}
}

func TestSelectedCleanupBeforeUploadRejectsUnknownBytes(t *testing.T) {
	for _, scenario := range []string{"absent", "unknown-stage", "unknown-blob"} {
		t.Run(scenario, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			claim := protocol.SelectedStorageUpload{Master: strings.Repeat("1", 32), Owner: strings.Repeat("2", 32), Relationship: strings.Repeat("3", 32), RelationshipBinding: strings.Repeat("4", 64), Generation: strings.Repeat("5", 64), StageID: strings.Repeat("6", 64), ObjectID: strings.Repeat("7", 64), ContentSHA256: strings.Repeat("8", 64), PublishChallenge: strings.Repeat("9", 64), CleanupChallenge: strings.Repeat("a", 64), OperationID: strings.Repeat("c", 64), Size: 1}
			var unknown string
			if scenario == "unknown-stage" {
				unknown = "staging/" + claim.OperationID + ".part"
			}
			if scenario == "unknown-blob" {
				unknown = "objects/77/77/" + claim.ObjectID + ".blob"
			}
			if unknown != "" {
				if err = root.MkdirAll(path.Dir(unknown), 0700); err != nil {
					t.Fatal(err)
				}
				f, e := root.OpenFile(unknown, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = f.Write([]byte("unknown")); e != nil {
					t.Fatal(e)
				}
				f.Close()
			}
			signed := false
			err = RunOperationCleanup(context.Background(), &testLease{}, &testDeadline{}, &testBody{closed: make(chan struct{})}, time.Second, root, v, claim, func(context.Context) error { signed = true; return nil })
			if unknown != "" {
				if err == nil || signed {
					t.Fatal("unknown bytes were acknowledged", err)
				}
				data, e := root.ReadFile(unknown)
				if e != nil || string(data) != "unknown" {
					t.Fatal("unknown bytes removed", e)
				}
				return
			}
			if err != nil || !signed {
				t.Fatal("absent Owner intent cancellation", err)
			}
			if _, err = root.Lstat(".selected-upload-intents/" + claim.OperationID + ".cancelled"); err != nil {
				t.Fatal("missing cancellation tombstone", err)
			}
			called := false
			err = RunOperationStaged(context.Background(), &testLease{}, &testDeadline{}, &testBody{closed: make(chan struct{})}, time.Second, root, v, claim, false, func(context.Context) (func(), error) { called = true; return nil, nil }, func(context.Context) error { return nil })
			if err == nil || called {
				t.Fatal("old upload restarted after cancellation", err)
			}
		})
	}
}
