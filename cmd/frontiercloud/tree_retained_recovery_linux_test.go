//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
)

func retainedTreeTestMounts(t *testing.T) [2]string {
	t.Helper()
	base := t.TempDir()
	paths := [2]string{filepath.Join(base, "data"), filepath.Join(base, "secrets")}
	for _, p := range paths {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(paths[0], 0755); err != nil {
		t.Fatal(err)
	}
	return paths
}

func retainedTreeTestFrames(t *testing.T, request runtimefacts.TreeRetainedRecoveryRequest, commit runtimefacts.TreeRetainedRecoveryCommit) *bytes.Buffer {
	t.Helper()
	var input bytes.Buffer
	for _, v := range []any{request, commit} {
		if err := json.NewEncoder(&input).Encode(v); err != nil {
			t.Fatal(err)
		}
	}
	return &input
}

func retainedTreeTestReplies(t *testing.T, request runtimefacts.TreeRetainedRecoveryRequest, output io.Reader) runtimefacts.TreeRetainedRecoveryReply {
	t.Helper()
	d := json.NewDecoder(output)
	var ready, complete runtimefacts.TreeRetainedRecoveryReply
	if d.Decode(&ready) != nil || d.Decode(&complete) != nil || d.Decode(new(any)) != io.EOF {
		t.Fatal("missing bounded runtime replies")
	}
	if ready.Phase != "ready" || complete.Phase != "complete" ||
		ready.Action != request.Action || complete.Action != request.Action ||
		ready.Nonce != request.Nonce || complete.Nonce != request.Nonce ||
		ready.BindingSHA256 != request.BindingSHA256 || complete.BindingSHA256 != request.BindingSHA256 ||
		ready.Mounts != complete.Mounts || ready.Already != nil {
		t.Fatal("runtime reply identity changed")
	}
	return complete
}

func TestRetainedTreeRuntimeHoldRequiresExactCommitAndStaysFenced(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	paths := retainedTreeTestMounts(t)
	gate, err := maintenance.Open(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	req := runtimefacts.TreeRetainedRecoveryRequest{Action: "hold", Nonce: strings.Repeat("a", 64), BindingSHA256: strings.Repeat("b", 64)}
	commit := runtimefacts.TreeRetainedRecoveryCommit{Nonce: req.Nonce, BindingSHA256: req.BindingSHA256}
	input := retainedTreeTestFrames(t, req, commit)
	if err := treeRetainedRecovery(ctx, input, io.Discard, paths); !errors.Is(err, maintenance.ErrState) {
		t.Fatal("hold accepted without the native maintenance fence", err)
	}
	if err := gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name  string
		input *bytes.Buffer
	}{
		{name: "unconfirmed", input: func() *bytes.Buffer {
			var input bytes.Buffer
			_ = json.NewEncoder(&input).Encode(req)
			return &input
		}()},
		{name: "wrong binding", input: retainedTreeTestFrames(t, req, runtimefacts.TreeRetainedRecoveryCommit{Nonce: req.Nonce, BindingSHA256: strings.Repeat("c", 64)})},
		{name: "trailing byte", input: func() *bytes.Buffer {
			input := retainedTreeTestFrames(t, req, commit)
			_ = input.WriteByte('\n')
			return input
		}()},
		{name: "duplicate field", input: bytes.NewBufferString(`{"action":"hold","action":"hold","nonce":"` + req.Nonce + `","binding_sha256":"` + req.BindingSHA256 + `"}` + "\n")},
		{name: "wrong action fields", input: retainedTreeTestFrames(t, runtimefacts.TreeRetainedRecoveryRequest{Action: req.Action, Nonce: req.Nonce, BindingSHA256: req.BindingSHA256, DatabaseRelative: "db.sqlite"}, commit)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := treeRetainedRecovery(ctx, test.input, io.Discard, paths); !errors.Is(err, errRetainedTreeRecoveryRequest) {
				t.Fatal("unsafe request accepted", err)
			}
			if held, err := gate.TreeRecoveryHeld(); err != nil || held {
				t.Fatal("rejected request installed a hold", held, err)
			}
		})
	}
	for range 2 {
		var output bytes.Buffer
		if err := treeRetainedRecovery(ctx, retainedTreeTestFrames(t, req, commit), &output, paths); err != nil {
			t.Fatal(err)
		}
		reply := retainedTreeTestReplies(t, req, &output)
		if reply.Already != nil || reply.Mounts.UID != uint32(os.Geteuid()) || reply.Mounts.Data.Inode == reply.Mounts.Secrets.Inode && reply.Mounts.Data.Device == reply.Mounts.Secrets.Device {
			t.Fatal("hold reply exceeded its admission")
		}
	}
	other := req
	other.BindingSHA256 = strings.Repeat("d", 64)
	if err := treeRetainedRecovery(ctx, retainedTreeTestFrames(t, other, runtimefacts.TreeRetainedRecoveryCommit{Nonce: req.Nonce, BindingSHA256: other.BindingSHA256}), io.Discard, paths); !errors.Is(err, maintenance.ErrState) {
		t.Fatal("replaced a hold owned by another plan", err)
	}
	if err := gate.Resume(ctx, func(context.Context) error { return nil }); !errors.Is(err, maintenance.ErrState) {
		t.Fatal("ordinary resume bypassed the recovery hold", err)
	}
}

func TestRetainedTreeRuntimeRejectsMountSwapBeforeCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	paths := retainedTreeTestMounts(t)
	enter := func(data string) *maintenance.Gate {
		t.Helper()
		gate, err := maintenance.Open(data)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = gate.Close() })
		if err := gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
		return gate
	}
	original := enter(paths[0])
	request := runtimefacts.TreeRetainedRecoveryRequest{Action: "hold", Nonce: strings.Repeat("a", 64), BindingSHA256: strings.Repeat("b", 64)}
	in, send := io.Pipe()
	reply, out := io.Pipe()
	defer send.Close()
	defer reply.Close()
	result := make(chan error, 1)
	go func() {
		defer in.Close()
		defer out.Close()
		result <- treeRetainedRecovery(ctx, in, out, paths)
	}()
	encoder := json.NewEncoder(send)
	if err := encoder.Encode(request); err != nil {
		t.Fatal(err)
	}
	var ready runtimefacts.TreeRetainedRecoveryReply
	if err := json.NewDecoder(reply).Decode(&ready); err != nil || ready.Phase != "ready" {
		t.Fatal("missing mount proof", err)
	}
	if err := os.Rename(paths[0], paths[0]+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths[0], 0755); err != nil {
		t.Fatal(err)
	}
	replacement := enter(paths[0])
	if err := encoder.Encode(runtimefacts.TreeRetainedRecoveryCommit{Nonce: request.Nonce, BindingSHA256: request.BindingSHA256}); err != nil {
		t.Fatal(err)
	}
	if err := send.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil || err.Error() != "retained tree runtime mount changed" {
		t.Fatal("mount swap passed the commit recheck", err)
	}
	for _, gate := range []*maintenance.Gate{original, replacement} {
		if held, err := gate.TreeRecoveryHeld(); err != nil || held {
			t.Fatal("mount swap installed a recovery hold", held, err)
		}
	}
}
