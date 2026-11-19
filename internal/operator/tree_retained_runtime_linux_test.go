//go:build linux

package operator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
)

type retainedTreeTestPipe struct {
	bytes.Buffer
	closed bool
}

func (p *retainedTreeTestPipe) Close() error { p.closed = true; return nil }

func TestRetainedTreeExchangeChecksMountBeforeCommit(t *testing.T) {
	ctx := context.Background()
	req := runtimefacts.TreeRetainedRecoveryRequest{Action: "hold", Nonce: strings.Repeat("a", 64), BindingSHA256: strings.Repeat("b", 64)}
	expected := runtimefacts.TreeRetainedRecoveryMounts{UID: 10001, GID: 10001, Data: runtimefacts.TreeBackupMount{Device: 10, Inode: 11}, Secrets: runtimefacts.TreeBackupMount{Device: 10, Inode: 12}}
	reply := runtimefacts.TreeRetainedRecoveryReply{Phase: "ready", Action: req.Action, Nonce: req.Nonce, BindingSHA256: req.BindingSHA256, Mounts: expected}
	reply.Mounts.UIDMap = "0 0 4294967295"
	reply.Mounts.Data.Inode++
	var output bytes.Buffer
	if err := json.NewEncoder(&output).Encode(reply); err != nil {
		t.Fatal(err)
	}
	pipe := new(retainedTreeTestPipe)
	if err := exchangeRetainedTreeRuntime(ctx, pipe, bufio.NewReader(&output), req, expected, func(context.Context) error { return nil }, nil); err == nil {
		t.Fatal("accepted mount identity changed before commit")
	}
	if pipe.closed || bytes.Count(pipe.Bytes(), []byte("\n")) != 1 {
		t.Fatal("host sent more than the initial request")
	}

	reply.Mounts.Data.Inode = expected.Data.Inode
	encoder := json.NewEncoder(&output)
	if err := encoder.Encode(reply); err != nil {
		t.Fatal(err)
	}
	reply.Phase = "complete"
	if err := encoder.Encode(reply); err != nil {
		t.Fatal(err)
	}
	pipe = new(retainedTreeTestPipe)
	if err := exchangeRetainedTreeRuntime(ctx, pipe, bufio.NewReader(&output), req, expected, func(context.Context) error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(pipe)
	var got runtimefacts.TreeRetainedRecoveryRequest
	var commit runtimefacts.TreeRetainedRecoveryCommit
	if !pipe.closed || dec.Decode(&got) != nil || dec.Decode(&commit) != nil || got != req || commit.Nonce != req.Nonce || commit.BindingSHA256 != req.BindingSHA256 {
		t.Fatal("wrong retained tree commit")
	}
}

func TestRetainedTreeExchangeRequiresLocalProofAtCompletion(t *testing.T) {
	ctx := context.Background()
	req := runtimefacts.TreeRetainedRecoveryRequest{Action: "verify-local", Nonce: strings.Repeat("a", 64), BindingSHA256: strings.Repeat("b", 64)}
	mounts := runtimefacts.TreeRetainedRecoveryMounts{UID: 10001, GID: 10001}
	valid := runtimefacts.TreeRetainedLocalProof{Version: 1, Media: 1, LocalObjects: 1, LocalBytes: 7, CensusCommitment: strings.Repeat("c", 64), ProofCommitment: strings.Repeat("d", 64)}
	for _, tc := range []struct {
		name       string
		ready, end *runtimefacts.TreeRetainedLocalProof
		ok         bool
	}{
		{"complete", nil, &valid, true},
		{"missing", nil, nil, false},
		{"before commit", &valid, &valid, false},
		{"invalid", nil, &runtimefacts.TreeRetainedLocalProof{Version: 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			ready := runtimefacts.TreeRetainedRecoveryReply{Phase: "ready", Action: req.Action, Nonce: req.Nonce, BindingSHA256: req.BindingSHA256, Mounts: mounts, Local: tc.ready}
			ready.Mounts.UIDMap = "0 0 4294967295"
			complete := ready
			complete.Phase, complete.Local = "complete", tc.end
			enc := json.NewEncoder(&output)
			if err := enc.Encode(ready); err != nil {
				t.Fatal(err)
			}
			if err := enc.Encode(complete); err != nil {
				t.Fatal(err)
			}
			var got runtimefacts.TreeRetainedLocalProof
			pipe := new(retainedTreeTestPipe)
			err := exchangeRetainedTreeRuntime(ctx, pipe, bufio.NewReader(&output), req, mounts, func(context.Context) error { return nil }, &got)
			if tc.ok && (err != nil || got != valid) || !tc.ok && (err == nil || got.Valid()) {
				t.Fatalf("proof = %+v, error = %v", got, err)
			}
			if tc.ready != nil && pipe.closed {
				t.Fatal("commit sent after unsolicited proof")
			}
		})
	}
}
