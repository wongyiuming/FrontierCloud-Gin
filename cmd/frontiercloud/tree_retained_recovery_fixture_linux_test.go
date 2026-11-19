//go:build linux && ledger_fixture

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestRetainedTreeRuntimeRebindUsesMatchingHold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	source := retainedTreeTestMounts(t)
	node, err := sealedtree.FixtureTreeCaptureMaster(ctx, source[0], source[1])
	if err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(source[0])
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	base := filepath.Join(t.TempDir(), "private-recovery")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(base, "state.tar")
	selection := append([]string{"db.sqlite", "db.sqlite-wal", "db.sqlite-shm", maintenance.Marker, ".native-runtime.lock", ".native-maintenance-control.lock"}, sealedtree.MasterStatePaths()...)
	sources := []recovery.Root{{Class: "data", Directory: source[0], IncludePaths: selection}, {Class: "runtime_secrets", Directory: source[1]}}
	m := recovery.Manifest{NodeID: node, Role: "Master", Revision: strings.Repeat("d", 40), Database: "sqlite", Scope: recovery.UpgradeStateScope,
		SchemaGeneration: migrations.Generation, Consistency: "native-offline-and-deployment-writers-stopped",
		KeyReferences: []string{"runtime_secrets/node-vault.key", "runtime_secrets/" + sealedtree.MasterKeyFile}}
	captured, err := sealedtree.CreateMasterTreeBackupStaged(ctx, gate, source[0], filepath.Join(source[0], "db.sqlite"), source[1], archive, m, sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "retained")
	report, err := recovery.ApplyTreeStateArchive(ctx, archive, target, captured.SHA256, node)
	if err != nil {
		t.Fatal(err)
	}
	paths := [2]string{filepath.Join(target, "data"), filepath.Join(target, "runtime_secrets")}
	req := runtimefacts.TreeRetainedRecoveryRequest{Action: "rebind", Nonce: strings.Repeat("a", 64), BindingSHA256: strings.Repeat("b", 64),
		DatabaseRelative: "db.sqlite", NodeID: node, ArchiveSHA256: report.SHA256, Manifest: &report.Manifest}
	call := func(request runtimefacts.TreeRetainedRecoveryRequest, output io.Writer) error {
		t.Helper()
		commit := runtimefacts.TreeRetainedRecoveryCommit{Nonce: request.Nonce, BindingSHA256: request.BindingSHA256}
		return treeRetainedRecovery(ctx, retainedTreeTestFrames(t, request, commit), output, paths)
	}
	if err := call(req, io.Discard); !errors.Is(err, maintenance.ErrState) {
		t.Fatal("rebind accepted without the persistent recovery hold", err)
	}
	root, err := os.OpenRoot(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if present, err := sealedtree.RetainedTreeRebindIntentPresent(root); err != nil || present {
		t.Fatal("unheld rebind published an intent", present, err)
	}
	hold := runtimefacts.TreeRetainedRecoveryRequest{Action: "hold", Nonce: req.Nonce, BindingSHA256: req.BindingSHA256}
	if err := call(hold, io.Discard); err != nil {
		t.Fatal(err)
	}
	other := req
	other.BindingSHA256 = strings.Repeat("c", 64)
	if err := call(other, io.Discard); !errors.Is(err, maintenance.ErrState) {
		t.Fatal("rebind accepted a hold for another plan", err)
	}
	for _, wantAlready := range []bool{false, true} {
		var output bytes.Buffer
		if err := call(req, &output); err != nil {
			t.Fatal(err)
		}
		reply := retainedTreeTestReplies(t, req, &output)
		if reply.Already == nil || *reply.Already != wantAlready {
			t.Fatal("runtime rebind retry result changed")
		}
	}
	if present, err := sealedtree.RetainedTreeRebindIntentPresent(root); err != nil || !present {
		t.Fatal("rebind lost its installer barrier", present, err)
	}
	retainedGate, err := maintenance.Open(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer retainedGate.Close()
	if held, err := retainedGate.TreeRecoveryHeld(); err != nil || !held {
		t.Fatal("rebind removed persistent hold", held, err)
	}
}
