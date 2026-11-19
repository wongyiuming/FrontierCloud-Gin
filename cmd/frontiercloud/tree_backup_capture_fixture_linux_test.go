//go:build linux && ledger_fixture

package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestTreeBackupCaptureRejectsUnsettledState(t *testing.T) {
	for _, tt := range []struct {
		name, mutation string
	}{
		{"wrong schema", "UPDATE frontiercloud_schema SET generation=generation-1"},
		{"unfinished operation", "INSERT INTO sealed_tree_operation_ids(operation_id) VALUES('pending')"},
		{"unfinished revocation", "INSERT INTO sealed_tree_revocations VALUES('pending','object')"},
		{"unfinished upload", "INSERT INTO selected_upload_intents VALUES('op','upload','member','parent','blob','key',X'00','pending')"},
		{"orphan multipart journal", "INSERT INTO selected_s3_uploads VALUES('op','key',X'00','completed')"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			base := t.TempDir()
			paths := [3]string{filepath.Join(base, "data"), filepath.Join(base, "secrets"), filepath.Join(base, "tmp")}
			for _, dir := range paths {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			node, err := sealedtree.FixtureTreeCaptureMaster(ctx, paths[0], paths[1])
			if err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", filepath.Join(paths[0], "db.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.ExecContext(ctx, tt.mutation)
			if err = errors.Join(err, db.Close()); err != nil {
				t.Fatal(err)
			}
			request := treeCaptureRequest{
				Nonce: strings.Repeat("a", 64), DatabaseRelative: "db.sqlite",
				Selection: append([]string{"db.sqlite", maintenance.Marker, ".native-runtime.lock", ".native-maintenance-control.lock"}, sealedtree.MasterStatePaths()...),
				Classes:   []string{"deployment"}, StageLimit: 1 << 20,
				Manifest: recovery.Manifest{
					NodeID: node, Role: "Master", Database: "sqlite", Revision: strings.Repeat("d", 40),
					Scope: recovery.UpgradeStateScope, SchemaGeneration: migrations.Generation,
					Consistency: "native-offline-and-deployment-writers-stopped",
				},
			}
			var input, output bytes.Buffer
			if err = json.NewEncoder(&input).Encode(request); err != nil {
				t.Fatal(err)
			}
			if err = treeBackupCapture(ctx, &input, &output, paths); !errors.Is(err, recovery.ErrUnsafe) || output.Len() != 0 {
				t.Fatalf("unsafe state reached capture handshake: %v, output bytes=%d", err, output.Len())
			}
			scratch, err := os.ReadDir(paths[2])
			if err != nil || len(scratch) != 0 {
				t.Fatal("rejected capture left scratch", err)
			}
		})
	}
}

func TestTreeBackupCaptureRealLeaseStreamAndAbort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	base := t.TempDir()
	paths := [3]string{filepath.Join(base, "data"), filepath.Join(base, "secrets"), filepath.Join(base, "tmp")}
	for _, p := range paths {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	node, err := sealedtree.FixtureTreeCaptureMaster(ctx, paths[0], paths[1])
	if err != nil {
		t.Fatal(err)
	}
	deployment := filepath.Join(base, "deployment")
	if err = os.Mkdir(deployment, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(deployment, ".env"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(paths[0], "media"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(paths[0], "media", "song.blob"), []byte("excluded"), 0600); err != nil {
		t.Fatal(err)
	}
	selection := []string{"db.sqlite", "db.sqlite-wal", "db.sqlite-shm", maintenance.Marker, ".native-runtime.lock", ".native-maintenance-control.lock"}
	selection = append(selection, sealedtree.MasterStatePaths()...)
	request := treeCaptureRequest{Nonce: strings.Repeat("a", 64), DatabaseRelative: "db.sqlite", Selection: selection, Classes: []string{"deployment"}, StageLimit: 1 << 20, Manifest: recovery.Manifest{NodeID: node, Role: "Master", Database: "sqlite", Revision: strings.Repeat("d", 40), Scope: recovery.UpgradeStateScope, SchemaGeneration: migrations.Generation, Consistency: "native-offline-and-deployment-writers-stopped", Missing: []string{}, KeyReferences: []string{"runtime_secrets/node-vault.key", "runtime_secrets/" + sealedtree.MasterKeyFile}}}
	start := func() (*io.PipeWriter, *bufio.Reader, <-chan error, treeCaptureReply) {
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		errors := make(chan error, 1)
		go func() { e := treeBackupCapture(ctx, inR, outW, paths); _ = outW.Close(); errors <- e }()
		if err := json.NewEncoder(inW).Encode(request); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(outR)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatal("missing ready", err, <-errors)
		}
		var ready treeCaptureReply
		if json.Unmarshal(line, &ready) != nil || ready.Phase != "ready" || ready.Mounts == nil || ready.Mounts.Nonce != request.Nonce || !strings.HasPrefix(ready.Scratch, ".fc-tree-capture-") || filepath.Base(ready.Scratch) != ready.Scratch {
			t.Fatal("invalid ready reply")
		}
		return inW, reader, errors, ready
	}
	in, output, errors, ready := start()
	// READY must be sent after the native snapshot holds SQLite's write lock.
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(paths[0], "db.sqlite"))+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TABLE capture_competing_writer (id INTEGER)`); err == nil {
		db.Close()
		t.Fatal("write was admitted during capture")
	}
	db.Close()
	if err = recovery.WriteCommittedTreeBackupClasses(ctx, in, []recovery.Root{{Class: "deployment", Directory: deployment}}, request.StageLimit, request.Nonce, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = in.Close(); err != nil {
		t.Fatal(err)
	}
	line, err := output.ReadBytes('\n')
	if err != nil {
		t.Fatal("missing completion", err, <-errors)
	}
	var complete treeCaptureReply
	if json.Unmarshal(line, &complete) != nil || complete.Phase != "complete" || complete.Scratch != ready.Scratch || complete.Report == nil {
		t.Fatal("invalid completion reply")
	}
	if err = <-errors; err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(paths[2], ready.Scratch, "archive.tar")
	verified, err := recovery.CheckTreeArchiveAuthenticated(ctx, archive, complete.Report.SHA256)
	if err != nil || verified.Manifest.NodeID != node || verified.Manifest.Scope != recovery.UpgradeStateScope {
		t.Fatal("archive not verified", err)
	}
	for _, entry := range verified.Manifest.Files {
		if strings.HasPrefix(entry.Path, "data/media/") {
			t.Fatal("media entered state archive")
		}
	}
	db, err = sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(paths[0], "db.sqlite"))+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TABLE capture_competing_writer (id INTEGER)`); err != nil {
		db.Close()
		t.Fatal("write lock not released", err)
	}
	db.Close()
	// A sender that closes without the authenticated commit frame cannot leave
	// a publishable archive or a generated scratch directory.
	in, output, errors, ready = start()
	_ = in.Close()
	if _, err = output.ReadBytes('\n'); err != io.EOF {
		t.Fatal("aborted capture produced completion", err)
	}
	if err = <-errors; err == nil {
		t.Fatal("aborted capture accepted")
	}
	if _, err = os.Lstat(filepath.Join(paths[2], ready.Scratch)); !os.IsNotExist(err) {
		t.Fatal("aborted scratch remains", err)
	}
}

func TestTreeBackupCaptureProcessHelper(t *testing.T) {
	args := os.Args
	if len(args) < 4 || args[len(args)-4] != "capture-fixture-helper" {
		return
	}
	paths := [3]string{args[len(args)-3], args[len(args)-2], args[len(args)-1]}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if treeBackupCapture(ctx, os.Stdin, os.Stdout, paths) != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestTreeBackupCaptureProcessCrashReleasesLease(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	base := t.TempDir()
	paths := [3]string{filepath.Join(base, "data"), filepath.Join(base, "secrets"), filepath.Join(base, "tmp")}
	for _, p := range paths {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	node, err := sealedtree.FixtureTreeCaptureMaster(ctx, paths[0], paths[1])
	if err != nil {
		t.Fatal(err)
	}
	selection := append([]string{"db.sqlite", "db.sqlite-wal", "db.sqlite-shm", maintenance.Marker, ".native-runtime.lock", ".native-maintenance-control.lock"}, sealedtree.MasterStatePaths()...)
	request := treeCaptureRequest{Nonce: strings.Repeat("b", 64), DatabaseRelative: "db.sqlite", Selection: selection, Classes: []string{"deployment"}, StageLimit: 1 << 20, Manifest: recovery.Manifest{NodeID: node, Role: "Master", Database: "sqlite", Revision: strings.Repeat("d", 40), Scope: recovery.UpgradeStateScope, SchemaGeneration: migrations.Generation, Consistency: "native-offline-and-deployment-writers-stopped", KeyReferences: []string{"runtime_secrets/node-vault.key", "runtime_secrets/" + sealedtree.MasterKeyFile}}}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTreeBackupCaptureProcessHelper$", "--", "capture-fixture-helper", paths[0], paths[1], paths[2])
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if err = json.NewEncoder(in).Encode(request); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(out).ReadBytes('\n')
	var ready treeCaptureReply
	if err != nil || json.Unmarshal(line, &ready) != nil || ready.Phase != "ready" {
		t.Fatal("child did not acquire lease", err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(paths[0], "db.sqlite"))+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TABLE crash_probe (id INTEGER)`); err == nil {
		db.Close()
		t.Fatal("child did not block writer")
	}
	if err = cmd.Process.Kill(); err != nil {
		db.Close()
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if _, err = db.ExecContext(ctx, `CREATE TABLE crash_probe (id INTEGER)`); err != nil {
		db.Close()
		t.Fatal("child crash retained SQLite write lock", err)
	}
	db.Close()
	gate, err := maintenance.Open(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if enabled, err := gate.Enabled(); err != nil || !enabled {
		t.Fatal("child crash released maintenance marker", enabled, err)
	}
}
