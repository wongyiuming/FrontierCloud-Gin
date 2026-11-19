//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// Only the existing foc process supplies this local, bounded protocol. The
// parent must verify Docker receipt, mount and container identity and must
// clean the exact generated scratch directory after inspecting the result.
type treeCaptureRequest = runtimefacts.TreeBackupCaptureRequest
type treeCaptureReply = runtimefacts.TreeBackupCaptureReply

func treeBackupCapture(ctx context.Context, in io.Reader, out io.Writer, paths [3]string) (err error) {
	if ctx == nil || in == nil || out == nil {
		return errors.New("invalid tree capture protocol")
	}
	stopClose := context.AfterFunc(ctx, func() {
		if stream, ok := in.(io.Closer); ok {
			_ = stream.Close()
		}
		if stream, ok := out.(io.Closer); ok {
			_ = stream.Close()
		}
	})
	defer stopClose()
	input := bufio.NewReaderSize(in, 64<<10)
	line, err := input.ReadSlice('\n')
	if err != nil || len(line) > 64<<10 {
		return errors.New("invalid tree capture request")
	}
	if _, err = protocol.ParseStrictJSON(line, 64<<10); err != nil {
		return errors.New("invalid tree capture request")
	}
	var request treeCaptureRequest
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !fs.ValidPath(request.DatabaseRelative) || request.DatabaseRelative == "." || strings.ContainsAny(request.DatabaseRelative, "\\\x00\r\n") || request.StageLimit == 0 || request.StageLimit > 10*1024*1024*1024*1024 {
		return errors.New("invalid tree capture request")
	}
	m := request.Manifest
	if m.Role != "Master" || m.Database != "sqlite" || m.SchemaGeneration != migrations.Generation || m.Scope != "deployment" && m.Scope != recovery.UpgradeStateScope || len(m.Files) != 0 || len(m.Directories) != 0 || len(m.Classes) != 0 || len(m.TreeEvidence) != 0 || m.Bytes != 0 || m.CreatedAt != "" || m.Format != "" || m.Version != 0 || m.ConfigurationVersion != 0 || m.Scope == "deployment" && request.Selection != nil || m.Scope == recovery.UpgradeStateScope && request.Selection == nil {
		return errors.New("invalid tree capture manifest")
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return errors.New("invalid tree capture mount")
		}
	}
	var proofBytes bytes.Buffer
	if err := inspectTreeBackupRuntimePaths([]string{request.Nonce}, &proofBytes, paths); err != nil {
		return err
	}
	var initial runtimefacts.TreeBackupRuntime
	if json.Unmarshal(proofBytes.Bytes(), &initial) != nil {
		return errors.New("invalid tree capture mount proof")
	}
	tmpRoot, err := os.OpenRoot(paths[2])
	if err != nil {
		return errors.New("tree capture scratch unavailable")
	}
	defer tmpRoot.Close()
	workspace, err := os.MkdirTemp(paths[2], ".fc-tree-capture-")
	if err != nil {
		return errors.New("tree capture scratch unavailable")
	}
	name := filepath.Base(workspace)
	info, err := os.Lstat(workspace)
	pinned, pinErr := tmpRoot.Lstat(name)
	if err != nil || pinErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !os.SameFile(info, pinned) {
		return errors.New("tree capture scratch unavailable")
	}
	keep := false
	defer func() {
		if keep {
			return
		}
		current, e := tmpRoot.Lstat(name)
		if e == nil && current.IsDir() && current.Mode()&os.ModeSymlink == 0 && os.SameFile(info, current) {
			_ = tmpRoot.RemoveAll(name)
		}
	}()
	stage, err := os.OpenRoot(workspace)
	if err != nil {
		return err
	}
	defer stage.Close()
	checkStage := func() error {
		opened, err := stage.Stat(".")
		current, pathErr := tmpRoot.Lstat(name)
		tmpOpened, tmpErr := tmpRoot.Stat(".")
		tmpCurrent, tmpPathErr := os.Lstat(paths[2])
		if err != nil || pathErr != nil || tmpErr != nil || tmpPathErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, opened) || !os.SameFile(info, current) || !os.SameFile(tmpOpened, tmpCurrent) {
			return errors.New("tree capture scratch changed")
		}
		return nil
	}
	if err = checkStage(); err != nil {
		return err
	}
	gate, err := maintenance.Open(paths[0])
	if err != nil {
		return err
	}
	defer gate.Close()
	sources := []recovery.Root{{Class: "data", Directory: paths[0], IncludePaths: request.Selection}, {Class: "runtime_secrets", Directory: paths[1]}}
	report, err := sealedtree.CreateMasterTreeBackupStaged(ctx, gate, paths[0], filepath.Join(paths[0], filepath.FromSlash(request.DatabaseRelative)), paths[1], filepath.Join(workspace, "archive.tar"), m, sources, func(held context.Context, check func() error) ([]recovery.Root, error) {
		if check() != nil || checkStage() != nil {
			return nil, errors.New("tree capture lease lost")
		}
		var currentBytes bytes.Buffer
		if err := inspectTreeBackupRuntimePaths([]string{request.Nonce}, &currentBytes, paths); err != nil || !bytes.Equal(proofBytes.Bytes(), currentBytes.Bytes()) {
			return nil, errors.New("tree capture mount changed")
		}
		if err := json.NewEncoder(out).Encode(treeCaptureReply{Phase: "ready", Mounts: &initial, Scratch: name}); err != nil {
			return nil, err
		}
		return recovery.ReceiveCommittedTreeBackupClasses(held, input, stage, request.Classes, request.StageLimit, request.Nonce)
	})
	if err != nil {
		return err
	}
	if err = checkStage(); err != nil {
		return err
	}
	if err = json.NewEncoder(out).Encode(treeCaptureReply{Phase: "complete", Scratch: name, Report: &report}); err != nil {
		return err
	}
	keep = true
	return nil
}
