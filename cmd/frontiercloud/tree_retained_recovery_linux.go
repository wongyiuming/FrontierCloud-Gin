//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

var errRetainedTreeRecoveryRequest = errors.New("invalid retained tree recovery request")

// treeRetainedRecovery is the private protocol of the image-pinned foc child.
// The host verifies the ready mount proof before committing the action.
func treeRetainedRecovery(ctx context.Context, in io.Reader, out io.Writer, paths [2]string) error {
	if ctx == nil || in == nil || out == nil {
		return errRetainedTreeRecoveryRequest
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

	input := bufio.NewReaderSize(in, runtimefacts.MaxTreeRetainedRecoveryControl)
	var request runtimefacts.TreeRetainedRecoveryRequest
	if err := readRetainedTreeFrame(input, runtimefacts.MaxTreeRetainedRecoveryRequest, &request); err != nil ||
		!validRetainedTreeRequest(request) || ctx.Err() != nil {
		return errRetainedTreeRecoveryRequest
	}
	initial, err := inspectRetainedTreeMounts(paths)
	if err != nil {
		return err
	}
	checkMounts := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := inspectRetainedTreeMounts(paths)
		if err != nil || current != initial {
			return errors.New("retained tree runtime mount changed")
		}
		return nil
	}
	output := json.NewEncoder(out)
	reply := runtimefacts.TreeRetainedRecoveryReply{
		Phase: "ready", Action: request.Action, Nonce: request.Nonce, BindingSHA256: request.BindingSHA256, Mounts: initial,
	}
	if err := output.Encode(reply); err != nil {
		return err
	}
	var commit runtimefacts.TreeRetainedRecoveryCommit
	if err := readRetainedTreeFrame(input, runtimefacts.MaxTreeRetainedRecoveryControl, &commit); err != nil ||
		commit.Nonce != request.Nonce || commit.BindingSHA256 != request.BindingSHA256 {
		return errRetainedTreeRecoveryRequest
	}
	if _, err := input.ReadByte(); err != io.EOF {
		return errRetainedTreeRecoveryRequest
	}
	gate, err := maintenance.OpenExisting(paths[0])
	if err != nil {
		return err
	}
	defer gate.Close()
	if err := checkMounts(); err != nil {
		return err
	}
	if request.Action == "hold" {
		if enabled, err := gate.Enabled(); err != nil || !enabled {
			return maintenance.ErrState
		}
		if err := gate.HoldTreeRecovery(ctx, request.BindingSHA256); err != nil {
			return err
		}
	} else if request.Action == "rebind" {
		already, err := sealedtree.RebindHeldRetainedMasterTreeState(ctx, gate, request.BindingSHA256, request.ArchiveSHA256,
			*request.Manifest, paths[0], paths[1], request.DatabaseRelative, request.NodeID, checkMounts)
		if err != nil {
			return err
		}
		reply.Already = &already
	} else {
		proof, err := verifyRetainedTreeLocal(ctx, gate, request, paths, checkMounts)
		if err != nil {
			return err
		}
		reply.Local = &proof
		reply.Phase = "complete"
		return output.Encode(reply)
	}
	if err := gate.Inspect(ctx, func(held context.Context) error {
		if err := checkMounts(); err != nil {
			return err
		}
		if err := gate.VerifyTreeRecoveryHoldBinding(held, request.BindingSHA256); err != nil {
			return err
		}
		return checkMounts()
	}); err != nil {
		return err
	}
	reply.Phase = "complete"
	return output.Encode(reply)
}

func validRetainedTreeRequest(request runtimefacts.TreeRetainedRecoveryRequest) bool {
	if !retainedTreeLowerHex(request.Nonce, 32) || !retainedTreeLowerHex(request.BindingSHA256, 32) {
		return false
	}
	if request.Action == "hold" {
		return request.DatabaseRelative == "" && request.ArchiveSHA256 == "" && request.NodeID == "" && request.Manifest == nil
	}
	if (request.Action != "rebind" && request.Action != "verify-local") || !retainedTreeLowerHex(request.ArchiveSHA256, 32) || !retainedTreeLowerHex(request.NodeID, 16) ||
		!fs.ValidPath(request.DatabaseRelative) || request.DatabaseRelative == "." ||
		strings.ContainsAny(request.DatabaseRelative, "\\\x00\r\n") || request.Manifest == nil {
		return false
	}
	m := request.Manifest
	if m.NodeID != request.NodeID || m.Format != recovery.Format || m.Version != 2 ||
		m.SchemaGeneration != migrations.Generation || m.Scope != recovery.UpgradeStateScope ||
		m.Role != "Master" || m.Database != "sqlite" || len(m.TreeEvidence) == 0 || len(m.TreeEvidence) > 4096 {
		return false
	}
	_, err := protocol.ParseStrictJSON(m.TreeEvidence, 4096)
	return err == nil
}

func retainedTreeLowerHex(value string, size int) bool {
	if len(value) != size*2 {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(raw) == value
}

// Both messages are encoded by the trusted caller using the shared Go types.
// Re-encoding checks exact typed JSON without allocating an untyped manifest.
func readRetainedTreeFrame(input *bufio.Reader, limit int, value any) error {
	var raw []byte
	for {
		fragment, err := input.ReadSlice('\n')
		if len(fragment) > limit-len(raw) {
			return errRetainedTreeRecoveryRequest
		}
		raw = append(raw, fragment...)
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return errRetainedTreeRecoveryRequest
		}
	}
	if !utf8.Valid(raw) {
		return errRetainedTreeRecoveryRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errRetainedTreeRecoveryRequest
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw[:len(raw)-1], canonical) {
		return errRetainedTreeRecoveryRequest
	}
	return nil
}

func inspectRetainedTreeMounts(paths [2]string) (runtimefacts.TreeRetainedRecoveryMounts, error) {
	var proof runtimefacts.TreeRetainedRecoveryMounts
	proof.UID, proof.GID = uint32(os.Geteuid()), uint32(os.Getegid())
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || len(uidMap) > 1024 || !slices.Equal(strings.Fields(string(uidMap)), []string{"0", "0", "4294967295"}) {
		return proof, errors.New("retained tree runtime UID map unavailable")
	}
	proof.UIDMap = strings.TrimSpace(string(uidMap))
	proof.Data, err = inspectRetainedTreeMount(paths[0])
	if err != nil {
		return proof, err
	}
	proof.Secrets, err = inspectRetainedTreeMount(paths[1])
	if err != nil {
		return proof, err
	}
	dataMode := proof.Data.Mode & 0777
	if proof.Data.Device == proof.Secrets.Device && proof.Data.Inode == proof.Secrets.Inode ||
		proof.Data.UID != proof.UID || proof.Data.GID != proof.GID || proof.Secrets.UID != proof.UID || proof.Secrets.GID != proof.GID ||
		dataMode != 0700 && dataMode != 0750 && dataMode != 0755 || proof.Secrets.Mode&0777 != 0700 {
		return proof, errors.New("unsafe retained tree runtime mount ownership")
	}
	return proof, nil
}

func inspectRetainedTreeMount(name string) (runtimefacts.TreeBackupMount, error) {
	var proof runtimefacts.TreeBackupMount
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return proof, errors.New("invalid retained tree runtime mount")
	}
	canonical, err := filepath.EvalSymlinks(name)
	before, statErr := os.Lstat(name)
	if err != nil || canonical != name || statErr != nil || !before.IsDir() {
		return proof, errors.New("retained tree runtime mount unavailable")
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return proof, err
	}
	defer root.Close()
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(before, actual) {
		return proof, errors.New("retained tree runtime mount changed")
	}
	st, ok := actual.Sys().(*syscall.Stat_t)
	if !ok || st.Ino == 0 {
		return proof, errors.New("retained tree runtime mount identity unavailable")
	}
	return runtimefacts.TreeBackupMount{Device: uint64(st.Dev), Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode}, nil
}
