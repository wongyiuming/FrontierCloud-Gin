//go:build linux

package operator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
)

// treeCaptureExchange sends state only after this specific child proves its
// mount identity and has acquired the native/SQLite/tree locks. The enclosing
// caller owns receipt rechecks, exact container lifecycle and archive proof.
func treeCaptureExchange(ctx context.Context, input io.WriteCloser, output *bufio.Reader, plan treeRuntimeBackupPlan, request runtimefacts.TreeBackupCaptureRequest, sources []recovery.Root, recheck func() error) (runtimefacts.TreeBackupCaptureReply, error) {
	var empty runtimefacts.TreeBackupCaptureReply
	if ctx == nil || input == nil || output == nil || recheck == nil || request.Nonce == "" || request.Manifest.NodeID != plan.nodeID || request.Manifest.Scope != plan.scope || request.StageLimit != plan.stagingLimit {
		return empty, errors.New("invalid tree capture exchange")
	}
	dataInfo, e := os.Lstat(plan.dataRoot)
	if e != nil || !dataInfo.IsDir() || dataInfo.Mode()&os.ModeSymlink != 0 {
		return empty, errors.New("tree capture data mount changed")
	}
	secretInfo, e := os.Lstat(plan.secretsRoot)
	if e != nil || !secretInfo.IsDir() || secretInfo.Mode()&os.ModeSymlink != 0 {
		return empty, errors.New("tree capture secrets mount changed")
	}
	tmpInfo, e := os.Lstat(plan.tmpRoot)
	if e != nil || !tmpInfo.IsDir() || tmpInfo.Mode()&os.ModeSymlink != 0 {
		return empty, errors.New("tree capture scratch mount changed")
	}
	dataProof, e := treeRuntimeMount(dataInfo)
	if e != nil {
		return empty, e
	}
	secretProof, e := treeRuntimeMount(secretInfo)
	if e != nil {
		return empty, e
	}
	tmpProof, e := treeRuntimeMount(tmpInfo)
	if e != nil {
		return empty, e
	}
	raw, e := json.Marshal(request)
	if e != nil || len(raw)+1 > 64<<10 {
		return empty, errors.New("invalid tree capture request")
	}
	raw = append(raw, '\n')
	n, e := input.Write(raw)
	if e != nil {
		return empty, e
	}
	if n != len(raw) {
		return empty, io.ErrShortWrite
	}
	var ready runtimefacts.TreeBackupCaptureReply
	if e = readTreeCaptureReply(ctx, output, 8192, &ready); e != nil {
		return empty, e
	}
	proof := ready.Mounts
	if ready.Phase != "ready" || ready.Report != nil || proof == nil || proof.Nonce != request.Nonce || proof.UID != plan.runtimeUID || proof.GID != plan.runtimeGID || !treeIdentityUIDMap(proof.UIDMap) || proof.Data != dataProof || proof.Secrets != secretProof || proof.Scratch != tmpProof || !validTreeCaptureScratch(ready.Scratch) {
		return empty, errors.New("tree capture readiness proof failed")
	}
	checkMounts := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, item := range []struct {
			path     string
			expected os.FileInfo
			proof    runtimefacts.TreeBackupMount
		}{{plan.dataRoot, dataInfo, dataProof}, {plan.secretsRoot, secretInfo, secretProof}, {plan.tmpRoot, tmpInfo, tmpProof}} {
			actual, err := os.Lstat(item.path)
			if err != nil || !actual.IsDir() || actual.Mode()&os.ModeSymlink != 0 || !os.SameFile(item.expected, actual) {
				return errors.New("tree capture mount changed")
			}
			actualProof, err := treeRuntimeMount(actual)
			if err != nil || actualProof != item.proof {
				return errors.New("tree capture mount metadata changed")
			}
		}
		return nil
	}
	checkAuthority := func() error {
		if checkMounts() != nil || recheck() != nil {
			return errors.New("tree capture authority changed")
		}
		return nil
	}
	if e = checkAuthority(); e != nil {
		return empty, e
	}
	if e = recovery.WriteCommittedTreeBackupClassesFinal(ctx, input, sources, request.StageLimit, request.Nonce, checkMounts, checkAuthority); e != nil {
		return empty, e
	}
	if e = input.Close(); e != nil {
		return empty, e
	}
	var complete runtimefacts.TreeBackupCaptureReply
	if e = readTreeCaptureReply(ctx, output, 2*recovery.MaxManifest+4096, &complete); e != nil {
		return empty, e
	}
	if complete.Phase != "complete" || complete.Mounts != nil || complete.Scratch != ready.Scratch || complete.Report == nil || complete.Report.Manifest.NodeID != plan.nodeID || complete.Report.Manifest.Scope != plan.scope || !complete.Report.Verified || checkAuthority() != nil {
		return empty, errors.New("tree capture completion proof failed")
	}
	sha, err := hex.DecodeString(complete.Report.SHA256)
	if err != nil || len(sha) != 32 || hex.EncodeToString(sha) != complete.Report.SHA256 {
		return empty, errors.New("tree capture completion proof failed")
	}
	return complete, nil
}

func validTreeCaptureScratch(name string) bool {
	return len(name) > len(".fc-tree-capture-") && len(name) <= 128 && strings.HasPrefix(name, ".fc-tree-capture-") && filepath.Base(name) == name && !strings.ContainsAny(name, "/\\\x00\r\n")
}

func readTreeCaptureReply(ctx context.Context, input *bufio.Reader, limit int, target any) error {
	var raw []byte
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		part, err := input.ReadSlice('\n')
		if len(part) > limit-len(raw) {
			return errors.New("tree capture reply exceeds limit")
		}
		raw = append(raw, part...)
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return errors.New("incomplete tree capture reply")
		}
	}
	if _, e := protocol.ParseStrictJSON(raw, limit); e != nil {
		return errors.New("invalid tree capture reply")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(target) != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("invalid tree capture reply")
	}
	return nil
}
