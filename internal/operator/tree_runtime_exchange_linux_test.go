//go:build linux

package operator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
)

func TestTreeCaptureExchangeBindsReadyAndFinalAuthority(t *testing.T) {
	pipeR, pipeW := io.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()
	plan := treeRuntimeBackupPlan{scope: recovery.UpgradeStateScope, nodeID: strings.Repeat("b", 32), stagingLimit: 1}
	wrongScope := runtimefacts.TreeBackupCaptureRequest{Nonce: strings.Repeat("a", 64), StageLimit: 1, Manifest: recovery.Manifest{NodeID: plan.nodeID, Scope: "deployment"}}
	if _, err := treeCaptureExchange(context.Background(), pipeW, bufio.NewReader(strings.NewReader("")), plan, wrongScope, nil, func() error { return nil }); err == nil {
		t.Fatal("full capture accepted under state-only capacity proof")
	}
	for _, mode := range []string{"ok", "wrong-uid", "revoked", "wrong-completion"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			base := t.TempDir()
			plan := treeRuntimeBackupPlan{dataRoot: filepath.Join(base, "data"), secretsRoot: filepath.Join(base, "secrets"), tmpRoot: filepath.Join(base, "tmp"), runtimeUID: uint32(os.Geteuid()), runtimeGID: uint32(os.Getegid()), stagingLimit: 1 << 20, nodeID: strings.Repeat("b", 32), scope: recovery.UpgradeStateScope}
			for _, p := range []string{plan.dataRoot, plan.secretsRoot, plan.tmpRoot} {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			source := filepath.Join(base, "deployment")
			if err := os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, ".env"), []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			proof := runtimefacts.TreeBackupRuntime{Nonce: strings.Repeat("a", 64), UID: plan.runtimeUID, GID: plan.runtimeGID, UIDMap: "0 0 4294967295"}
			for _, item := range []struct {
				path string
				out  *runtimefacts.TreeBackupMount
			}{{plan.dataRoot, &proof.Data}, {plan.secretsRoot, &proof.Secrets}, {plan.tmpRoot, &proof.Scratch}} {
				info, err := os.Lstat(item.path)
				if err != nil {
					t.Fatal(err)
				}
				*item.out, err = treeRuntimeMount(info)
				if err != nil {
					t.Fatal(err)
				}
			}
			request := runtimefacts.TreeBackupCaptureRequest{Nonce: proof.Nonce, StageLimit: plan.stagingLimit, Manifest: recovery.Manifest{NodeID: plan.nodeID, Scope: plan.scope}}
			inR, inW := io.Pipe()
			outR, outW := io.Pipe()
			done := make(chan error, 1)
			go func() {
				defer outW.Close()
				reader := bufio.NewReader(inR)
				line, err := reader.ReadBytes('\n')
				if err != nil {
					done <- err
					return
				}
				var got runtimefacts.TreeBackupCaptureRequest
				if json.Unmarshal(line, &got) != nil || got.Nonce != request.Nonce {
					done <- errors.New("request mismatch")
					return
				}
				childProof := proof
				if mode == "wrong-uid" {
					childProof.UID++
				}
				if err = json.NewEncoder(outW).Encode(runtimefacts.TreeBackupCaptureReply{Phase: "ready", Mounts: &childProof, Scratch: ".fc-tree-capture-fixture"}); err != nil {
					done <- err
					return
				}
				stagePath := filepath.Join(plan.tmpRoot, "stage")
				if err = os.Mkdir(stagePath, 0700); err != nil {
					done <- err
					return
				}
				stage, err := os.OpenRoot(stagePath)
				if err != nil {
					done <- err
					return
				}
				defer stage.Close()
				_, err = recovery.ReceiveCommittedTreeBackupClasses(ctx, reader, stage, []string{"deployment"}, request.StageLimit, request.Nonce)
				if err != nil {
					done <- err
					return
				}
				node := plan.nodeID
				if mode == "wrong-completion" {
					node = strings.Repeat("c", 32)
				}
				err = json.NewEncoder(outW).Encode(runtimefacts.TreeBackupCaptureReply{Phase: "complete", Scratch: ".fc-tree-capture-fixture", Report: &recovery.Report{SHA256: strings.Repeat("d", 64), Verified: true, Manifest: recovery.Manifest{NodeID: node, Scope: plan.scope}}})
				done <- err
			}()
			checks := 0
			reply, err := treeCaptureExchange(ctx, inW, bufio.NewReader(outR), plan, request, []recovery.Root{{Class: "deployment", Directory: source}}, func() error {
				checks++
				if mode == "revoked" && checks >= 2 {
					return errors.New("revoked")
				}
				return nil
			})
			_ = inW.Close()
			_ = outR.Close()
			childErr := <-done
			if mode == "ok" {
				if err != nil || childErr != nil || checks != 3 || reply.Report == nil {
					t.Fatalf("exchange failed: %v %v checks=%d", err, childErr, checks)
				}
			} else if err == nil {
				t.Fatal("unsafe exchange accepted")
			}
		})
	}
}
