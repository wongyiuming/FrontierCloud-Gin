//go:build linux

package operator

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

type archiveLateMutationContext struct {
	context.Context
	archivePrefix, target string
	mutated               bool
	mutationErr           error
}

func (c *archiveLateMutationContext) Err() error {
	if !c.mutated {
		paths, _ := filepath.Glob(c.archivePrefix + ".next-*")
		for _, p := range paths {
			if info, err := os.Stat(p); err == nil && info.Size() > 128*1024 {
				c.mutated = true
				before, statErr := os.Stat(c.target)
				c.mutationErr = os.WriteFile(c.target, []byte("late!"), 0600)
				if c.mutationErr == nil && statErr == nil {
					// Same size and restored mtime still changes inode ctime.
					c.mutationErr = os.Chtimes(c.target, before.ModTime(), before.ModTime())
				}
				break
			}
		}
	}
	return c.Context.Err()
}

func TestTreeOutputCreateAsUID(t *testing.T) {
	root := os.Getenv("FC_TEST_TREE_STAGE_ROOT")
	if root == "" {
		return
	}
	dir := filepath.Join(root, "run-child")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "tree.tar"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(f, os.Stdin); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func fixtureTreeEvidence(m recovery.Manifest) (json.RawMessage, error) {
	var ev struct {
		Version                                                  int `json:"version"`
		ManifestSHA, NodeID, RootVerifier, MasterBinding, OldTag string
		Device, Inode                                            uint64
		Generation                                               int64
		MAC, RecoveryMAC                                         string
	}
	digest, err := recovery.TreeManifestDigest(m)
	if err != nil {
		return nil, err
	}
	ev.Version = 1
	ev.ManifestSHA = digest
	ev.NodeID = m.NodeID
	ev.Inode = 1
	ev.MAC = strings.Repeat("0", 64)
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, []byte(strings.Repeat("x", 32)))
	h.Write([]byte("frontiercloud:tree-fence-recovery-outer:v1\x00"))
	h.Write(raw)
	ev.RecoveryMAC = hex.EncodeToString(h.Sum(nil))
	return json.Marshal(ev)
}

// A structurally valid v2 archive remains blocked at the existing operator
// restore-check entry point. This fixture does not imply valid tree contents.
func TestRestoreCheckReportsTreeRecoveryStillBlocked(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	data, keys, archives := filepath.Join(base, "data"), filepath.Join(base, "keys"), filepath.Join(base, "archives")
	for _, d := range []string{data, keys, archives} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	database := filepath.Join(data, "db.sqlite")
	if err := os.WriteFile(database, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "tree-master.key"), []byte(strings.Repeat("x", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "node-vault.key"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(archives, "tree.tar")
	m := recovery.Manifest{NodeID: strings.Repeat("a", 32), Role: "Master", Revision: strings.Repeat("b", 40), Database: "sqlite", Consistency: "native-offline-and-deployment-writers-stopped", Missing: []string{}, KeyReferences: []string{"runtime_secrets/node-vault.key", "runtime_secrets/tree-master.key"}}
	mutatedArchive := filepath.Join(archives, "changed.tar")
	_, err = recovery.CreateTreeArchive(ctx, gate, data, database, mutatedArchive, m, []recovery.Root{{Class: "data", Directory: data}, {Class: "runtime_secrets", Directory: keys}}, func(_ context.Context, check func() error) (func(recovery.Manifest) (json.RawMessage, error), func() error, error) {
		return func(_ recovery.Manifest) (json.RawMessage, error) {
			if err := os.WriteFile(database, []byte("changed"), 0600); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"fixture":true}`), check()
		}, func() error { return check() }, nil
	})
	if err == nil {
		t.Fatal("changed source accepted")
	}
	if got, e := os.ReadFile(database); e != nil || string(got) != "changed" {
		t.Fatal("source not preserved", e)
	}
	if _, e := os.Lstat(mutatedArchive); !os.IsNotExist(e) {
		t.Fatal("invalid final archive published", e)
	}
	if err = os.WriteFile(database, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	first, large := filepath.Join(data, "a-first"), filepath.Join(data, "z-large")
	if err = os.WriteFile(first, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(large, make([]byte, 1024*1024), 0600); err != nil {
		t.Fatal(err)
	}
	lateArchive := filepath.Join(archives, "late-change.tar")
	late := &archiveLateMutationContext{Context: ctx, archivePrefix: lateArchive, target: first}
	_, err = recovery.CreateTreeArchive(late, gate, data, database, lateArchive, m, []recovery.Root{{Class: "data", Directory: data}, {Class: "runtime_secrets", Directory: keys}}, func(_ context.Context, check func() error) (func(recovery.Manifest) (json.RawMessage, error), func() error, error) {
		return func(m recovery.Manifest) (json.RawMessage, error) { return fixtureTreeEvidence(m) }, func() error { return check() }, nil
	})
	if !late.mutated || late.mutationErr != nil {
		t.Fatal("late mutation did not run", late.mutationErr)
	}
	if err == nil {
		t.Fatal("already copied source mutation accepted")
	}
	if got, e := os.ReadFile(first); e != nil || string(got) != "late!" {
		t.Fatal("source not preserved", e)
	}
	if _, e := os.Lstat(lateArchive); !os.IsNotExist(e) {
		t.Fatal("late-mutation archive published", e)
	}
	added := filepath.Join(data, "b-added")
	addedArchive := filepath.Join(archives, "added-source.tar")
	addition := &archiveLateMutationContext{Context: ctx, archivePrefix: addedArchive, target: added}
	_, err = recovery.CreateTreeArchive(addition, gate, data, database, addedArchive, m, []recovery.Root{{Class: "data", Directory: data}, {Class: "runtime_secrets", Directory: keys}}, func(_ context.Context, check func() error) (func(recovery.Manifest) (json.RawMessage, error), func() error, error) {
		return func(m recovery.Manifest) (json.RawMessage, error) { return fixtureTreeEvidence(m) }, func() error { return check() }, nil
	})
	if !addition.mutated || addition.mutationErr != nil {
		t.Fatal("late addition did not run", addition.mutationErr)
	}
	if err == nil {
		t.Fatal("new source file after snapshot accepted")
	}
	if got, e := os.ReadFile(added); e != nil || string(got) != "late!" {
		t.Fatal("new source not preserved", e)
	}
	if _, e := os.Lstat(addedArchive); !os.IsNotExist(e) {
		t.Fatal("late-addition archive published", e)
	}
	if err = os.Remove(added); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(large); err != nil {
		t.Fatal(err)
	}
	report, err := recovery.CreateTreeArchive(ctx, gate, data, database, archive, m, []recovery.Root{{Class: "data", Directory: data}, {Class: "runtime_secrets", Directory: keys}}, func(_ context.Context, check func() error) (func(recovery.Manifest) (json.RawMessage, error), func() error, error) {
		return func(m recovery.Manifest) (json.RawMessage, error) {
			if err := check(); err != nil {
				return nil, err
			}
			return fixtureTreeEvidence(m)
		}, func() error { return check() }, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise trusted runtime output publication against the actual v2
	// archive. The staged source is kept; pre-existing targets are never replaced.
	tmpVolume := filepath.Join(base, "tmp-volume")
	stageDir := filepath.Join(tmpVolume, "run-unique")
	if err = os.Mkdir(tmpVolume, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(stageDir, 0700); err != nil {
		t.Fatal(err)
	}
	stageBytes, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(stageDir, "tree.tar")
	if err = os.WriteFile(staged, stageBytes, 0600); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(archives, "published.tar")
	gotPublish, err := publishTreeRuntimeArchive(ctx, data, tmpVolume, "run-unique", "tree.tar", published, report.SHA256, m.NodeID, uint64(len(stageBytes)), 0)
	if err != nil || !gotPublish.Verified || gotPublish.RestoreReady {
		t.Fatal("private output publication", gotPublish, err)
	}
	if got, e := os.ReadFile(published); e != nil || !bytes.Equal(got, stageBytes) {
		t.Fatal("published bytes", e)
	}
	if got, e := os.ReadFile(staged); e != nil || !bytes.Equal(got, stageBytes) {
		t.Fatal("stage modified", e)
	}
	if _, err = publishTreeRuntimeArchive(ctx, data, tmpVolume, "run-unique", "tree.tar", published, report.SHA256, m.NodeID, uint64(len(stageBytes)), 0); err == nil {
		t.Fatal("existing target overwritten")
	}
	if got, e := os.ReadFile(published); e != nil || !bytes.Equal(got, stageBytes) {
		t.Fatal("existing target changed", e)
	}
	badOut := filepath.Join(archives, "bad-sha.tar")
	if _, err = publishTreeRuntimeArchive(ctx, data, tmpVolume, "run-unique", "tree.tar", badOut, strings.Repeat("f", 64), m.NodeID, uint64(len(stageBytes)), 0); err == nil {
		t.Fatal("bad SHA accepted")
	}
	if _, e := os.Lstat(badOut); !os.IsNotExist(e) {
		t.Fatal("bad SHA published output", e)
	}
	link := filepath.Join(archives, "existing-link.tar")
	if err = os.Symlink(published, link); err != nil {
		t.Fatal(err)
	}
	if _, err = publishTreeRuntimeArchive(ctx, data, tmpVolume, "run-unique", "tree.tar", link, report.SHA256, m.NodeID, uint64(len(stageBytes)), 0); err == nil {
		t.Fatal("symlink target accepted")
	}
	if info, e := os.Lstat(link); e != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("existing symlink changed", e)
	}
	tooSmall := filepath.Join(archives, "too-small.tar")
	if _, err = publishTreeRuntimeArchive(ctx, data, tmpVolume, "run-unique", "tree.tar", tooSmall, report.SHA256, m.NodeID, uint64(len(stageBytes)-1), 0); err == nil {
		t.Fatal("bound ignored")
	}
	if _, e := os.Lstat(tooSmall); !os.IsNotExist(e) {
		t.Fatal("overbound output created", e)
	}
	safetyOut := filepath.Join(archives, "insufficient-safety.tar")
	if _, err = publishTreeRuntimeArchive(ctx, data, tmpVolume, "run-unique", "tree.tar", safetyOut, report.SHA256, m.NodeID, uint64(len(stageBytes)), ^uint64(0)); err == nil {
		t.Fatal("safety capacity ignored")
	}
	if _, e := os.Lstat(safetyOut); !os.IsNotExist(e) {
		t.Fatal("insufficient capacity output created", e)
	}
	wrongNodeOut := filepath.Join(archives, "wrong-node.tar")
	if _, err = publishTreeRuntimeArchive(ctx, data, tmpVolume, "run-unique", "tree.tar", wrongNodeOut, report.SHA256, strings.Repeat("f", 32), uint64(len(stageBytes)), 0); err == nil {
		t.Fatal("wrong node accepted")
	}
	if _, e := os.Lstat(wrongNodeOut); !os.IsNotExist(e) {
		t.Fatal("wrong node output published", e)
	}
	if err = os.Symlink("tree.tar", filepath.Join(stageDir, "source-link")); err != nil {
		t.Fatal(err)
	}
	if _, err = publishTreeRuntimeArchive(ctx, data, tmpVolume, "run-unique", "source-link", filepath.Join(archives, "from-link.tar"), report.SHA256, m.NodeID, uint64(len(stageBytes)), 0); err == nil {
		t.Fatal("staged symlink accepted")
	}
	if err = os.Chmod(stageDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = publishTreeRuntimeArchive(ctx, data, tmpVolume, "run-unique", "tree.tar", filepath.Join(archives, "bad-mode.tar"), report.SHA256, m.NodeID, uint64(len(stageBytes)), 0); err == nil {
		t.Fatal("nonprivate stage accepted")
	}
	if err = os.Chmod(stageDir, 0700); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	canceledOut := filepath.Join(archives, "canceled.tar")
	if _, err = publishTreeRuntimeArchive(canceled, data, tmpVolume, "run-unique", "tree.tar", canceledOut, report.SHA256, m.NodeID, uint64(len(stageBytes)), 0); err == nil {
		t.Fatal("canceled copy accepted")
	}
	if _, e := os.Lstat(canceledOut); !os.IsNotExist(e) {
		t.Fatal("canceled output published", e)
	}
	entries, err := os.ReadDir(archives)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".fc-tree-backup-") {
			t.Fatal("own temporary output leaked", entry.Name())
		}
	}
	if os.Geteuid() == 0 {
		const uid, gid = 12345, 12345
		crossParent, e := os.MkdirTemp("", "fc-tree-output-uid-")
		if e != nil {
			t.Fatal(e)
		}
		defer os.RemoveAll(crossParent)
		if err = os.Chmod(crossParent, 0711); err != nil {
			t.Fatal(err)
		}
		crossData := filepath.Join(crossParent, "data")
		if err = os.Mkdir(crossData, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.Chown(crossData, uid, gid); err != nil {
			t.Fatal(err)
		}
		crossTmp := filepath.Join(crossParent, "tmp")
		if err = os.Mkdir(crossTmp, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(crossTmp, os.ModeSticky|0777); err != nil {
			t.Fatal(err)
		}
		exe, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		f, e := os.Open(exe)
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command("/proc/self/fd/3", "-test.run=^TestTreeOutputCreateAsUID$", "-test.count=1")
		cmd.ExtraFiles = []*os.File{f}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
		cmd.Stdin = bytes.NewReader(stageBytes)
		cmd.Env = append(os.Environ(), "FC_TEST_TREE_STAGE_ROOT="+crossTmp)
		output, e := cmd.CombinedOutput()
		f.Close()
		if e != nil {
			t.Fatalf("runtime user staging: %v: %s", e, output)
		}
		crossOutput := filepath.Join(archives, "cross-uid.tar")
		if _, err = publishTreeRuntimeArchive(ctx, crossData, crossTmp, "run-child", "tree.tar", crossOutput, report.SHA256, m.NodeID, uint64(len(stageBytes)), 0); err != nil {
			t.Fatal("cross-UID authenticated publication", err)
		}
		if got, e := os.ReadFile(crossOutput); e != nil || !bytes.Equal(got, stageBytes) {
			t.Fatal("cross-UID output", e)
		}
	}
	target := filepath.Join(base, "new-target")
	got, err := RestoreCheck(ctx, archive, target, report.SHA256)
	if !errors.Is(err, ErrTreeRecoveryNotReady) || !got.Verified || got.RestoreReady {
		t.Fatal("tree gate opened", got, err)
	}
	if _, err = os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("restore-check changed target", err)
	}
	if _, err = RestoreCheck(ctx, archive, target, strings.Repeat("f", 64)); errors.Is(err, ErrTreeRecoveryNotReady) || err == nil {
		t.Fatal("wrong checksum passed", err)
	}
}
