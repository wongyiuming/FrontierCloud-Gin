//go:build linux

package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type treePlanTestRunner struct {
	*upgradeRunner
	tmp        string
	security   string
	proofFault string
	proofSeen  bool
}

func (r *treePlanTestRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(args, " ")
	if len(args) > 0 && args[0] == "run" {
		if !strings.Contains(call, "--network=none") || !strings.Contains(call, "--read-only") || !strings.Contains(call, "--pull=never") || !strings.Contains(call, "--cap-drop=ALL") || !strings.Contains(call, "tree-backup-runtime-inspect") {
			return nil, fmt.Errorf("unsafe runtime invocation")
		}
		mount := func(path string) runtimefacts.TreeBackupMount {
			info, err := os.Stat(path)
			if err != nil {
				panic(err)
			}
			st := info.Sys().(*syscall.Stat_t)
			return runtimefacts.TreeBackupMount{Device: uint64(st.Dev), Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode}
		}
		v := runtimefacts.TreeBackupRuntime{Nonce: args[len(args)-1], UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), UIDMap: "0 0 4294967295", Data: mount(r.data), Secrets: mount(r.secrets), Scratch: mount(r.tmp)}
		switch r.proofFault {
		case "nonce":
			v.Nonce = strings.Repeat("0", 64)
		case "uid":
			v.UID++
		case "data":
			v.Data.Inode++
		case "secrets":
			v.Secrets.Inode++
		case "tmp":
			v.Scratch.Inode++
		case "map":
			v.UIDMap = "0 10000 65536"
		}
		r.proofSeen = true
		return json.Marshal(v)
	}
	if strings.Contains(call, "info --format {{json .SecurityOptions}}") {
		return []byte(r.security), nil
	}
	if strings.Contains(call, "volume inspect") && strings.HasSuffix(call, "test_web_tmp") {
		return json.Marshal(r.tmp)
	}
	return r.upgradeRunner.Run(ctx, name, args...)
}

func TestTreeBackupRuntimePlanBindsReceiptAndRejectsUnsafeIdentity(t *testing.T) {
	d, receipt, runner, _ := upgradeFixture(t)
	tmp := filepath.Join(d.Directory, "tmp-volume")
	if err := os.Mkdir(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	web := runner.config.Services["web"]
	web.Execution = map[string]json.RawMessage{"user": json.RawMessage(fmt.Sprintf("%q", fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid())))}
	web.Volumes = append(web.Volumes, Mount{Type: "volume", Source: "web_tmp", Target: "/tmp"})
	runner.config.Services["web"] = web
	runner.config.Volumes["web_tmp"] = struct {
		Name     string `json:"name"`
		External bool   `json:"external"`
	}{Name: "test_web_tmp"}
	receipt.SelectionHash = selectionHash(runner.config)
	if err := os.WriteFile(filepath.Join(runner.secrets, "tree-master.key"), []byte(strings.Repeat("x", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range sealedtree.MasterStatePaths() {
		p := filepath.Join(runner.data, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Repeat("f", 32)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	runner.role = "Master"
	proxy := &treePlanTestRunner{upgradeRunner: runner, tmp: tmp, security: `["name=seccomp,profile=default"]`}
	d.Runner = proxy
	outputParent := filepath.Join(t.TempDir(), "private-output")
	if err := os.Mkdir(outputParent, 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(outputParent, "archive.tar")
	plan, err := d.treeBackupRuntimePreflight(context.Background(), receipt, output)
	if err != nil || plan.dataRoot != runner.data || plan.secretsRoot != runner.secrets || plan.tmpRoot != tmp || plan.webImage != receipt.ServiceImages["web"] || plan.receiptSelection != receipt.SelectionHash || plan.archiveLimit == 0 || plan.nodeID != runner.node {
		t.Fatal("valid receipt plan", plan, err)
	}
	proxy.tmp = runner.data
	if _, err = d.treeBackupRuntimePreflight(context.Background(), receipt, output); err == nil {
		t.Fatal("aliased data and scratch accepted")
	}
	proxy.tmp = tmp
	if !proxy.proofSeen {
		t.Fatal("runtime mount proof was not requested")
	}
	for _, fault := range []string{"nonce", "uid", "data", "secrets", "tmp", "map"} {
		proxy.proofFault = fault
		if _, err = d.treeBackupRuntimePreflight(context.Background(), receipt, output); err == nil {
			t.Fatal("runtime mismatch accepted", fault)
		}
	}
	proxy.proofFault = ""
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("read-only plan created output", err)
	}
	// Simulate a same-sized key change after identity sampling and restore its
	// mtime; the final inode/ctime check must refuse the stale plan.
	keyPath := filepath.Join(runner.secrets, "tree-master.key")
	beforeKey, e := os.Stat(keyPath)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	var mutationErr error
	runner.onFact = func() {
		calls++
		if calls == 2 {
			mutationErr = os.WriteFile(keyPath, []byte(strings.Repeat("z", 32)), 0600)
			if mutationErr == nil {
				mutationErr = os.Chtimes(keyPath, beforeKey.ModTime(), beforeKey.ModTime())
			}
		}
	}
	if _, err = d.treeBackupRuntimePreflight(context.Background(), receipt, output); err == nil || calls < 2 || mutationErr != nil {
		t.Fatal("mutated key plan accepted or test did not run", err, calls, mutationErr)
	}
	if raw, e := os.ReadFile(keyPath); e != nil || string(raw) != strings.Repeat("z", 32) {
		t.Fatal("mutated source changed by planning", e)
	}
	runner.onFact = nil
	if err = os.WriteFile(keyPath, []byte(strings.Repeat("x", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	changed := runner.config.Services["web"]
	changed.Execution["user"] = json.RawMessage(`"9876:9876"`)
	runner.config.Services["web"] = changed
	if _, err = d.treeBackupRuntimePreflight(context.Background(), receipt, output); err == nil {
		t.Fatal("receipt drift accepted")
	}
	changed.Execution["user"] = json.RawMessage(fmt.Sprintf("%q", fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid())))
	runner.config.Services["web"] = changed
	proxy.security = `["name=userns"]`
	if _, err = d.treeBackupRuntimePreflight(context.Background(), receipt, output); err == nil {
		t.Fatal("remapped Docker accepted")
	}
	proxy.security = `["name=rootless"]`
	if _, err = d.treeBackupRuntimePreflight(context.Background(), receipt, output); err == nil {
		t.Fatal("rootless Docker accepted")
	}
	proxy.security = `["name=seccomp"]`
	if err = os.Chmod(tmp, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err = d.treeBackupRuntimePreflight(context.Background(), receipt, output); err == nil {
		t.Fatal("world-writable nonsticky scratch accepted")
	}
	if err = os.Chmod(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	fence := filepath.Join(runner.data, filepath.FromSlash(sealedtree.MasterStatePaths()[0]))
	if err = os.Rename(fence, fence+".fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err = d.treeBackupRuntimePreflight(context.Background(), receipt, output); err == nil {
		t.Fatal("missing fence accepted")
	}
	if err = os.Symlink("tree-master.binding", fence); err != nil {
		t.Fatal(err)
	}
	if _, err = d.treeBackupRuntimePreflight(context.Background(), receipt, output); err == nil {
		t.Fatal("symlinked fence accepted")
	}
	if err = os.Remove(fence); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(fence+".fixture", fence); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(runner.secrets, "tree-master.key")
	if err = os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("node-vault.key", key); err != nil {
		t.Fatal(err)
	}
	if _, err = d.treeBackupRuntimePreflight(context.Background(), receipt, output); err == nil {
		t.Fatal("tree-key symlink accepted")
	}
}

func TestTreeBackupUIDMapRequiresHostIdentity(t *testing.T) {
	for _, v := range []string{"0 1 4294967295", "0 0 65536", "0 0 4294967295\n1 1 1", "bad"} {
		if treeIdentityUIDMap(v) {
			t.Fatal("accepted", v)
		}
	}
	if !treeIdentityUIDMap("         0          0 4294967295\n") {
		t.Fatal("identity map rejected")
	}
}

func TestTreeBackupPreflightStateExcludesMediaAndCountsFence(t *testing.T) {
	d, receipt, runner, _ := upgradeFixture(t)
	tmp := filepath.Join(d.Directory, "tmp-volume")
	if err := os.Mkdir(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	web := runner.config.Services["web"]
	web.Execution = map[string]json.RawMessage{"user": json.RawMessage(fmt.Sprintf("%q", fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid())))}
	web.Volumes = append(web.Volumes, Mount{Type: "volume", Source: "web_tmp", Target: "/tmp"})
	runner.config.Services["web"] = web
	runner.config.Volumes["web_tmp"] = struct {
		Name     string `json:"name"`
		External bool   `json:"external"`
	}{Name: "test_web_tmp"}
	receipt.SelectionHash = selectionHash(runner.config)
	if err := os.WriteFile(filepath.Join(runner.secrets, sealedtree.MasterKeyFile), []byte(strings.Repeat("x", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range sealedtree.MasterStatePaths() {
		p := filepath.Join(runner.data, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Repeat("f", 256)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(runner.data, "media", "music", "actual.mp3"), make([]byte, 256<<10), 0600); err != nil {
		t.Fatal(err)
	}
	runner.role = "Master"
	d.Runner = &treePlanTestRunner{upgradeRunner: runner, tmp: tmp, security: `["name=seccomp,profile=default"]`}
	outputParent := filepath.Join(t.TempDir(), "private-output")
	if err := os.Mkdir(outputParent, 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(outputParent, "archive.tar")
	full, err := d.treeBackupRuntimePreflightScope(context.Background(), receipt, output, "deployment")
	if err != nil {
		t.Fatal(err)
	}
	state, err := d.treeBackupRuntimePreflightScope(context.Background(), receipt, output, recovery.UpgradeStateScope)
	if err != nil {
		t.Fatal(err)
	}
	if full.scope != "deployment" || state.scope != recovery.UpgradeStateScope || full.archiveLimit <= state.archiveLimit || full.archiveLimit-state.archiveLimit < 128<<10 {
		t.Fatal("state capacity counted media payload", full.archiveLimit, state.archiveLimit)
	}
	base, err := d.backupCapacityScope(context.Background(), receipt, output, "", recovery.UpgradeStateScope)
	if err != nil {
		t.Fatal(err)
	}
	withTree, err := d.backupCapacityScopeWithTree(context.Background(), receipt, output, "", recovery.UpgradeStateScope, sealedtree.MasterStatePaths(), true)
	if err != nil || withTree.ArchiveBytes <= base.ArchiveBytes || withTree.Files != base.Files+2 {
		t.Fatal("tree fence/binding missing from capacity", withTree, base, err)
	}
}

func TestTreeBackupCapacityCountsBothCopies(t *testing.T) {
	if treeBackupCapacityFits(159, 159, true, 100, 50, 10, 10) {
		t.Fatal("same filesystem undercounted")
	}
	if !treeBackupCapacityFits(160, 160, true, 100, 50, 10, 10) {
		t.Fatal("exact capacity rejected")
	}
	if treeBackupCapacityFits(100, 69, false, 100, 50, 10, 10) {
		t.Fatal("separate stage undercounted")
	}
	if !treeBackupCapacityFits(100, 70, false, 100, 50, 10, 10) {
		t.Fatal("separate stage capacity rejected")
	}
	if treeBackupCapacityFits(^uint64(0), ^uint64(0), true, ^uint64(0), 1, 0, 0) || treeBackupCapacityFits(^uint64(0), ^uint64(0), false, 1, ^uint64(0), 0, 1) {
		t.Fatal("overflow accepted")
	}
}
