package deployment

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Executes the actual operator script against an isolated Git repository and a
// capture-only Engine CLI. Real image builds remain a separate acceptance gate.
func TestBootstrapArchivesExactCommitAndRejectsMutableSelections(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux operator bootstrap requires bash/git/tar")
	}
	for _, name := range []string{"bash", "git", "tar"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip("operator tool unavailable: " + name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	write := func(name, data string, mode os.FileMode) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	fixture := map[string]string{
		"Dockerfile.gin":   "FROM committed-native\n",
		"Dockerfile":       "FROM committed-native\n",
		"nginx/Dockerfile": "FROM committed-edge\n", "go.mod": "module fixture\n", "go.sum": "committed-sum\n",
		"cmd/entry.txt": "committed\n", "internal/core.txt": "committed\n", "migrations/schema.txt": "committed\n",
		"protocol/contract.txt": "committed\n", "static/index.txt": "committed\n",
		".env": "private-tracked-secret\n", "data/key": "private-tracked-key\n",
		"app/main.py": "excluded reference runtime\n", "updater/server.py": "excluded reference updater\n",
		"docker-compose.yaml": "services: {}\n", "docker-compose.gin-mysql.yaml": "services: {}\n",
		"docker-compose.storage.yaml": "services: {}\n", ".env.example": "SERVER_NAME=fixture.invalid\n",
		"deploy/compose.foc.yaml": "services: {}\n", "scripts/foc": "#!/bin/sh\n", "scripts/install-foc.sh": "#!/bin/sh\n",
		".env.storage.example": "SERVER_NAME=fixture.invalid\n", "docs/operator-manual.md": "Operator fixture\n",
		"docs/operator-upgrade.md": "Approved upgrade fixture\n", "docs/operator-recovery-sets.md": "Recovery set fixture\n",
	}
	for name, data := range fixture {
		write(name, data, 0600)
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture Git failed: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("add", ".")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "commit", "-qm", "immutable fixture")
	revision := git("rev-parse", "HEAD")
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-native-images.sh"))
	if os.IsNotExist(err) {
		t.Skip("operator script is source-checkout-only, not shipped in the native runtime build")
	}
	if err != nil {
		t.Fatal(err)
	}
	write("scripts/build-native-images.sh", string(script), 0700)
	write("cmd/entry.txt", "mutable-source-must-not-enter\n", 0600)
	write("cmd/untracked.txt", "untracked-must-not-enter\n", 0600)
	write("fake-bin/docker", `#!/usr/bin/env bash
set -euo pipefail
test "$1" = --host
test "$2" = unix:///var/run/docker.sock
test "$3" = build
printf '%s\n' "$*" >> "$BOOTSTRAP_CAPTURE/args"
dest=$(mktemp -d "$BOOTSTRAP_CAPTURE/archive-XXXXXXXX")
tar xf - -C "$dest"
test "$(cat "$dest/cmd/entry.txt")" = committed
test "$(cat "$dest/Dockerfile")" = FROM\ committed-native
test "$(cat "$dest/Dockerfile.gin")" = FROM\ committed-native
test "$(cat "$dest/docs/operator-upgrade.md")" = Approved\ upgrade\ fixture
test "$(cat "$dest/docs/operator-recovery-sets.md")" = Recovery\ set\ fixture
test -f "$dest/$(cat "$BOOTSTRAP_CAPTURE/installer-path")"
test -f "$dest/scripts/foc"
test -f "$dest/scripts/install-foc.sh"
for excluded in .env data .git app updater/server.py cmd/untracked.txt; do
  test ! -e "$dest/$excluded"
done
`, 0700)
	capture := filepath.Join(root, "capture")
	if err := os.Mkdir(capture, 0700); err != nil {
		t.Fatal(err)
	}
	write("capture/installer-path", "deploy/compose.foc.yaml\n", 0600)
	run := func(selection string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "bash", "scripts/build-native-images.sh", selection)
		cmd.Dir = root
		// This fixture captures immutable source builds, not registry resolution.
		// Select the operator's isolated acceptance mode explicitly rather than
		// inheriting a driver's setting or consulting the public registry.
		for _, variable := range os.Environ() {
			name, _, _ := strings.Cut(variable, "=")
			if name != "PATH" && name != "BOOTSTRAP_CAPTURE" && name != "FRONTIERCLOUD_IMAGE_SOURCE" {
				cmd.Env = append(cmd.Env, variable)
			}
		}
		cmd.Env = append(cmd.Env, "PATH="+filepath.Join(root, "fake-bin")+":"+os.Getenv("PATH"), "BOOTSTRAP_CAPTURE="+capture, "FRONTIERCLOUD_IMAGE_SOURCE=local")
		return cmd.CombinedOutput()
	}
	for _, invalid := range []string{"HEAD", "gin_dev", revision[:12], strings.Repeat("f", 40)} {
		if out, err := run(invalid); err == nil {
			t.Fatalf("mutable/missing revision accepted: %s: %s", invalid, out)
		}
	}
	if _, err := os.Stat(filepath.Join(capture, "args")); !os.IsNotExist(err) {
		t.Fatal("invalid source selection reached Engine")
	}
	if out, err := run(revision); err != nil {
		t.Fatalf("immutable bootstrap failed: %v: %s", err, out)
	}
	args, err := os.ReadFile(filepath.Join(capture, "args"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(lines) != 2 {
		t.Fatal("bootstrap did not build exactly two images")
	}
	for index, component := range []string{"web", "nginx"} {
		if !strings.Contains(lines[index], "REVISION="+revision) || !strings.Contains(lines[index], "frontiercloud-go-"+component+":"+revision) || !strings.HasSuffix(lines[index], " -") {
			t.Fatal("immutable component context/label mismatch", component)
		}
	}
	if !strings.Contains(lines[1], "FRONTIERCLOUD_RUNTIME=go") {
		t.Fatal("edge lost explicit native runtime label")
	}
	// Historical revisions must still archive the path their Dockerfiles select.
	if err := os.Rename(filepath.Join(root, "deploy", "compose.foc.yaml"), filepath.Join(root, "compose.foc.yaml")); err != nil {
		t.Fatal(err)
	}
	git("add", "deploy/compose.foc.yaml", "compose.foc.yaml")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "commit", "-qm", "legacy installer layout fixture")
	write("capture/installer-path", "compose.foc.yaml\n", 0600)
	if out, err := run(git("rev-parse", "HEAD")); err != nil {
		t.Fatalf("historical installer archive failed: %v: %s", err, out)
	}
}
