package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

type composeDiscoveryRunner struct {
	ids    string
	labels map[string]string
	calls  []string
}

func (r *composeDiscoveryRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if len(args) > 0 && args[0] == "ps" {
		return []byte(r.ids), nil
	}
	return json.Marshal(r.labels)
}

func TestComposeDiscoveryUsesUniqueNativeWebWithoutInstaller(t *testing.T) {
	root := t.TempDir()
	labels := map[string]string{"frontiercloud.runtime": "go", "frontiercloud.component": "web", "com.docker.compose.service": "web", "com.docker.compose.oneoff": "False", "com.docker.compose.project": "native", "com.docker.compose.project.working_dir": root, "com.docker.compose.project.config_files": filepath.Join(root, "docker-compose.yaml")}
	runner := &composeDiscoveryRunner{ids: "native-web\n", labels: labels}
	got, err := discoverComposeWeb(context.Background(), runner, root)
	if err != nil {
		t.Fatal(err)
	}
	d, err := composeDeployment(root, got)
	if err != nil || d.Role != "master" || d.Project != "native" {
		t.Fatal(d, err)
	}
	if strings.Contains(strings.Join(runner.calls, " "), "foc-bootstrap") {
		t.Fatal("discovery required installer", runner.calls)
	}
	for _, marker := range []string{"label=com.docker.compose.service=web", "label=frontiercloud.runtime=go", "label=frontiercloud.component=web"} {
		if !strings.Contains(runner.calls[0], marker) {
			t.Fatal("missing candidate restriction", marker)
		}
	}
	for _, bad := range []string{"", "one\ntwo\n"} {
		runner.ids = bad
		if _, err = discoverComposeWeb(context.Background(), runner, root); err == nil {
			t.Fatal("ambiguous or absent Web accepted", bad)
		}
	}
}

func TestComposeDiscoveryRejectsForeignIdentityAndFileSelection(t *testing.T) {
	root := t.TempDir()
	base := map[string]string{"frontiercloud.runtime": "go", "frontiercloud.component": "web", "com.docker.compose.service": "web", "com.docker.compose.oneoff": "False", "com.docker.compose.project": "native", "com.docker.compose.project.working_dir": root, "com.docker.compose.project.config_files": filepath.Join(root, "docker-compose.yaml")}
	for key, value := range map[string]string{"frontiercloud.runtime": "python", "frontiercloud.component": "nginx", "com.docker.compose.service": "redis", "com.docker.compose.oneoff": "True", "com.docker.compose.project.working_dir": filepath.Join(root, "other")} {
		t.Run(key, func(t *testing.T) {
			labels := map[string]string{}
			for k, v := range base {
				labels[k] = v
			}
			labels[key] = value
			if _, err := discoverComposeWeb(context.Background(), &composeDiscoveryRunner{ids: "web", labels: labels}, root); err == nil {
				t.Fatal("foreign candidate accepted")
			}
		})
	}
	for _, file := range []string{"", "docker-compose.yaml", filepath.Join(root, "other", "docker-compose.yaml"), filepath.Join(root, "custom.yaml"), filepath.Join(root, "docker-compose.yaml") + "," + filepath.Join(root, "docker-compose.storage.yaml")} {
		labels := map[string]string{}
		for k, v := range base {
			labels[k] = v
		}
		labels["com.docker.compose.project.config_files"] = file
		if _, err := composeDeployment(root, labels); err == nil {
			t.Fatal("nonstandard Compose selection accepted", file)
		}
	}
}
