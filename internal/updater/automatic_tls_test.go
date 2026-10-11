package updater

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyUpgradeRefusesAutomaticTLSBeforeReplacement(t *testing.T) {
	x, f, status, target := executorFixture(t, "")
	f.automatic = true
	_, err := x.Execute(context.Background(), Request{Target: target, Mode: "upgrade", Hold: true}, status, func(Checkpoint) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "Compose topology migration") {
		t.Fatal("legacy TLS upgrade was not fenced", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.removed) != 0 {
		t.Fatal("legacy service removed before TLS topology migration")
	}
	web, ok := f.container("private-web")
	if !ok || web.State.Status != "running" || f.images[web.Image].Config.Labels["frontiercloud.revision"] != f.old {
		t.Fatal("refused migration changed Web")
	}
	if _, err = os.Stat(filepath.Join(x.ControlDirectory, "replacement.json")); !os.IsNotExist(err) {
		t.Fatal("refused migration created replacement journal", err)
	}
}
func TestAutomaticCertificateReplacementRollbackRestoresBothServices(t *testing.T) {
	x, f, status, target := executorFixture(t, "health")
	f.automatic = true
	f.mu.Lock()
	for id, c := range f.containers {
		switch c.label("com.docker.compose.service") {
		case "web":
			c.HostConfig["Binds"] = []string{"runtime:/run/frontiercloud-certificate:ro"}
		case "nginx":
			c.HostConfig["Binds"] = []string{"published:/run/frontiercloud-tls:ro"}
		}
		f.containers[id] = c
	}
	oldWeb, _ := f.container("private-web")
	for _, service := range []string{"certificate-init", "certificate-agent"} {
		c := sampleContainer()
		f.next++
		c.ID = fmt.Sprintf("%064x", f.next)
		c.Name = "/private-" + service
		c.Image = oldWeb.Image
		c.Config["Labels"] = map[string]any{"com.docker.compose.project": f.project, "com.docker.compose.service": service}
		c.HostConfig["Binds"] = []string{"private:/var/lib/frontiercloud-certificate", "runtime:/run/frontiercloud-certificate", "published:/run/frontiercloud-tls"}
		c.State.Status = "running"
		c.State.Health.Status = "healthy"
		f.containers[c.ID] = c
	}
	f.mu.Unlock()
	if _, err := x.Execute(context.Background(), Request{Target: target, Mode: "upgrade", Hold: true}, status, func(Checkpoint) error { return nil }); err == nil {
		t.Fatal("failed Web upgrade reported success")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, name := range []string{"web", "certificate-init", "certificate-agent"} {
		current, ok := f.container("private-" + name)
		if !ok || f.images[current.Image].Config.Labels["frontiercloud.revision"] != f.old {
			t.Fatal("rollback did not restore certificate service", name)
		}
	}
	if _, err := os.Stat(filepath.Join(x.ControlDirectory, "replacement.json")); !os.IsNotExist(err) {
		t.Fatal("certificate rollback journal remains", err)
	}
}
func TestAutomaticTLSMountSourcesAndReadOnlyBoundaries(t *testing.T) {
	snapshots := map[string]Container{}
	for _, service := range []string{"web", "nginx", "updater", "secrets-init", "media-init", "certificate-init", "certificate-agent"} {
		snapshots[service] = Container{HostConfig: map[string]any{}}
	}
	for _, service := range []string{"certificate-init", "certificate-agent"} {
		c := snapshots[service]
		c.HostConfig["Mounts"] = []map[string]any{{"Source": "private", "Target": "/var/lib/frontiercloud-certificate"}, {"Source": "runtime", "Target": "/run/frontiercloud-certificate"}, {"Source": "published", "Target": "/run/frontiercloud-tls"}}
		snapshots[service] = c
	}
	snapshots["web"].HostConfig["Binds"] = []string{"runtime:/run/frontiercloud-certificate:ro"}
	snapshots["nginx"].HostConfig["Binds"] = []string{"published:/run/frontiercloud-tls:ro"}
	if err := automaticTLSTopology(snapshots); err != nil {
		t.Fatal("real Engine mount shape rejected", err)
	}
	for _, bad := range []string{"published:/run/frontiercloud-tls:rw", "wrong:/run/frontiercloud-tls:ro"} {
		snapshots["nginx"].HostConfig["Binds"] = []string{bad}
		if err := automaticTLSTopology(snapshots); err == nil {
			t.Fatal("invalid certificate topology accepted", bad)
		}
	}
}
