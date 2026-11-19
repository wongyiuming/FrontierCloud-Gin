//go:build linux

package operator

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestTreeCaptureRequiresFencedMasterAndSettledOwners(t *testing.T) {
	id := strings.Repeat("a", 32)
	peer := NodeFact{NodeID: strings.Repeat("b", 32), Direction: "downstream", State: "active", Protocol: 2}
	plan := treeRuntimeBackupPlan{nodeID: id}
	fact := RuntimeFact{NodeID: id, Role: "Master", NativeMaintenance: true, Nodes: []NodeFact{peer},
		Database: store.MaintenanceSnapshot{Role: "Master", SchemaGeneration: migrations.Generation,
			Pending: map[string]int64{"sealed_tree_unrecoverable": 1, "uploads": 0}}}
	if got, err := treeCaptureOfflineFact(plan, fact); err != nil || len(got) != 1 || got[0].NodeID != peer.NodeID {
		t.Fatalf("fenced tree Master refused: %v %v", got, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*RuntimeFact)
	}{
		{"unfenced", func(f *RuntimeFact) { f.NativeMaintenance = false }},
		{"other identity", func(f *RuntimeFact) { f.NodeID = strings.Repeat("c", 32) }},
		{"older schema", func(f *RuntimeFact) { f.Database.SchemaGeneration-- }},
		{"missing tree", func(f *RuntimeFact) { f.Database.Pending["sealed_tree_unrecoverable"] = 0 }},
		{"pending upload", func(f *RuntimeFact) { f.Database.Pending["uploads"] = 1 }},
		{"pending Owner", func(f *RuntimeFact) { f.Nodes[0].State = "pending" }},
		{"duplicate Owner", func(f *RuntimeFact) { f.Nodes = append(f.Nodes, peer) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			altered := fact
			altered.Database.Pending = map[string]int64{"sealed_tree_unrecoverable": 1, "uploads": 0}
			altered.Nodes = []NodeFact{peer}
			tc.change(&altered)
			if _, err := treeCaptureOfflineFact(plan, altered); err == nil {
				t.Fatal("unsafe offline state was admitted")
			}
		})
	}
}

func TestTreeCaptureChildOnlyUsesPinnedMountsAndIdentity(t *testing.T) {
	plan := treeRuntimeBackupPlan{dataRoot: "/data", secretsRoot: "/keys", tmpRoot: "/scratch",
		runtimeUID: 10001, runtimeGID: 10002, webImage: "registry.example/web@sha256:" + strings.Repeat("a", 64)}
	nonce := strings.Repeat("b", 64)
	name := "fc-tree-backup-" + nonce
	args := treeCaptureCreateArgs(plan, name, nonce)
	for _, want := range []string{
		"--read-only", "--network=none", "--cap-drop=ALL", "--pull=never", "--interactive", "10001:10002",
		"type=bind,src=/data,dst=/fc-tree-data",
		"type=bind,src=/keys,dst=/fc-tree-secrets,readonly",
		"type=bind,src=/scratch,dst=/fc-tree-tmp",
		treeCaptureLabel + "=" + nonce, plan.webImage, "tree-backup-capture",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("required container boundary missing: %s", want)
		}
	}
	if slices.Contains(args, "--privileged") || slices.Contains(args, "--rm") {
		t.Fatal("capture lost its explicit isolation or inspectable exit")
	}

	runner := &treeCaptureInspectionRunner{name: name, image: plan.webImage, id: strings.Repeat("c", 64)}
	d := &Deployment{Runner: runner}
	runner.label = strings.Repeat("d", 64)
	if err := d.removeTreeCaptureContainer(context.Background(), plan, name, nonce); err == nil || runner.removed {
		t.Fatal("unrelated child was removed")
	}
	runner.label = nonce
	if err := d.removeTreeCaptureContainer(context.Background(), plan, name, nonce); err != nil || !runner.removed {
		t.Fatalf("owned capture child cleanup failed: %v", err)
	}
}

type treeCaptureInspectionRunner struct {
	name, image, id, label string
	removed                bool
}

func (r *treeCaptureInspectionRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "docker" || len(args) < 2 || args[0] != "container" {
		panic("unexpected capture inspection command")
	}
	switch args[1] {
	case "ls":
		return []byte(r.id + "\n"), nil
	case "inspect":
		var reply []string
		for _, field := range []any{r.id, "/" + r.name, r.image, "/app/frontiercloud",
			[]string{"tree-backup-capture"}, r.label, "exited", 0} {
			raw, _ := json.Marshal(field)
			reply = append(reply, string(raw))
		}
		return []byte(strings.Join(reply, " ")), nil
	case "rm":
		r.removed = slices.Equal(args, []string{"container", "rm", "--force", r.id})
		return nil, nil
	default:
		panic("unexpected capture child action")
	}
}
