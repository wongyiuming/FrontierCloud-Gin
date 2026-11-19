package node

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestHostCPUTicks(t *testing.T) {
	before, ok := readHostCPUTicks(strings.NewReader("cpu  10 2 3 40 5 2 3 1 100 200\ncpu0 100 0 0 0 0 0 0 0"))
	if !ok || before != (hostCPUTicks{total: 66, idle: 45}) {
		t.Fatalf("aggregate CPU counts %+v, %t", before, ok)
	}
	for _, tc := range []struct {
		name    string
		current hostCPUTicks
		want    int64
		valid   bool
	}{
		{"both busy and idle", hostCPUTicks{86, 60}, 25, true},
		{"all idle", hostCPUTicks{86, 65}, 0, true},
		{"unchanged", before, 0, false},
		{"reset", hostCPUTicks{10, 5}, 0, false},
		{"idle counter decreased", hostCPUTicks{86, 44}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := hostCPUPercent(before, tc.current); got != tc.want || ok != tc.valid {
				t.Fatalf("CPU percentage %d, %t", got, ok)
			}
		})
	}
	if _, ok = hostCPUPercent(hostCPUTicks{}, before); ok {
		t.Fatal("first sample reported a CPU percentage")
	}
}

func TestHostMemoryAvailable(t *testing.T) {
	used, total, ok := readHostMemory(strings.NewReader("MemTotal: 1024 kB\nMemFree: 1 kB\nMemAvailable: 768 kB\n"))
	if !ok || used != 256*1024 || total != 1024*1024 {
		t.Fatalf("memory counts %d/%d, %t", used, total, ok)
	}
	for _, raw := range []string{
		"MemTotal: 1024 kB\nMemFree: 256 kB\n",
		"MemTotal: 1024 kB\nMemAvailable: 1025 kB\n",
		"MemTotal: 1024 MB\nMemAvailable: 768 kB\n",
		"MemTotal: 9223372036854775807 kB\nMemAvailable: 768 kB\n",
	} {
		if _, _, ok := readHostMemory(strings.NewReader(raw)); ok {
			t.Fatalf("invalid memory sample accepted: %q", raw)
		}
	}
}

func TestHostUsageViewOnlyShowsFreshValidatedFacts(t *testing.T) {
	now := time.Now().Unix()
	rel := store.Relationship{Direction: "downstream", State: "active", Status: "online", LastHeartbeat: now - 30}
	if got := hostUsageView(&rel, now); len(got) != 0 {
		t.Fatalf("old peer reports CPU or memory: %v", got)
	}
	rel.Summary = map[string]any{"host_usage": map[string]any{
		"cpu_percent": json.Number("0"), "memory_used_bytes": json.Number("0"), "memory_total_bytes": json.Number("1024"),
		"unknown": "ignore",
	}}
	want := map[string]any{"cpu_percent": int64(0), "memory_used_bytes": int64(0), "memory_total_bytes": int64(1024)}
	if got := hostUsageView(&rel, now); !maps.Equal(got, want) {
		t.Fatalf("fresh host usage %v", got)
	}
	for _, status := range []string{"degraded", "offline"} {
		rel.Status = status
		if got := hostUsageView(&rel, now); len(got) != 0 {
			t.Fatalf("host usage for %s peer: %v", status, got)
		}
	}
	rel.Status, rel.LastHeartbeat = "online", now-120
	if got := hostUsageView(&rel, now); len(got) != 0 {
		t.Fatalf("stale host usage: %v", got)
	}
	rel.LastHeartbeat = now
	rel.Summary["host_usage"] = map[string]any{"cpu_percent": 101, "memory_used_bytes": 2048, "memory_total_bytes": 1024}
	if got := hostUsageView(&rel, now); len(got) != 0 {
		t.Fatalf("invalid host usage: %v", got)
	}
}

func TestFollowerHostUsageFollowsExistingHeartbeat(t *testing.T) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		t.Skip("Linux host memory information unavailable")
	}
	_, total, ok := readHostMemory(file)
	file.Close()
	if !ok {
		t.Skip("Linux host memory totals unavailable")
	}
	stat, err := os.Open("/proc/stat")
	if err != nil {
		t.Skip("Linux CPU counters unavailable")
	}
	_, ok = readHostCPUTicks(stat)
	stat.Close()
	if !ok {
		t.Skip("Linux aggregate CPU counters unavailable")
	}

	ctx := context.Background()
	control := &localControl{nodes: map[string]*Service{}}
	const masterOrigin, followerOrigin = "https://master.test", "https://follower.test"
	master, masterDB := testNode(t, "Master", masterOrigin, control)
	follower, followerDB := testNode(t, "Follower", followerOrigin, control)
	master.ConfigureVolumes(masterDB.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigureVolumes(followerDB.Pool(), &testVolume{}, recordingRoot(t))
	control.nodes[masterOrigin], control.nodes[followerOrigin] = master, follower
	pair, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"Direct", "Relay"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "Relay" {
				// Allow the kernel counters to advance past the Direct probe.
				time.Sleep(100 * time.Millisecond)
			}
			if err := masterDB.Nodes().SetRelationshipMode(ctx, id, mode, false, store.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
			rel, err := master.repo.Relationship(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if err = master.Tick(ctx, rel); err != nil {
				t.Fatal(err)
			}
			view, err := master.Observability(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, member := range view["members"].([]map[string]any) {
				if member["member_id"] != rel.PeerID {
					continue
				}
				usage, _ := member["observed"].(map[string]any)["host_usage"].(map[string]any)
				if usage["memory_total_bytes"] != total {
					t.Fatalf("node memory not delivered over %s heartbeat: %v", mode, usage)
				}
				cpu, haveCPU := intField(usage, "cpu_percent")
				if mode == "Direct" && haveCPU || mode == "Relay" && (!haveCPU || cpu < 0 || cpu > 100) {
					t.Fatalf("unexpected CPU sample over %s heartbeat: %v", mode, usage)
				}
				return
			}
			t.Fatal("follower missing from observability")
		})
	}
}
