//go:build linux

package node

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This isolated in-process sample is not a public-network latency or capacity
// claim. SELF CPU includes both Owner and Master plus fixture overhead.
func TestSelectedAdminOriginProbeSample(t *testing.T) {
	ctx := context.Background()
	base := &localControl{nodes: map[string]*Service{}}
	master, _ := testNode(t, "Master", "https://master.test", base)
	owner, _ := testNode(t, "Follower", "https://owner.test", base)
	base.nodes["https://master.test"], base.nodes["https://owner.test"] = master, owner
	if err := master.ConfigureSelectedAdminOrigin(ctx, "https://master.test"); err != nil {
		t.Fatal(err)
	}
	pkg, err := owner.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pkg, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	wire := &selectedProbeControl{localControl: base}
	owner.transport = wire
	var before, after syscall.Rusage
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	const count = 20
	for i := 0; i < count; i++ {
		if _, err = owner.FreshSelectedAdminOrigin(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(started)
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
		t.Fatal(err)
	}
	cpu := time.Duration(after.Utime.Sec-before.Utime.Sec+after.Stime.Sec-before.Stime.Sec)*time.Second + time.Duration(after.Utime.Usec-before.Utime.Usec+after.Stime.Usec-before.Stime.Usec)*time.Microsecond
	if wire.probes != count {
		t.Fatal("unexpected control requests", wire.probes)
	}
	t.Logf("sample_count=%d all_wall=%s master_handler_wall=%s combined_process_cpu=%s; in-process synthetic control, no TLS/network", count, elapsed, wire.masterElapsed, cpu)
}
