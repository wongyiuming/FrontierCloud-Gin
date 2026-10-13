package businesstraffic

import (
	"sync"
	"testing"
	"time"
)

func TestActualBytesHysteresisAndSustainedLowTraffic(t *testing.T) {
	now := time.Unix(1800000000, 0)
	m := New(func() time.Time { return now })
	if v := m.Snapshot(); v.CanRun || v.ResumeAfter != 30 {
		t.Fatal(v)
	}
	now = now.Add(LowInterval)
	if !m.Snapshot().CanRun {
		t.Fatal("warm idle monitor did not open")
	}
	m.Egress(int(HighBytesPerSecond))
	if v := m.Snapshot(); v.CanRun || v.State != "high_traffic" || v.Recent != HighBytesPerSecond {
		t.Fatal(v)
	}
	now = now.Add(Window)
	if v := m.Snapshot(); v.CanRun || v.ResumeAfter != 30 {
		t.Fatal(v)
	}
	now = now.Add(29 * time.Second)
	if m.Snapshot().CanRun {
		t.Fatal("recovered before sustained low interval")
	}
	// Moderate traffic does not cause oscillation when running, but breaks
	// the low interval while waiting. Ingress and egress both count.
	m.Ingress(int(LowBytesPerSecond + 1))
	if v := m.Snapshot(); v.CanRun || v.State != "high_traffic" {
		t.Fatal(v)
	}
	now = now.Add(Window)
	m.Snapshot()
	now = now.Add(LowInterval)
	if !m.Snapshot().CanRun {
		t.Fatal("low interval did not recover")
	}
	m.Ingress(int(LowBytesPerSecond + 1))
	if !m.Snapshot().CanRun {
		t.Fatal("running work oscillated below high threshold")
	}
	now = now.Add(-time.Minute)
	if m.Snapshot().CanRun {
		t.Fatal("backwards clock opened the gate")
	}
}

func TestConcurrentCountersAreBoundedAndRetainBothDirections(t *testing.T) {
	now := time.Unix(1800000000, 0)
	m := New(func() time.Time { return now })
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				m.Ingress(7)
				m.Egress(13)
				m.Snapshot()
			}
		}()
	}
	workers.Wait()
	v := m.Snapshot()
	if v.Ingress != 1120 || v.Egress != 2080 || v.Recent != 16000 {
		t.Fatal(v)
	}
}

func TestUnavailableGatewayCannotBecomeLowTrafficByWaiting(t *testing.T) {
	now := time.Unix(1800000000, 0)
	m := New(func() time.Time { return now })
	m.Unavailable("edge_traffic_unavailable")
	now = now.Add(time.Hour)
	if v := m.Snapshot(); v.CanRun || v.State != "unavailable" || v.Reason != "edge_traffic_unavailable" || v.MetricSource != "go_http_body" {
		t.Fatal(v)
	}
}
