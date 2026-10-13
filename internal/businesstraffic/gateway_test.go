package businesstraffic

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func gatewayFixture(now time.Time, epoch string) GatewaySample {
	return GatewaySample{Format: "frontiercloud-nginx-traffic", Version: 1, Epoch: epoch, ObservedAt: now.UnixMilli()}
}
func TestGatewayEpochFreshnessAndActualRatesGateMigration(t *testing.T) {
	now := time.Unix(1800000000, 0)
	m := New(func() time.Time { return now })
	m.gatewayRequired = true
	if m.Snapshot().State != "unavailable" {
		t.Fatal(m.Snapshot())
	}
	s := gatewayFixture(now, "12-345")
	m.updateGateway(&s)
	for i := 0; i < 30; i++ {
		now = now.Add(time.Second)
		s.ObservedAt = now.UnixMilli()
		m.updateGateway(&s)
	}
	if !m.Snapshot().CanRun {
		t.Fatal(m.Snapshot())
	}
	s.Egress = HighBytesPerSecond
	s.Recent = HighBytesPerSecond
	m.updateGateway(&s)
	if v := m.Snapshot(); v.CanRun || v.Egress != HighBytesPerSecond || v.MetricSource != "nginx_http_io+go_http_body" {
		t.Fatal(v)
	}
	s.Egress, s.Recent = 0, 0
	for i := 0; i < 31; i++ {
		now = now.Add(time.Second)
		s.ObservedAt = now.UnixMilli()
		m.updateGateway(&s)
	}
	if !m.Snapshot().CanRun {
		t.Fatal(m.Snapshot())
	}
	s.Epoch = "13-678"
	m.updateGateway(&s)
	if m.Snapshot().CanRun {
		t.Fatal("gateway restart reused old quiet interval")
	}
	now = now.Add(3 * time.Second)
	if m.Snapshot().State != "unavailable" {
		t.Fatal("stale gateway called quiet")
	}
	for _, change := range []func(*GatewaySample){func(s *GatewaySample) { s.Ingress = -1 }, func(s *GatewaySample) { s.ObservedAt = now.Add(-time.Minute).UnixMilli() }, func(s *GatewaySample) { s.Epoch = "bad" }, func(s *GatewaySample) { s.Version = 2 }} {
		v := gatewayFixture(now, "12-345")
		change(&v)
		raw, _ := json.Marshal(v)
		if _, e := decodeGateway(raw, now); e == nil {
			t.Fatal("invalid gateway sample admitted")
		}
	}
}

func TestGatewayPollerUsesPrivateUnixSocketAndJoinsShutdown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux container Unix observation socket")
	}
	socket := filepath.Join(t.TempDir(), "counter.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/traffic" {
			t.Error(r.URL.Path)
		}
		json.NewEncoder(w).Encode(gatewayFixture(time.Now(), "12-345"))
	})}
	go server.Serve(listener)
	defer server.Close()
	m := New(nil)
	stop := m.watchGateway(context.Background(), socket)
	deadline := time.Now().Add(3 * time.Second)
	for m.Snapshot().State == "unavailable" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.Snapshot().State == "unavailable" {
		t.Fatal("Unix sample not received")
	}
	if e = stop(); e != nil {
		t.Fatal(e)
	}
	if e = stop(); e != nil {
		t.Fatal(e)
	}
}

func TestGatewayShortBurstPausesBeforeFiveSecondAveragePeaks(t *testing.T) {
	now := time.Unix(1800000000, 0)
	m := New(func() time.Time { return now })
	m.gatewayRequired = true
	s := gatewayFixture(now, "12-345")
	m.updateGateway(&s)
	for i := 0; i < 30; i++ {
		now = now.Add(time.Second)
		s.ObservedAt = now.UnixMilli()
		m.updateGateway(&s)
	}
	if !m.Snapshot().CanRun {
		t.Fatal("idle gateway did not open")
	}
	// A short sendfile burst crosses the one-second limit while its five-second
	// average is still below the pause threshold and Go has seen no body bytes.
	s.Egress, s.Recent = HighBytesPerSecond/5, HighBytesPerSecond
	m.updateGateway(&s)
	if v := m.Snapshot(); v.CanRun || v.State != "high_traffic" {
		t.Fatal("gateway-only burst did not pause work", v)
	}
	s.Egress, s.Recent = 0, 0
	for i := 0; i < 30; i++ {
		now = now.Add(time.Second)
		s.ObservedAt = now.UnixMilli()
		m.updateGateway(&s)
		if m.Snapshot().CanRun {
			t.Fatal("gateway burst resumed before continuous low interval")
		}
	}
	now = now.Add(time.Second)
	s.ObservedAt = now.UnixMilli()
	m.updateGateway(&s)
	if !m.Snapshot().CanRun {
		t.Fatal("gateway quiet interval did not resume work")
	}
}
