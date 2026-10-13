// Package businesstraffic measures actual HTTP body I/O for background work
// admission. Its bounded counters contain no paths, identities or request data.
package businesstraffic

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

var ErrWait = errors.New("background work waits for low business traffic")

// Wait suspends work without spinning or retaining SQL transactions. The
// caller's deadline/authorization still applies; observations grant no rights.
func Wait(ctx context.Context, snapshot func() View) error {
	if snapshot == nil {
		return ErrWait
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if snapshot().CanRun {
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

const (
	Window             = 5 * time.Second
	LowInterval        = 30 * time.Second
	HighBytesPerSecond = int64(256 << 10)
	LowBytesPerSecond  = int64(64 << 10)
	quantum            = 100 * time.Millisecond
	count              = int(Window / quantum)
)

type View struct {
	State         string `json:"state"`
	CanRun        bool   `json:"can_run"`
	ObservedAt    int64  `json:"observed_at_ms"`
	Ingress       int64  `json:"ingress_bytes_per_second"`
	Egress        int64  `json:"egress_bytes_per_second"`
	Recent        int64  `json:"recent_bytes_per_second"`
	High          int64  `json:"high_bytes_per_second"`
	Low           int64  `json:"low_bytes_per_second"`
	WindowSeconds int64  `json:"window_seconds"`
	LowSeconds    int64  `json:"low_interval_seconds"`
	ResumeAfter   int64  `json:"resume_after_seconds"`
	Reason        string `json:"reason,omitempty"`
	MetricSource  string `json:"metric_source"`
}
type bucket struct{ tick, in, out int64 }
type Monitor struct {
	mutex           sync.Mutex
	now             func() time.Time
	buckets         [count]bucket
	paused          bool
	lowSince        time.Time
	last            time.Time
	unavailable     string
	gatewayRequired bool
	gateway         *GatewaySample
}

func (m *Monitor) Unavailable(reason string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.unavailable = reason
}

func New(now func() time.Time) *Monitor {
	if now == nil {
		now = time.Now
	}
	stamp := now()
	return &Monitor{now: now, paused: true, lowSince: stamp, last: stamp}
}

func add(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}
func (m *Monitor) record(in, out int64) {
	if in < 0 || out < 0 {
		return
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	now := m.now()
	tick := now.UnixNano() / int64(quantum)
	index := int(tick % int64(count))
	if index < 0 {
		return
	}
	b := &m.buckets[index]
	if b.tick != tick {
		*b = bucket{tick: tick}
	}
	b.in = add(b.in, in)
	b.out = add(b.out, out)
	m.view(now)
}
func (m *Monitor) Ingress(n int) { m.record(int64(n), 0) }
func (m *Monitor) Egress(n int)  { m.record(0, int64(n)) }
func (m *Monitor) Snapshot() View {
	if m == nil {
		return View{State: "unavailable"}
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.view(m.now())
}
func (m *Monitor) view(now time.Time) View {
	tick := now.UnixNano() / int64(quantum)
	var in, out, recent int64
	for _, b := range m.buckets {
		age := tick - b.tick
		if age < 0 || age >= int64(count) {
			continue
		}
		in = add(in, b.in)
		out = add(out, b.out)
		if age < int64(time.Second/quantum) {
			recent = add(recent, add(b.in, b.out))
		}
	}
	v := View{ObservedAt: now.UnixMilli(), Ingress: in / 5, Egress: out / 5, Recent: recent,
		High: HighBytesPerSecond, Low: LowBytesPerSecond, WindowSeconds: 5, LowSeconds: 30, MetricSource: "go_http_body"}
	if m.gatewayRequired {
		v.MetricSource = "nginx_http_io+go_http_body"
		if m.gateway == nil || m.gateway.ObservedAt < now.Add(-2*time.Second).UnixMilli() || m.gateway.ObservedAt > now.Add(2*time.Second).UnixMilli() {
			m.paused = true
			m.lowSince = time.Time{}
			v.State, v.Reason = "unavailable", "edge_traffic_unavailable"
			return v
		}
		// Public proxy traffic appears in both observations. Taking their maximum
		// retains gateway-only sendfile data without counting proxy payload twice.
		v.Ingress = max(v.Ingress, m.gateway.Ingress)
		v.Egress = max(v.Egress, m.gateway.Egress)
		v.Recent = max(v.Recent, m.gateway.Recent)
	}
	if m.unavailable != "" {
		v.State, v.Reason = "unavailable", m.unavailable
		return v
	}
	rate := max(add(v.Ingress, v.Egress), v.Recent)
	if now.Before(m.last) {
		m.paused = true
		m.lowSince = now
	}
	m.last = now
	if rate >= HighBytesPerSecond {
		m.paused = true
	}
	if m.paused {
		v.State = "cooldown"
		if rate > LowBytesPerSecond {
			m.lowSince = time.Time{}
			v.State = "high_traffic"
		} else {
			if m.lowSince.IsZero() {
				m.lowSince = now
			}
			remaining := LowInterval - now.Sub(m.lowSince)
			if remaining <= 0 {
				m.paused = false
			} else {
				v.ResumeAfter = int64((remaining + time.Second - 1) / time.Second)
			}
		}
	}
	if !m.paused {
		v.State = "low_traffic"
		v.CanRun = true
		v.ResumeAfter = 0
	}
	return v
}
