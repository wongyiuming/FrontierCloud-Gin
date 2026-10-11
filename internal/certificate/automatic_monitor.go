package certificate

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Read-only observations are cached independently of heartbeat/media work.
// Losing the controller does not shut down a valid HTTPS serving process.
type AutomaticMonitor struct {
	mu     sync.Mutex
	client Client
	view   View
}

func NewAutomaticMonitor(client Client, host string, enabled bool) *AutomaticMonitor {
	state := "PENDING"
	if !enabled {
		state = "DISABLED"
	}
	return &AutomaticMonitor{client: client, view: View{Hostname: host, Enabled: enabled, Managed: enabled, Mode: "automatic", AutoRenew: enabled, State: state}}
}
func (m *AutomaticMonitor) Status() View {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.view
	v.SAN = append([]string(nil), v.SAN...)
	return v
}
func (m *AutomaticMonitor) Control(ctx context.Context, r Request) (View, error) {
	if r.Action == "download" && !r.Enabled {
		return m.client.Control(ctx, r)
	}
	if r.Action != "status" || r.Enabled {
		return View{}, errors.New("certificate management is automatic and read-only")
	}
	v, e := m.client.Control(ctx, r)
	m.mu.Lock()
	defer m.mu.Unlock()
	if e == nil {
		m.view = v
	} else {
		m.view.ControllerRunning = false
		m.view.LastError = "controller_unavailable"
		m.view.HTTPSReady = false
		if m.view.Enabled {
			m.view.State = "DEGRADED"
		}
	}
	return m.view, e
}
func (m *AutomaticMonitor) Run(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, _ = m.Control(c, Request{Action: "status"})
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
