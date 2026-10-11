package certificate

import (
	"context"
	"sync"
	"time"
)

// Agent observations are separate from heartbeat/media paths. An unavailable
// local agent never turns a valid TLS server or successful heartbeat into failure.
type Monitor struct {
	mu       sync.Mutex
	client   Client
	tls      *TLS
	observed View
}

func NewMonitor(t *TLS, c Client) *Monitor { return &Monitor{tls: t, client: c} }
func (m *Monitor) Status() View {
	v := m.tls.Status()
	m.mu.Lock()
	defer m.mu.Unlock()
	v.Managed = m.client != nil && m.observed.Managed
	v.AutoRenew = m.observed.AutoRenew
	v.Job = m.observed.Job
	return v
}
func (m *Monitor) Control(ctx context.Context, r Request) (View, error) {
	v, e := m.client.Control(ctx, r)
	m.mu.Lock()
	if e == nil {
		m.observed = v
	} else {
		m.observed.Job.Code = "agent_unavailable"
	}
	m.mu.Unlock()
	return v, e
}
func (m *Monitor) Run(ctx context.Context) {
	if m.client == nil {
		return
	}
	tick := time.NewTicker(15 * time.Second)
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
