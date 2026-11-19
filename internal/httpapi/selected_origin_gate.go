package httpapi

import (
	"sync"
	"time"
)

// selectedOriginGate bounds work created by the optional origin proof endpoint.
// It never delays unrelated requests; callers receive 429 and may retry.
type selectedOriginGate struct {
	mu                       sync.Mutex
	tokens, burst, perSecond float64
	at                       time.Time
	inflight                 chan struct{}
}

func newSelectedOriginGate(burst int, perSecond float64, concurrent int) *selectedOriginGate {
	return &selectedOriginGate{tokens: float64(burst), burst: float64(burst), perSecond: perSecond, at: time.Now(), inflight: make(chan struct{}, concurrent)}
}
func (g *selectedOriginGate) acquire() bool {
	g.mu.Lock()
	now := time.Now()
	g.tokens += now.Sub(g.at).Seconds() * g.perSecond
	if g.tokens > g.burst {
		g.tokens = g.burst
	}
	g.at = now
	allowed := g.tokens >= 1
	if allowed {
		g.tokens--
	}
	g.mu.Unlock()
	if !allowed {
		return false
	}
	select {
	case g.inflight <- struct{}{}:
		return true
	default:
		return false
	}
}
func (g *selectedOriginGate) release() { <-g.inflight }
