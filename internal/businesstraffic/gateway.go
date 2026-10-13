package businesstraffic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"
)

const GatewaySocket = "/run/frontiercloud-traffic/counter.sock"

type GatewaySample struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	Epoch      string `json:"epoch"`
	ObservedAt int64  `json:"observed_at_ms"`
	Ingress    int64  `json:"ingress_bytes_per_second"`
	Egress     int64  `json:"egress_bytes_per_second"`
	Recent     int64  `json:"recent_bytes_per_second"`
}

var gatewayEpoch = regexp.MustCompile(`^[0-9]{1,12}-[0-9]{1,20}$`)

func decodeGateway(raw []byte, now time.Time) (GatewaySample, error) {
	var sample GatewaySample
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 4096 || d.Decode(&sample) != nil || d.Decode(new(any)) != io.EOF || sample.Format != "frontiercloud-nginx-traffic" || sample.Version != 1 || !gatewayEpoch.MatchString(sample.Epoch) || sample.ObservedAt < now.Add(-2*time.Second).UnixMilli() || sample.ObservedAt > now.Add(2*time.Second).UnixMilli() || sample.Ingress < 0 || sample.Egress < 0 || sample.Recent < 0 {
		return sample, errors.New("gateway traffic observation unavailable")
	}
	return sample, nil
}
func (m *Monitor) updateGateway(sample *GatewaySample) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if sample == nil || m.gateway == nil || m.gateway.Epoch != sample.Epoch {
		m.paused = true
		m.lowSince = time.Time{}
	}
	if sample == nil {
		m.gateway = nil
	} else {
		value := *sample
		m.gateway = &value
	}
	m.view(m.now())
}

// One joined poller reads only a fixed local Unix socket. No URL, credential,
// private payload, Docker socket or host network configuration is involved.
func (m *Monitor) WatchGateway(parent context.Context) func() error {
	return m.watchGateway(parent, GatewaySocket)
}
func (m *Monitor) watchGateway(parent context.Context, socket string) func() error {
	m.mutex.Lock()
	m.gatewayRequired = true
	m.unavailable = ""
	m.mutex.Unlock()
	ctx, cancel := context.WithCancel(parent)
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
		}}
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			req, e := http.NewRequestWithContext(ctx, "GET", "http://gateway/traffic", nil)
			var sample *GatewaySample
			if e == nil {
				response, err := client.Do(req)
				if err == nil {
					raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
					response.Body.Close()
					if err == nil && response.StatusCode == 200 {
						value, err := decodeGateway(raw, m.now())
						if err == nil {
							sample = &value
						}
					}
				}
			}
			m.updateGateway(sample)
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	var once sync.Once
	return func() error { once.Do(func() { cancel(); <-done; transport.CloseIdleConnections() }); return nil }
}
