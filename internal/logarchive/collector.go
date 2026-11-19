package logarchive

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const CollectorSocket = "/run/frontiercloud-project-logs/collector.sock"

func CollectorReady() bool {
	i, e := os.Lstat(CollectorSocket)
	return e == nil && i.Mode()&os.ModeSocket != 0
}

type CaptureSink interface {
	Enabled() bool
	Capture(Kind, map[string]any)
}
type DisabledSink struct{}

func (DisabledSink) Enabled() bool                { return false }
func (DisabledSink) Capture(Kind, map[string]any) {}

// The dedicated shared volume contains only a Unix socket, never a plaintext
// spool. The existing traffic-counter mount remains read-only for Web.
func OpenCollector(sink CaptureSink, fallback io.Writer) (func() error, error) {
	info, e := os.Lstat(filepath.Dir(CollectorSocket))
	if os.IsNotExist(e) {
		return func() error { return nil }, nil
	}
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrPolicy
	}
	if old, e := os.Lstat(CollectorSocket); e == nil {
		if old.Mode()&os.ModeSocket == 0 {
			return nil, ErrPolicy
		}
		if e = os.Remove(CollectorSocket); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	conn, e := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: CollectorSocket, Net: "unixgram"})
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(CollectorSocket, 0660); e != nil {
		conn.Close()
		return nil, e
	}
	conn.SetReadBuffer(64 << 10)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buffer := make([]byte, 8193)
		for {
			n, _, e := conn.ReadFromUnix(buffer)
			if e != nil {
				return
			}
			if n == len(buffer) {
				continue
			}
			raw := strings.TrimSpace(string(buffer[:n]))
			at := strings.IndexByte(raw, '{')
			fields := map[string]any{}
			kind := Access
			if at < 0 || json.Unmarshal([]byte(raw[at:]), &fields) != nil {
				if len(raw) > 512 {
					raw = raw[:512]
				}
				fields = map[string]any{"component": "nginx", "message": raw}
				kind = Error
			}
			if len(fields) > 40 {
				continue
			}
			if fields["component"] == "certificate" {
				kind = Certificate
			}
			if status, ok := fields["status"].(float64); ok && status >= 500 {
				kind = Error
			}
			if sink.Enabled() {
				sink.Capture(kind, fields)
			} else {
				if gate, ok := sink.(interface{ FallbackAllowed() bool }); ok && !gate.FallbackAllowed() {
					sink.Capture(Application, map[string]any{"message": "unconfigured_log_omitted"})
					continue
				}
				line, e := json.Marshal(fields)
				if e == nil {
					fallback.Write(append(line, '\n'))
				}
			}
		}
	}()
	return func() error { e := conn.Close(); wg.Wait(); return e }, nil
}

// Certificate-agent forwarding never falls back to plaintext persistence.
type ForwardWriter struct{ dropped atomic.Int64 }

func (w *ForwardWriter) Write(p []byte) (int, error) {
	var payload map[string]any
	if len(p) > 7000 || json.Unmarshal(p, &payload) != nil {
		w.dropped.Add(1)
		return len(p), nil
	}
	payload["component"] = "certificate"
	payload["forward_dropped"] = w.dropped.Load()
	raw, e := json.Marshal(payload)
	if e != nil {
		return len(p), nil
	}
	conn, e := net.DialTimeout("unixgram", CollectorSocket, 10*time.Millisecond)
	if e != nil {
		w.dropped.Add(1)
		return len(p), nil
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if _, e = conn.Write(raw); e != nil {
		w.dropped.Add(1)
	} else {
		w.dropped.Store(0)
	}
	return len(p), nil
}
