package certmanager

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"golang.org/x/net/netutil"
)

// Serve exposes read-only controller facts on the mounted Unix socket. It has
// no public management listener and no manual renew/disable/upload operation.
func (m *Manager) Serve() error {
	socket := filepath.Join(m.opt.runtime, "control.sock")
	if info, e := os.Lstat(socket); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("unsafe certificate control socket")
		}
		if e = os.Remove(socket); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	listener, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	defer listener.Close()
	defer os.Remove(socket)
	if e = os.Chmod(socket, 0660); e != nil {
		return e
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" || r.URL.Path != "/control" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, 1025))
		if e != nil || len(body) > 1024 {
			http.Error(w, "invalid request", 400)
			return
		}
		var request certificate.Request
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.Enabled || request.Action != "status" && request.Action != "download" || request.Action == "status" && (request.BrowserPublicKey != "" || request.BrowserNonce != "") {
			http.Error(w, "certificate management is automatic and read-only", 400)
			return
		}
		v := m.Status()
		if request.Action == "download" {
			var err error
			v, err = m.download(request)
			if err != nil {
				http.Error(w, "verified certificate download unavailable", 409)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})}
	done := make(chan struct{})
	go func() {
		select {
		case <-m.ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	e = server.Serve(netutil.LimitListener(listener, 1))
	close(done)
	if errors.Is(e, http.ErrServerClosed) || m.ctx.Err() != nil {
		return nil
	}
	return e
}
