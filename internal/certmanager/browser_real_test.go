package certmanager

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

// A loopback-only development fixture serves the shipping browser function and
// real node-side encryption. It is not linked into the product executable.
func TestCertificateBrowserFixture(t *testing.T) {
	work := os.Getenv("FRONTIERCLOUD_TEST_CERTIFICATE_BROWSER_WORK")
	if work == "" {
		t.Skip("requires real Chromium certificate export driver")
	}
	source, err := os.ReadFile("../../static/js/nodes.js")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "    async function downloadCertificate(")
	if start < 0 {
		t.Fatal("shipping download function missing")
	}
	end := strings.Index(string(source)[start:], "\n    function renderRows(")
	if end < 0 {
		t.Fatal("shipping download function boundary missing")
	}
	opt, _, _ := fixture(t, Relay)
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	facts := waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, "<!doctype html><meta charset=utf-8><script>const facts="+string(encoded)+";async function post(endpoint,body){const response=await fetch('/download',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!response.ok)throw new Error('download unavailable');return response.json();}"+string(source[start:start+end])+";window.run=()=>downloadCertificate('/download',facts);</script>")
		case r.Method == "POST" && r.URL.Path == "/download":
			var request certificate.Request
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
				http.Error(w, "request", 400)
				return
			}
			view, err := m.download(request)
			if err != nil {
				http.Error(w, "download unavailable", 409)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(view)
		case r.Method == "POST" && r.URL.Path == "/done":
			select {
			case done <- struct{}{}:
			default:
			}
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	metadata, _ := json.Marshal(map[string]string{"url": server.URL, "hostname": facts.Hostname, "fingerprint": facts.Fingerprint})
	if err = os.WriteFile(filepath.Join(work, "browser.json"), metadata, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Minute):
		t.Fatal("Chromium driver did not complete")
	}
}
