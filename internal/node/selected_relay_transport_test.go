package node

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

func TestSelectedRelayStreamingAuthenticatesTokenAndTLS(t *testing.T) {
	credential := protocol.Encode(bytes.Repeat([]byte{8}, 48))
	relationship := strings.Repeat("a", 32)
	token := "opaque-test-capability"
	payload := bytes.Repeat([]byte("ciphertext"), 100000)
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := map[string]string{}
		for _, name := range []string{"X-Node-Relationship", "X-Node-Time", "X-Node-Nonce", "X-Node-Signature"} {
			headers[name] = r.Header.Get(name)
		}
		if r.Method != http.MethodPut || r.URL.Path != selectedRelayPath || r.Header.Get("Origin") != "" || r.Header.Get("X-Fc-Selected-Upload") != token || r.ContentLength != int64(len(payload)) {
			t.Error("unexpected request")
			w.WriteHeader(400)
			return
		}
		if _, err := protocol.VerifyAuth(credential, headers, r.Method, r.URL.Path, []byte(token), time.Now().Unix()); err != nil {
			t.Error("node authentication", err)
			w.WriteHeader(403)
			return
		}
		got, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(got, payload) {
			t.Error("incorrect stream")
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	transport := testTransport(t, server, roots)
	relay := transport.selectedRelay
	if relay.Transport == transport.storage.Transport || relay.Timeout != 0 ||
		relay.Transport.(*http.Transport).ResponseHeaderTimeout != 15*time.Minute ||
		transport.storage.Transport.(*http.Transport).ResponseHeaderTimeout != 30*time.Second {
		t.Fatal("selected Relay verification budget must be independent of media streaming")
	}
	result, err := transport.selectedRelayUpload(context.Background(), "https://node.test", relationship, credential, token, bytes.NewReader(payload), int64(len(payload)))
	if err != nil || result["ok"] != true {
		t.Fatal("relay upload", err)
	}
	untrusted := testTransport(t, server, x509.NewCertPool())
	if _, err = untrusted.selectedRelayUpload(context.Background(), "https://node.test", relationship, credential, token, bytes.NewReader(payload), int64(len(payload))); err == nil || strings.Contains(err.Error(), token) {
		t.Fatal("untrusted TLS or secret in error")
	}
}
