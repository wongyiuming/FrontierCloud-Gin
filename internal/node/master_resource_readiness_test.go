package node

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestMasterDirectReadinessChecksSignedIdentityTLSAndReader(t *testing.T) {
	ctx := context.Background()
	master, _ := testNode(t, "Master", "https://control-master.test", nil)
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 2}
	serveReader := true
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/internal/v1/identity":
			signed, err := master.SignedIdentity(r.Context(), r.URL.Query().Get("challenge"))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(signed)
		case strings.HasPrefix(r.URL.Path, "/api/v1/media/master-direct/") && serveReader:
			if r.Header.Get("Origin") != ingress.PublicOrigin || r.Header.Get("X-Media-Capability") != "" {
				t.Error("probe widened request")
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"Resource authorization invalid or expired"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	master.transport = testTransport(t, server, roots)
	if err := master.VerifyMasterResourceReadiness(ctx, ingress, "Direct", "https://node.test"); err != nil {
		t.Fatal(err)
	}
	serveReader = false
	if err := master.VerifyMasterResourceReadiness(ctx, ingress, "Direct", "https://node.test"); err == nil {
		t.Fatal("missing Direct reader accepted")
	}
	serveReader = true
	master.transport = testTransport(t, server, x509.NewCertPool())
	if err := master.VerifyMasterResourceReadiness(ctx, ingress, "Direct", "https://node.test"); err == nil {
		t.Fatal("untrusted resource TLS accepted")
	}
	if err := master.VerifyMasterResourceReadiness(ctx, ingress, "Direct", "https://wrong-name.test"); err == nil {
		t.Fatal("wrong resource origin accepted")
	}
}
