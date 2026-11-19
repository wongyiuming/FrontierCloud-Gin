package httpapi

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

func TestPublicCryptoTransportRequiresVerifiedIngress(t *testing.T) {
	resolver, err := network.New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://master.example/api/v1/media/crypto/session", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	if securePublicCryptoTransport(req, resolver) {
		t.Fatal("plain remote request without verified context accepted")
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Real-IP", "192.0.2.10")
	req.Header.Set("X-Fc-Public-Hop", "forged")
	req.Header.Set("X-Node-Signature", "forged")
	if securePublicCryptoTransport(req, resolver) {
		t.Fatal("forged proxy and node headers accepted")
	}
	ctx, err := network.WithAuthenticatedIngress(req.Context(), network.AuthenticatedIngress{
		NodeID: "0123456789abcdef0123456789abcdef", Generation: 1,
		PublicOrigin: "https://peer.example", ClientIP: "192.0.2.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	verified := req.WithContext(ctx)
	if !securePublicCryptoTransport(verified, resolver) {
		t.Fatal("authenticated ingress rejected")
	}
	if resolver.SecureAdmin(verified) {
		t.Fatal("authenticated public ingress weakened Admin transport")
	}
	bareTLS := httptest.NewRequest("POST", "https://master.example/", nil)
	bareTLS.TLS = &tls.ConnectionState{}
	if !securePublicCryptoTransport(bareTLS, resolver) {
		t.Fatal("direct HTTPS rejected")
	}
}
