package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

func TestEndpointIPv6PreservesPrivateLANAndRejectsLocalTargets(t *testing.T) {
	for raw, want := range map[string]string{
		"https://[2606:4700:4700:0:0:0:0:1111]:443/": "https://[2606:4700:4700::1111]",
		"https://[2606:4700:4700::1111]:8443":        "https://[2606:4700:4700::1111]:8443",
		"https://[fd12:3456::1]:8443":                "https://[fd12:3456::1]:8443",
		"https://192.168.6.201:14443":                "https://192.168.6.201:14443",
		"https://[::ffff:124.220.156.46]":            "https://124.220.156.46",
	} {
		got, err := Endpoint(raw)
		if err != nil || got != want {
			t.Fatal(raw, got, want, err)
		}
	}
	for _, raw := range []string{"https://[::]", "https://[::1]", "https://[::ffff:127.0.0.1]", "https://[::ffff:169.254.169.254]", "https://[fe80::1]", "https://[ff02::1]", "https://[fd12:3456::1%25eth0]", "https://2606:4700:4700::1111", "https://[2606:4700:4700::1111]:0", "https://[2606:4700:4700::1111]:65536", "https://[2606:4700:4700::1111]/%2f", "https://[2606:4700:4700::1111]?"} {
		if got, err := Endpoint(raw); err == nil {
			t.Fatal("unsafe IPv6 endpoint admitted", raw, got)
		}
	}
}

// This IPv4 case also runs unchanged against released 8fa2b4f transport.go:
// the protocol-v2 wire shape and strict IP-SAN trust already work on old Master.
func TestControlPublicIPIdentityCompatibility(t *testing.T) {
	for _, test := range []struct{ name, host, origin string }{
		{"IPv4", "124.220.156.46", "https://124.220.156.46"},
		{"IPv6", "2606:4700:4700::1111", "https://[2606:4700:4700::1111]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			private := protocol.Encode(bytes.Repeat([]byte{7}, 32))
			public, _ := protocol.PublicKey(private)
			id := strings.Repeat("1", 32)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != strings.TrimPrefix(test.origin, "https://") {
					t.Error("IP HTTP Host changed", r.Host)
				}
				payload := map[string]any{"node_id": id, "role": "Follower", "endpoint": test.origin, "public_key": public, "challenge": r.URL.Query().Get("challenge"), "protocol": 2, "app_version": AppVersion, "storage_transport": "direct"}
				signature, err := protocol.Sign(private, payload)
				if err != nil {
					t.Error(err)
				}
				json.NewEncoder(w).Encode(Envelope{payload, signature})
			})
			server, roots := ipTransportFixture(t, test.host, false, handler)
			transport := testTransport(t, server, roots)
			peer, err := transport.Identity(context.Background(), test.origin, id, public, "Follower")
			if err != nil || peer.Endpoint != test.origin || peer.StorageTransport != "direct" {
				t.Fatal("IP protocol-v2 Direct identity rejected", peer, err)
			}
			untrusted := testTransport(t, server, x509.NewCertPool())
			if _, err = untrusted.Identity(context.Background(), test.origin, id, public, "Follower"); err == nil {
				t.Fatal("IP endpoint bypassed normal CA trust")
			}
			wrongSAN, wrongRoots := ipTransportFixture(t, test.host, true, handler)
			wrong := testTransport(t, wrongSAN, wrongRoots)
			if _, err = wrong.Identity(context.Background(), test.origin, id, public, "Follower"); err == nil {
				t.Fatal("IP string in DNS SAN replaced required IP SAN")
			}
		})
	}
}

func ipTransportFixture(t *testing.T, host string, dnsOnly bool, handler http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if dnsOnly {
		leaf.DNSNames = []string{host}
	} else {
		leaf.IPAddresses = []net.IP{net.ParseIP(host)}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: key}}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != "" {
			t.Error("literal IP TLS unexpectedly sent SNI", hello.ServerName)
		}
		return nil, nil
	}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return server, roots
}
