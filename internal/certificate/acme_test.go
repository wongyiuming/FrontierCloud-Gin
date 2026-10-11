package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// The real ACME SDK exchanges signed v2 requests with this bounded fixture CA.
// The production factory still accepts only approved HTTPS directory URLs.
func TestACMEV2OrderRealHTTPChallengeCSRAndCertificate(t *testing.T) {
	host := "storage.fixture.test"
	address := port(t)
	var validated atomic.Bool
	var finalized atomic.Bool
	var nonces atomic.Int32
	var certificatePEM []byte
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	var base string
	payload := func(r *http.Request) map[string]any {
		t.Helper()
		var jws struct {
			Payload string `json:"payload"`
		}
		if e := json.NewDecoder(r.Body).Decode(&jws); e != nil {
			t.Fatal(e)
		}
		b, e := base64.RawURLEncoding.DecodeString(jws.Payload)
		if e != nil {
			t.Fatal(e)
		}
		var p map[string]any
		if len(b) > 0 {
			if e = json.Unmarshal(b, &p); e != nil {
				t.Fatal(e)
			}
		}
		return p
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString([]byte("nonce-"+strconv.Itoa(int(nonces.Add(1))))))
		w.Header().Set("Content-Type", "application/json")
		order := func() map[string]any {
			status := "pending"
			if validated.Load() {
				status = "ready"
			}
			if finalized.Load() {
				status = "valid"
			}
			return map[string]any{"status": status, "identifiers": []map[string]string{{"type": "dns", "value": host}}, "authorizations": []string{base + "/authz"}, "finalize": base + "/finalize", "certificate": base + "/cert"}
		}
		switch r.URL.Path {
		case "/directory":
			json.NewEncoder(w).Encode(map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/new-order"})
		case "/nonce":
			w.WriteHeader(200)
		case "/account":
			payload(r)
			w.Header().Set("Location", base+"/account/1")
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
		case "/new-order":
			p := payload(r)
			ids := p["identifiers"].([]any)
			if len(ids) != 1 || ids[0].(map[string]any)["value"] != host {
				t.Fatal("wrong order hostname", p)
			}
			w.Header().Set("Location", base+"/order")
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(order())
		case "/authz":
			payload(r)
			status := "pending"
			if validated.Load() {
				status = "valid"
			}
			json.NewEncoder(w).Encode(map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": host}, "challenges": []map[string]string{{"type": "http-01", "url": base + "/challenge", "token": "fixture_token", "status": status}}})
		case "/challenge":
			payload(r)
			request, _ := http.NewRequest("GET", "http://"+address+"/.well-known/acme-challenge/fixture_token", nil)
			request.Host = host
			client := http.Client{Timeout: time.Second}
			response, e := client.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			b, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != 200 || len(b) < len("fixture_token.") || string(b[:len("fixture_token.")]) != "fixture_token." {
				t.Fatal("HTTP-01 proof missing", response.Status, string(b))
			}
			validated.Store(true)
			json.NewEncoder(w).Encode(map[string]string{"type": "http-01", "url": base + "/challenge", "token": "fixture_token", "status": "valid"})
		case "/order":
			payload(r)
			json.NewEncoder(w).Encode(order())
		case "/finalize":
			p := payload(r)
			der, e := base64.RawURLEncoding.DecodeString(p["csr"].(string))
			if e != nil {
				t.Fatal(e)
			}
			csr, e := x509.ParseCertificateRequest(der)
			if e != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != host || !validated.Load() {
				t.Fatal("CSR/authorization mismatch", csr, e)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: host}, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, e = x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, caKey)
			if e != nil {
				t.Fatal(e)
			}
			certificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			finalized.Store(true)
			json.NewEncoder(w).Encode(order())
		case "/cert":
			payload(r)
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(certificatePEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base = server.URL
	account, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	client := &acme.Client{Key: account, DirectoryURL: base + "/directory", HTTPClient: server.Client()}
	a := openTest(t, address, func(ctx context.Context, present func(string, string) (func(), error)) ([]byte, []byte, error) {
		return issueOrder(ctx, client, host, "", present)
	})
	if _, e = a.Start(); e != nil {
		t.Fatal(e)
	}
	v := waitJob(t, a)
	if v.Job.State != "success" || v.State != "valid" || !validated.Load() || !finalized.Load() || v.Job.Port80Active {
		t.Fatal("ACME order did not complete safely", v)
	}
}
