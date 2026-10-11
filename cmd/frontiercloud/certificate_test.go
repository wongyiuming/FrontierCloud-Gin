package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
)

func TestStorageHealthPinsManagedPairAfterExpiredBootstrap(t *testing.T) {
	host := "storage.fixture.test"
	dir := t.TempDir()
	write := func(directory string, serial int64, expiry time.Time) (string, string) {
		t.Helper()
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{host}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		os.MkdirAll(directory, 0700)
		cf, kf := filepath.Join(directory, "fullchain.pem"), filepath.Join(directory, "privkey.pem")
		if e = os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600); e != nil {
			t.Fatal(e)
		}
		return cf, kf
	}
	bootstrapCert, bootstrapKey := write(filepath.Join(dir, "bootstrap"), 1, time.Now().Add(-time.Hour))
	managed := filepath.Join(dir, "managed")
	generation := "0123456789abcdef0123456789abcdef"
	cert, key := write(filepath.Join(managed, generation), 2, time.Now().Add(24*time.Hour))
	if e := os.WriteFile(filepath.Join(managed, "current.json"), []byte(`{"generation":"`+generation+`"}`), 0600); e != nil {
		t.Fatal(e)
	}
	pair, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()
	settings := config.Config{ServerName: host, StorageTLSCert: bootstrapCert, StorageTLSKey: bootstrapKey, StorageCertificateDirectory: managed}
	client, e := storageHealthClient(settings)
	if e != nil {
		t.Fatal("managed readiness used expired bootstrap", e)
	}
	defer client.CloseIdleConnections()
	response, e := client.Get(server.URL)
	if e != nil {
		t.Fatal("managed local TLS readiness failed", e)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.Status)
	}
	settings.StorageCertificateDirectory = ""
	if _, e = storageHealthClient(settings); e == nil {
		t.Fatal("expired bootstrap unexpectedly ready")
	}
}
