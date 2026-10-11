package certmanager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

func TestCertificateDownloadBoundToBrowserAndVerifiedIdentity(t *testing.T) {
	opt, _, _ := fixture(t, Relay)
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	browser, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	request := certificate.Request{Action: "download", BrowserPublicKey: encode(browser.PublicKey().Bytes()), BrowserNonce: encode(nonce)}
	result, err := m.download(request)
	if err != nil {
		t.Fatal(err)
	}
	envelope := result.Download
	if envelope == nil || envelope.Algorithm != downloadAlgorithm || envelope.Hostname != opt.host || envelope.BrowserNonce != request.BrowserNonce {
		t.Fatal("missing browser identity binding")
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Fatal("node exposed plaintext pair in control response")
	}
	decode := func(v string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	public, err := ecdh.P256().NewPublicKey(decode(envelope.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := browser.ECDH(public)
	if err != nil {
		t.Fatal(err)
	}
	aad := strings.Join([]string{"frontiercloud.certificate.download.v1", envelope.Hostname, envelope.Fingerprint, envelope.BrowserNonce}, "\n")
	key, err := hkdf.Key(sha256.New, secret, decode(envelope.Salt), aad, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv, sealed := decode(envelope.IV), decode(envelope.Ciphertext)
	plaintext, err := gcm.Open(nil, iv, sealed, []byte(aad))
	if err != nil {
		t.Fatal("browser cannot decrypt envelope", err)
	}
	var pair struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	if err = json.Unmarshal(plaintext, &pair); err != nil {
		t.Fatal(err)
	}
	valid, err := Validate(opt.host, []byte(pair.Certificate), []byte(pair.PrivateKey), opt.roots, time.Now())
	if err != nil || fingerprint(valid) != result.Fingerprint {
		t.Fatal("download differs from verified serving identity", err)
	}
	if _, err = gcm.Open(nil, iv, sealed, []byte(aad+"changed")); err == nil {
		t.Fatal("changed node identity was authenticated")
	}
	sealed[0] ^= 1
	if _, err = gcm.Open(nil, iv, sealed, []byte(aad)); err == nil {
		t.Fatal("ciphertext modification was authenticated")
	}
	second, err := m.download(request)
	if err != nil {
		t.Fatal(err)
	}
	if second.Download.PublicKey == envelope.PublicKey || second.Download.Ciphertext == envelope.Ciphertext {
		t.Fatal("download reused ephemeral wrapping key")
	}
	for _, bad := range []certificate.Request{
		{Action: "download", Enabled: true, BrowserPublicKey: request.BrowserPublicKey, BrowserNonce: request.BrowserNonce},
		{Action: "download", BrowserPublicKey: "invalid", BrowserNonce: request.BrowserNonce},
		{Action: "download", BrowserPublicKey: request.BrowserPublicKey, BrowserNonce: "invalid"},
		{Action: "renew", BrowserPublicKey: request.BrowserPublicKey, BrowserNonce: request.BrowserNonce},
	} {
		if _, err = m.download(bad); err == nil {
			t.Fatal("unsafe download request admitted", bad.Action)
		}
	}
	m.mu.Lock()
	m.view.HTTPSReady = false
	m.mu.Unlock()
	if _, err = m.download(request); err == nil {
		t.Fatal("unverified serving state exported key")
	}
}
