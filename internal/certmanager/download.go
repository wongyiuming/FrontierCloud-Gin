package certmanager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

const downloadAlgorithm = "P256-HKDF-SHA256-AES256GCM"

func decode(value string, limit int) ([]byte, error) {
	if len(value) > limit {
		return nil, errors.New("invalid browser key")
	}
	return base64.RawURLEncoding.DecodeString(value)
}
func (m *Manager) download(r certificate.Request) (certificate.View, error) {
	if r.Action != "download" || r.Enabled {
		return certificate.View{}, errors.New("invalid download request")
	}
	pub, e := decode(r.BrowserPublicKey, 90)
	if e != nil {
		return certificate.View{}, e
	}
	peer, e := ecdh.P256().NewPublicKey(pub)
	if e != nil {
		return certificate.View{}, errors.New("invalid browser public key")
	}
	nonce, e := decode(r.BrowserNonce, 43)
	if e != nil || len(nonce) != 32 {
		return certificate.View{}, errors.New("invalid browser download nonce")
	}
	v := m.Status()
	if !v.Enabled || !v.HTTPSReady || !v.ServingMatches {
		return certificate.View{}, errors.New("download requires verified active node TLS")
	}
	cert, key, e := readGeneration(m.opt.published)
	if e != nil {
		return certificate.View{}, e
	}
	defer clear(key)
	pair, e := Validate(m.opt.host, cert, key, m.opt.roots, time.Now())
	if e != nil || fingerprint(pair) != v.Fingerprint {
		return certificate.View{}, errors.New("certificate changed during download; query status and retry")
	}
	private, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return certificate.View{}, e
	}
	secret, e := private.ECDH(peer)
	if e != nil {
		return certificate.View{}, e
	}
	defer clear(secret)
	salt := make([]byte, 32)
	if _, e = rand.Read(salt); e != nil {
		return certificate.View{}, e
	}
	aad := strings.Join([]string{"frontiercloud.certificate.download.v1", v.Hostname, v.Fingerprint, r.BrowserNonce}, "\n")
	wrapping, e := hkdf.Key(sha256.New, secret, salt, aad, 32)
	if e != nil {
		return certificate.View{}, e
	}
	defer clear(wrapping)
	block, e := aes.NewCipher(wrapping)
	if e != nil {
		return certificate.View{}, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return certificate.View{}, e
	}
	iv := make([]byte, gcm.NonceSize())
	if _, e = rand.Read(iv); e != nil {
		return certificate.View{}, e
	}
	plaintext, e := json.Marshal(struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}{string(cert), string(key)})
	if e != nil {
		return certificate.View{}, e
	}
	defer clear(plaintext)
	encode := base64.RawURLEncoding.EncodeToString
	v.Download = &certificate.DownloadEnvelope{Algorithm: downloadAlgorithm, PublicKey: encode(private.PublicKey().Bytes()), Salt: encode(salt), IV: encode(iv), Ciphertext: encode(gcm.Seal(nil, iv, plaintext, []byte(aad))), Hostname: v.Hostname, Fingerprint: v.Fingerprint, BrowserNonce: r.BrowserNonce}
	return v, nil
}
