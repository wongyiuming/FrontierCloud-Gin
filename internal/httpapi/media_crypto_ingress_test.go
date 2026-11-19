package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// The verifier tests establish how contexts are authenticated and their
// active-configuration lease held. These are actual HTTP key handlers.
func TestCryptoHandlersBindAuthenticatedIngressAndScopedRevocation(t *testing.T) {
	router, db, _, public := publicFixture(t, false)
	plain := []byte("[00:01] key authorization")
	meta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := public.crypto.FileKey(meta)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce, _ := meta.ChunkNonce(0)
	ciphertext := aead.Seal(nil, nonce, plain, meta.ChunkAAD(0))
	stage, err := public.media.Stage(context.Background(), bytes.NewReader(ciphertext), int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	path, err := public.media.PublishEncrypted(context.Background(), stage, "ingress.mp3", "music/artist", "", false, 255, store.AdminAudit{}, &meta)
	stage.Close()
	if err != nil {
		t.Fatal(err)
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handshake := gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}
	first := network.AuthenticatedIngress{NodeID: strings.Repeat("a", 32), Generation: 1, PublicOrigin: "https://entry.example:9443", ClientIP: "192.0.2.1"}
	second := network.AuthenticatedIngress{NodeID: strings.Repeat("b", 32), Generation: 2, PublicOrigin: "https://entry.example:9444", ClientIP: "192.0.2.1"}
	call := func(ingress *network.AuthenticatedIngress, target string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		payload, _ := json.Marshal(body)
		origin := first.PublicOrigin
		if ingress != nil {
			origin = ingress.PublicOrigin
		}
		r := httptest.NewRequest(http.MethodPost, origin+target, bytes.NewReader(payload))
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "198.51.100.5:1234"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if ingress != nil {
			ctx, e := network.WithAuthenticatedIngress(r.Context(), *ingress)
			if e != nil {
				t.Fatal(e)
			}
			r = r.WithContext(ctx)
		} else {
			r.Header.Set("X-Fc-Public-Ingress", first.NodeID)
			r.Header.Set("X-Fc-Public-Generation", "1")
			r.Header.Set("X-Fc-Public-Origin", first.PublicOrigin)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	w := call(&first, "/api/v1/media/crypto/session", handshake, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var grant mediacrypto.SessionGrant
	if err := json.Unmarshal(w.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != mediaCryptoCookie || !cookies[0].Secure {
		t.Fatal("authenticated HTTPS origin must issue a secure browser cookie", cookies)
	}
	cookie := cookies[0]
	payload := gin.H{"session_id": grant.SessionID, "file_path": path}
	check := func(ingress *network.AuthenticatedIngress, want int) *httptest.ResponseRecorder {
		t.Helper()
		result := call(ingress, "/api/v1/media/crypto/key", payload, cookie)
		if result.Code != want || !strings.Contains(result.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("key authorization: got %d want %d: %s", result.Code, want, result.Body.String())
		}
		return result
	}
	result := check(&first, 200)
	var response map[string]json.RawMessage
	if err := json.Unmarshal(result.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var envelope mediacrypto.KeyEnvelope
	if err := json.Unmarshal(response["key_envelope"], &envelope); err != nil || envelope.ExpiresAt != grant.ExpiresAt {
		t.Fatal("key issuance must retain the handshake deadline", err)
	}
	check(&second, 401)
	newGeneration := first
	newGeneration.Generation++
	check(&newGeneration, 401)
	otherOrigin := first
	otherOrigin.PublicOrigin = second.PublicOrigin
	check(&otherOrigin, 401)
	otherID := first
	otherID.NodeID = second.NodeID
	check(&otherID, 401)
	check(nil, 401)

	w = call(&second, "/api/v1/media/crypto/session", handshake, cookie)
	var secondGrant mediacrypto.SessionGrant
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &secondGrant) != nil {
		t.Fatal("second ingress handshake", w.Code, w.Body.String())
	}
	w = call(&second, "/api/v1/media/crypto/revoke", gin.H{}, cookie)
	if w.Code != 200 || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("revoke must not clear a cookie shared by another port", w.Code, w.Header())
	}
	check(&first, 200)
	payload["session_id"] = secondGrant.SessionID
	check(&second, 401)

	payload["session_id"] = grant.SessionID
	if err := db.Media().SetHidden(context.Background(), []string{path}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	check(&first, 404)
}

func TestCryptoOriginComparisonUsesConfiguredSchemeAndPort(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"https://entry.example", "https://ENTRY.example:443", true},
		{"https://entry.example:8443", "https://entry.example:8444", false},
		{"http://entry.example", "https://entry.example", false},
		{"https://entry.example/path", "https://entry.example", false},
		{"https://user@entry.example", "https://entry.example", false},
	} {
		if sameCryptoOrigin(tc.a, tc.b) != tc.same {
			t.Fatalf("origin comparison %q / %q", tc.a, tc.b)
		}
	}
}

func TestCryptoLocalMasterRequiresAuthoritativeIngress(t *testing.T) {
	router, db, _, public := publicFixture(t, false)
	ctx := context.Background()
	if err := public.media.WithPromotion(ctx, "Master", func(promotion store.NodePromotion) error {
		promotion.Endpoint, promotion.Allocation = "https://master.example", 10*store.GiB
		_, err := db.Nodes().PromoteIdentity(ctx, promotion, store.NodeAudit{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	public.media.ConfigureCluster(db.Nodes(), db.Pool(), nil)
	if err := public.control.ConfigurePublicOrigin("https://master.example"); err != nil {
		t.Fatal(err)
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())})
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://master.example/api/v1/media/crypto/session", bytes.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Origin", "https://master.example")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	w := call()
	if w.Code != 200 {
		t.Fatal("default Master ingress", w.Code, w.Body.String())
	}
	control := public.control
	public.control = nil
	if w = call(); w.Code != 401 {
		t.Fatal("missing authority admitted a public session", w.Code)
	}
	public.control = control
	if _, err := db.Database().Exec("UPDATE public_ingress_config SET node_id=? WHERE singleton=1", strings.Repeat("f", 32)); err != nil {
		t.Fatal(err)
	}
	if w = call(); w.Code != 401 {
		t.Fatal("nonlocal or invalid authority admitted a public session", w.Code)
	}
}
