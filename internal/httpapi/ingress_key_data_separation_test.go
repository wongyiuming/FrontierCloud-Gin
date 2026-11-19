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

// The source planner is incomplete, but a Master's visible encrypted object
// must still be authorized independently of browser-to-Master reachability.
func TestPeerKeyEnvelopeDoesNotInventMissingMasterDirectSource(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, db, _, public, master := clusterFixture(t, "https://master.test", transport, false)
	plain := []byte("encrypted media payload")
	meta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := public.crypto.FileKey(meta)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := meta.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, plain, meta.ChunkAAD(0))
	stage, err := public.media.Stage(ctx, bytes.NewReader(ciphertext), int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	name, err := public.media.PublishEncrypted(ctx, stage, "master-direct.mp3", "music/artist", "", false, 255, store.AdminAudit{}, &meta)
	stage.Close()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	routing := db.Nodes().(store.PublicRoutingRepository)
	policy, err := routing.ConfirmNativeTransport(ctx, identity.ID, "Direct", 0, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	selected := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 8}
	public.media.ConfigureCluster(selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: routing, selected: selected}, db.Pool(), master)
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	call := func(path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, selected.PublicOrigin+path, bytes.NewReader(raw))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", selected.PublicOrigin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		verified, e := network.WithAuthenticatedIngress(r.Context(), network.AuthenticatedIngress{NodeID: selected.NodeID, PublicOrigin: selected.PublicOrigin, Generation: selected.Generation, ClientIP: "192.0.2.1"})
		if e != nil {
			t.Fatal(e)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r.WithContext(verified))
		return w
	}
	session := call("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, nil)
	var grant mediacrypto.SessionGrant
	if session.Code != 200 || json.Unmarshal(session.Body.Bytes(), &grant) != nil || len(session.Result().Cookies()) != 1 {
		t.Fatal("session", session.Code, session.Body.String())
	}
	w := call("/api/v1/media/crypto/key", gin.H{"session_id": grant.SessionID, "file_path": name}, session.Result().Cookies()[0])
	var response map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response["key_envelope"] == nil || string(response["source_error"]) != `"native_source_unavailable"` || response["source_url"] != nil || response["download_url"] != nil {
		t.Fatalf("source was invented or envelope missing: %d %s", w.Code, w.Body.String())
	}
	after, err := routing.NativeTransport(ctx, identity.ID)
	if err != nil || after.ConfiguredTransport != "Direct" || after.Revision != policy.Revision {
		t.Fatal("authorization changed policy", after, err)
	}
}
