package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestMasterDirectLyricHTTPRequiresLiveSession(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	masterRouter, db, dir, public, original := clusterFixture(t, "https://master.test", transport, false)
	meta, err := mediacrypto.NewMetadata(10)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := bytes.Repeat([]byte{7}, int(meta.CiphertextSize))
	stage, err := public.media.Stage(ctx, bytes.NewReader(ciphertext), int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	lyric, err := public.media.PublishEncrypted(ctx, stage, "direct.lrc", "", "", true, 255, store.AdminAudit{}, &meta)
	stage.Close()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := original.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := public.media.ReplaceLyrics(ctx, "track", "music/artist/song.mp3", []string{lyric}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 5}
	routing := &masterDirectHTTPRouting{selectedIngressRepository: selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: ingress},
		policy: store.NativeTransportPolicy{MemberID: identity.ID, ConfiguredTransport: "Direct", AppliedTransport: "Direct", State: "applied", Revision: 2}}
	localIdentity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	control := node.NewService(routing, localIdentity, transport)
	prepareMasterHTTPPolicy(t, control)
	public.media.ConfigureCluster(routing, db.Pool(), control)
	settings := public.settings
	settings.TLSEnabled = true
	router := gin.New()
	reader, err := RegisterMasterDirect(router, settings, "https://resource.test", public.media, control, public.crypto)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.PublicOrigin, Generation: ingress.Generation, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	admitted, admission := network.WithPublicAdmission(verified)
	defer admission.Abort()
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := "browser:v2:" + strings.Repeat("c", 64)
	session, err := public.crypto.NewSession(binding, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	object, err := public.media.CryptoObject(admitted, lyric, "", false)
	if err != nil {
		t.Fatal(err)
	}
	metadataRouter := gin.New()
	metadataRouter.Use(func(c *gin.Context) { c.Request = c.Request.WithContext(admitted); c.Next() })
	metadataRouter.GET("/api/v1/media/lyrics/content", public.lyricsContent)
	metadataRequest := func(track string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/media/lyrics/content?"+url.Values{"track": {track}}.Encode(), nil)
		w := httptest.NewRecorder()
		metadataRouter.ServeHTTP(w, r)
		return w
	}
	if w := metadataRequest("music/artist/song.mp3"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"encrypted":true`) || strings.Contains(w.Body.String(), "source_url") || strings.Contains(w.Body.String(), "private lyrics") {
		t.Fatal("lyric metadata", w.Code, w.Body.String())
	}
	if w := metadataRequest("music/nested/album/音乐.mp3"); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "暂无歌词") {
		t.Fatal("plain lyric content crossed the business proxy", w.Code, w.Body.String())
	}
	source, headers, err := reader.Issue(admitted, object, binding, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method string, authorized bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, source, nil)
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Origin", ingress.PublicOrigin)
		if authorized {
			r.Header.Set("X-Media-Capability", headers["X-Media-Capability"])
		}
		if method == http.MethodOptions {
			r.Header.Set("Access-Control-Request-Method", "GET")
			r.Header.Set("Access-Control-Request-Headers", "range, x-media-capability")
		} else {
			r.Header.Set("Range", "bytes=1-3")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(masterDirectRecorder{w}, r)
		return w
	}
	if w := request(http.MethodOptions, false); w.Code != http.StatusNoContent {
		t.Fatal("preflight", w.Code)
	}
	if w := request(http.MethodGet, false); w.Code != http.StatusUnauthorized {
		t.Fatal("unsigned read", w.Code)
	}
	if w := request(http.MethodGet, true); w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), ciphertext[1:4]) {
		t.Fatal("range read", w.Code, w.Body.String())
	}
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Relay", "Relay"
	if err := control.PrepareMasterResourcePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	relayRouter := gin.New()
	relayRouter.Use(func(c *gin.Context) { c.Request = c.Request.WithContext(verified); c.Next() })
	relay, err := RegisterMasterRelay(relayRouter, public.media, control, public.crypto)
	if err != nil {
		t.Fatal(err)
	}
	relaySource, relayHeaders, _, err := relay.Issue(admitted, object, binding, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	relayRead := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, relaySource, nil)
		r.Header.Set("X-Media-Relay", relayHeaders["X-Media-Relay"])
		r.Header.Set("Range", "bytes=1-3")
		w := httptest.NewRecorder()
		relayRouter.ServeHTTP(masterDirectRecorder{w}, r)
		return w
	}
	if w := relayRead(); w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), ciphertext[1:4]) {
		t.Fatal("relay range", w.Code, w.Body.String())
	}
	public.masterDirect, public.masterRelay = reader, relay
	call := func(route string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
		encoded, _ := json.Marshal(body)
		requestContext, requestAdmission := network.WithPublicAdmission(verified)
		defer requestAdmission.Abort()
		r := httptest.NewRequest(http.MethodPost, ingress.PublicOrigin+route, bytes.NewReader(encoded)).WithContext(requestContext)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", ingress.PublicOrigin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		masterRouter.ServeHTTP(w, r)
		if w.Code == http.StatusOK && !requestAdmission.Commit() {
			t.Fatal("admission commit")
		}
		return w
	}
	response := call("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, nil)
	var browserSession mediacrypto.SessionGrant
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &browserSession) != nil || len(response.Result().Cookies()) != 1 {
		t.Fatal("browser session", response.Code)
	}
	cookie := response.Result().Cookies()[0]
	for _, mode := range []string{"Direct", "Relay"} {
		routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = mode, mode
		if err := control.PrepareMasterResourcePolicy(ctx); err != nil {
			t.Fatal(err)
		}
		response = call("/api/v1/media/crypto/key", gin.H{"session_id": browserSession.SessionID, "file_path": lyric}, cookie)
		var grant struct {
			SourceURL       string            `json:"source_url"`
			SourceTransport string            `json:"source_transport"`
			SourceHeaders   map[string]string `json:"source_headers"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &grant) != nil || grant.SourceTransport != mode || strings.Contains(grant.SourceURL, "?") {
			t.Fatal("lyric key plan", mode, response.Code, response.Body.String())
		}
		if mode == "Direct" && (grant.SourceURL != source || grant.SourceHeaders["X-Media-Capability"] == "") {
			t.Fatal("lyric Direct plan", grant)
		}
		if mode == "Relay" && (grant.SourceURL != relaySource || grant.SourceHeaders["X-Media-Relay"] == "") {
			t.Fatal("lyric Relay plan", grant)
		}
	}
	public.crypto.RevokeBinding(binding)
	if w := request(http.MethodGet, true); w.Code != http.StatusForbidden {
		t.Fatal("revoked session accepted", w.Code)
	}
	if w := relayRead(); w.Code != http.StatusForbidden {
		t.Fatal("revoked relay session accepted", w.Code)
	}
}
