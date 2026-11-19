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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type masterDirectHTTPRouting struct {
	selectedIngressRepository
	policy store.NativeTransportPolicy
}

type masterDirectRecorder struct{ *httptest.ResponseRecorder }

// This fixture pauses an already admitted response at its first body write so
// tests can distinguish revoking a session from rejecting a new request.
type pausedMasterDirectWriter struct {
	masterDirectRecorder
	started chan struct{}
	resume  <-chan struct{}
	once    sync.Once
}

func (w *pausedMasterDirectWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.started)
		<-w.resume
	})
	return w.masterDirectRecorder.Write(p)
}

type masterHTTPPolicyLease struct{}

func (masterHTTPPolicyLease) Commit() error { return nil }
func (masterHTTPPolicyLease) Release()      {}
func (r *masterDirectHTTPRouting) AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	return r.selected, masterHTTPPolicyLease{}, nil
}

func prepareMasterHTTPPolicy(t *testing.T, control *node.Service) {
	t.Helper()
	if err := control.ConfigureMasterResourceReadiness("https://resource.test", func(context.Context, store.PublicIngress, string, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := control.PrepareMasterResourcePolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (w masterDirectRecorder) SetWriteDeadline(time.Time) error { return nil }

func (r *masterDirectHTTPRouting) NativeTransport(context.Context, string) (store.NativeTransportPolicy, error) {
	return r.policy, nil
}

func TestMasterDirectRuntimeRequiresExplicitValidatedOrigin(t *testing.T) {
	router, _, _, public := publicFixture(t, false)
	settings := public.settings
	settings.TLSEnabled = true
	if err := public.ConfigureMasterDirect(router, settings, public.control); err != nil || public.masterDirect != nil {
		t.Fatal("default resource reader was enabled", err)
	}
	settings.MasterResourceOrigin = "http://resource.test"
	if err := public.ConfigureMasterDirect(router, settings, public.control); err == nil {
		t.Fatal("insecure resource origin accepted")
	}
	settings.MasterResourceOrigin = "https://resource.test"
	if err := public.ConfigureMasterDirect(router, settings, public.control); err != nil || public.masterDirect == nil {
		t.Fatal("explicit origin was not mounted", err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://resource.test/api/v1/media/master-direct/"+strings.Repeat("a", 64), nil)
	r.Header.Set("Origin", "https://entry.test")
	w := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{w}, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned resource request: %d", w.Code)
	}
}

func TestMasterDirectHTTPRangeCorsAndBoundedDrain(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	masterRouter, db, dir, public, original := clusterFixture(t, "https://master.test", transport, false)
	plain := []byte("private encrypted payload")
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
	identity, err := original.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Pool().Resources(ctx, name, true)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	row := rows[0]
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
	if err != nil || reader == nil {
		t.Fatal(reader, err)
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
	object, err := public.media.CryptoObject(admitted, row.Path, row.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = reader.Issue(admitted, object, "browser:wrong", session.SessionID); err == nil {
		t.Fatal("wrong browser binding issued a grant")
	}
	source, headers, err := reader.Issue(admitted, object, binding, session.SessionID)
	if err != nil || strings.Contains(source, "?") || headers["X-Media-Capability"] == "" {
		t.Fatal("grant", source, err)
	}
	claim, err := control.VerifyMasterDirectCapability(ctx, headers["X-Media-Capability"], "https://resource.test", row.ID)
	if err != nil || claim.SessionID != session.SessionID || claim.ExpiresAt > session.ExpiresAt {
		t.Fatal("grant exceeds browser session", claim, err)
	}
	tokenParts := strings.Split(headers["X-Media-Capability"], ".")
	payload, err := protocol.Decode(tokenParts[0])
	if err != nil || bytes.Contains(payload, []byte(binding)) {
		t.Fatal("browser binding leaked in capability")
	}
	request := func(method, target, origin string, signed bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Origin", origin)
		if signed {
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
	if w := request(http.MethodOptions, source, ingress.PublicOrigin, false); w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != ingress.PublicOrigin {
		t.Fatal("preflight", w.Code, w.Header())
	}
	if w := request(http.MethodOptions, source, "https://other.test", false); w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unissued origin preflight", w.Code)
	}
	badPreflight := httptest.NewRequest(http.MethodOptions, source, nil)
	badPreflight.TLS = &tls.ConnectionState{}
	badPreflight.Header.Set("Origin", ingress.PublicOrigin)
	badPreflight.Header.Set("Access-Control-Request-Method", "GET")
	badPreflight.Header.Set("Access-Control-Request-Headers", "x-media-capability, authorization")
	badResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{badResponse}, badPreflight)
	if badResponse.Code != http.StatusForbidden || badResponse.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unreviewed preflight headers allowed", badResponse.Code)
	}
	spoofed := httptest.NewRequest(http.MethodGet, source, nil)
	spoofed.TLS = nil
	spoofed.RemoteAddr = "172.18.0.3:1234"
	spoofed.Header.Set("X-Real-IP", "192.0.2.1")
	spoofed.Header.Set("X-Forwarded-Proto", "https")
	spoofed.Header.Set("Origin", ingress.PublicOrigin)
	spoofed.Header.Set("X-Media-Capability", headers["X-Media-Capability"])
	spoofedResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{spoofedResponse}, spoofed)
	if spoofedResponse.Code != http.StatusForbidden {
		t.Fatal("unconfigured proxy asserted HTTPS", spoofedResponse.Code)
	}
	w := request(http.MethodGet, source, ingress.PublicOrigin, true)
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), ciphertext[1:4]) || w.Header().Get("Content-Type") != "application/octet-stream" || w.Header().Get("Access-Control-Allow-Origin") != ingress.PublicOrigin || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("encrypted range", w.Code, w.Header(), w.Body.Bytes())
	}
	if w := request(http.MethodGet, source+"?token=secret", ingress.PublicOrigin, true); w.Code != http.StatusForbidden {
		t.Fatal("query capability accepted", w.Code)
	}
	if w := request(http.MethodGet, source, "https://other.test", true); w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("wrong origin", w.Code)
	}
	if w := request(http.MethodGet, source, ingress.PublicOrigin, false); w.Code != http.StatusUnauthorized {
		t.Fatal("missing capability", w.Code)
	}
	// Exercise the actual HTTP server's write-deadline support rather than only
	// a ResponseRecorder; the target Host remains controlled configuration.
	server := httptest.NewTLSServer(router)
	defer server.Close()
	real, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/media/master-direct/"+row.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	real.Host = "resource.test"
	real.Header.Set("Origin", ingress.PublicOrigin)
	real.Header.Set("X-Media-Capability", headers["X-Media-Capability"])
	real.Header.Set("Range", "bytes=1-3")
	response, err := server.Client().Do(real)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusPartialContent {
		t.Fatal("real TLS range", response.StatusCode)
	}
	// Exercise the real public key-response planner as well as the reader. The
	// fixture substitutes only the not-yet-available applied policy/selection.
	public.masterDirect = reader
	call := func(route string, value any, cookie *http.Cookie) *httptest.ResponseRecorder {
		body, _ := json.Marshal(value)
		requestContext, requestAdmission := network.WithPublicAdmission(verified)
		defer requestAdmission.Abort()
		r := httptest.NewRequest(http.MethodPost, ingress.PublicOrigin+route, bytes.NewReader(body)).WithContext(requestContext)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", ingress.PublicOrigin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		masterRouter.ServeHTTP(w, r)
		if w.Code == http.StatusOK && !requestAdmission.Commit() {
			t.Fatal("public admission failed")
		}
		return w
	}
	httpSession := call("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, nil)
	var browserSession mediacrypto.SessionGrant
	if httpSession.Code != http.StatusOK || json.Unmarshal(httpSession.Body.Bytes(), &browserSession) != nil || len(httpSession.Result().Cookies()) != 1 {
		t.Fatal("public session", httpSession.Code)
	}
	cookie := httpSession.Result().Cookies()[0]
	keyResponse := call("/api/v1/media/crypto/key", gin.H{"session_id": browserSession.SessionID, "file_path": row.Path, "resource_id": row.ID}, cookie)
	var issued struct {
		SourceURL       string            `json:"source_url"`
		SourceOrigin    string            `json:"source_origin"`
		SourceTransport string            `json:"source_transport"`
		SourceHeaders   map[string]string `json:"source_headers"`
		SourceExpiresAt int64             `json:"source_expires_at"`
		SourceExpiresIn int64             `json:"source_expires_in"`
	}
	if keyResponse.Code != http.StatusOK || json.Unmarshal(keyResponse.Body.Bytes(), &issued) != nil || issued.SourceURL != source || issued.SourceOrigin != "https://resource.test" || issued.SourceTransport != "Direct" || issued.SourceHeaders["X-Media-Capability"] == "" || strings.Contains(issued.SourceURL, "?") {
		t.Fatalf("key response did not select explicit Direct: %d %s", keyResponse.Code, keyResponse.Body.String())
	}
	issuedClaim, err := control.VerifyMasterDirectCapability(ctx, issued.SourceHeaders["X-Media-Capability"], "https://resource.test", row.ID)
	if err != nil || issued.SourceExpiresAt > issuedClaim.ExpiresAt || issued.SourceExpiresIn < 1 || issued.SourceExpiresIn > 300 {
		t.Fatalf("Direct client deadline exceeded grant: client=%d grant=%d ttl=%d err=%v", issued.SourceExpiresAt, issuedClaim.ExpiresAt, issued.SourceExpiresIn, err)
	}
	httpRead := httptest.NewRequest(http.MethodGet, issued.SourceURL, nil)
	httpRead.Header.Set("Origin", ingress.PublicOrigin)
	httpRead.Header.Set("X-Media-Capability", issued.SourceHeaders["X-Media-Capability"])
	httpRead.Header.Set("Range", "bytes=1-3")
	httpReadResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{httpReadResponse}, httpRead)
	if httpReadResponse.Code != http.StatusPartialContent || !bytes.Equal(httpReadResponse.Body.Bytes(), ciphertext[1:4]) {
		t.Fatal("planned Direct read", httpReadResponse.Code)
	}
	if revoke := call("/api/v1/media/crypto/revoke", gin.H{}, cookie); revoke.Code != http.StatusOK {
		t.Fatal("revoke", revoke.Code)
	}
	afterRevoke := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{afterRevoke}, httpRead)
	if afterRevoke.Code != http.StatusForbidden || afterRevoke.Header().Get("Access-Control-Allow-Origin") != ingress.PublicOrigin {
		t.Fatal("revoked session retained Direct grant", afterRevoke.Code)
	}
	relayReader, err := RegisterMasterRelay(router, public.media, control, public.crypto)
	if err != nil {
		t.Fatal(err)
	}
	public.masterRelay = relayReader
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Relay", "Relay"
	if err := control.PrepareMasterResourcePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	relaySession := call("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, nil)
	var relayBrowserSession mediacrypto.SessionGrant
	if relaySession.Code != http.StatusOK || json.Unmarshal(relaySession.Body.Bytes(), &relayBrowserSession) != nil || len(relaySession.Result().Cookies()) != 1 {
		t.Fatal("relay session", relaySession.Code)
	}
	relayKey := call("/api/v1/media/crypto/key", gin.H{"session_id": relayBrowserSession.SessionID, "file_path": row.Path, "resource_id": row.ID}, relaySession.Result().Cookies()[0])
	var relayIssued struct {
		SourceURL       string            `json:"source_url"`
		SourceTransport string            `json:"source_transport"`
		SourceHeaders   map[string]string `json:"source_headers"`
		SourceExpiresAt int64             `json:"source_expires_at"`
		SourceExpiresIn int64             `json:"source_expires_in"`
	}
	if relayKey.Code != http.StatusOK || json.Unmarshal(relayKey.Body.Bytes(), &relayIssued) != nil || relayIssued.SourceURL != ingress.PublicOrigin+"/api/v1/media/master-relay/"+row.ID || relayIssued.SourceTransport != "Relay" || relayIssued.SourceHeaders["X-Media-Relay"] == "" || strings.Contains(relayIssued.SourceURL, "?") {
		t.Fatalf("key response did not select explicit Relay: %d", relayKey.Code)
	}
	relayClaim, err := control.VerifyMasterRelayCapability(verified, relayIssued.SourceHeaders["X-Media-Relay"], row.ID)
	if err != nil || relayIssued.SourceExpiresAt > relayClaim.ExpiresAt || relayIssued.SourceExpiresIn < 1 || relayIssued.SourceExpiresIn > 300 {
		t.Fatal("Relay client deadline exceeded grant", err)
	}
	relayRead := httptest.NewRequest(http.MethodGet, relayIssued.SourceURL, nil).WithContext(verified)
	relayRead.Header.Set("Origin", ingress.PublicOrigin)
	relayRead.Header.Set("X-Media-Relay", relayIssued.SourceHeaders["X-Media-Relay"])
	relayRead.Header.Set("Range", "bytes=1-3")
	relayResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{relayResponse}, relayRead)
	if relayResponse.Code != http.StatusPartialContent || !bytes.Equal(relayResponse.Body.Bytes(), ciphertext[1:4]) {
		t.Fatal("planned Relay read", relayResponse.Code)
	}
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Direct", "Direct"
	// Switching selection/policy cannot issue another Direct grant. The old
	// signed grant and its bounded preflight origin can drain until expiry.
	routing.selected.Generation++
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Relay", "Relay"
	if _, _, err = reader.Issue(admitted, object, binding, session.SessionID); err == nil {
		t.Fatal("stale grant issuance")
	}
	if w := request(http.MethodGet, source, ingress.PublicOrigin, true); w.Code != http.StatusPartialContent {
		t.Fatal("issued grant could not drain", w.Code)
	}
	// Simulate an out-of-band stale revision to verify the old grant cannot
	// read a replacement or a changed encryption descriptor of equal size.
	if _, err := db.Database().Exec("UPDATE global_media_objects SET etag=? WHERE media_id=?", "replacement", row.ID); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodGet, source, ingress.PublicOrigin, true); w.Code != http.StatusForbidden {
		t.Fatal("changed revision remained readable", w.Code)
	}
	if _, err := db.Database().Exec("UPDATE global_media_objects SET etag=? WHERE media_id=?", row.ETag, row.ID); err != nil {
		t.Fatal(err)
	}
	var originalDescriptor string
	if err := db.Database().QueryRow("SELECT descriptor_json FROM media_encryption WHERE object_kind='media' AND object_id=?", row.ID).Scan(&originalDescriptor); err != nil {
		t.Fatal(err)
	}
	changed := meta
	changed.FileID = strings.Repeat("f", 32)
	if changed.FileID == meta.FileID {
		changed.FileID = strings.Repeat("e", 32)
	}
	encoded, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().Exec("UPDATE media_encryption SET descriptor_json=? WHERE object_kind='media' AND object_id=?", string(encoded), row.ID); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodGet, source, ingress.PublicOrigin, true); w.Code != http.StatusForbidden {
		t.Fatal("changed encryption descriptor remained readable", w.Code)
	}
	if _, err = db.Database().Exec("UPDATE media_encryption SET descriptor_json=? WHERE object_kind='media' AND object_id=?", originalDescriptor, row.ID); err != nil {
		t.Fatal(err)
	}
	if err := public.media.Hide(ctx, []string{name}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodGet, source, ingress.PublicOrigin, true); w.Code != http.StatusForbidden {
		t.Fatal("hidden resource readable", w.Code)
	}
	if err := public.media.Hide(ctx, []string{name}, false, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodGet, source, ingress.PublicOrigin, true); w.Code != http.StatusPartialContent {
		t.Fatal("unhidden resource unreadable", w.Code)
	}
	// Characterize the current boundary: revocation denies the next request
	// but does not reauthorize or interrupt a response already admitted. The
	// production handler's absolute write deadline bounds that drain. A future
	// renewable-stream implementation must replace this assertion together
	// with a tested, bounded revocation mechanism.
	started, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	resumeStream := func() { resumeOnce.Do(func() { close(resume) }) }
	defer resumeStream()
	paused := &pausedMasterDirectWriter{masterDirectRecorder: masterDirectRecorder{httptest.NewRecorder()}, started: started, resume: resume}
	streamRequest := httptest.NewRequest(http.MethodGet, source, nil)
	streamRequest.TLS = &tls.ConnectionState{}
	streamRequest.Header.Set("Origin", ingress.PublicOrigin)
	streamRequest.Header.Set("X-Media-Capability", headers["X-Media-Capability"])
	streamRequest.Header.Set("Range", "bytes=1-3")
	go func() {
		defer close(done)
		router.ServeHTTP(paused, streamRequest)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("admitted stream did not reach its first body write")
	}
	public.crypto.RevokeBinding(binding)
	if w := request(http.MethodGet, source, ingress.PublicOrigin, true); w.Code != http.StatusForbidden {
		t.Fatal("revoked browser session remained readable", w.Code)
	}
	resumeStream()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("admitted stream did not finish after revocation")
	}
	if paused.Code != http.StatusPartialContent || !bytes.Equal(paused.Body.Bytes(), ciphertext[1:4]) {
		t.Fatal("current admitted-stream drain changed", paused.Code, paused.Body.Bytes())
	}
}
