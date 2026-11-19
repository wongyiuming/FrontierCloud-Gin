package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// The control and owner handlers are real; TLS framing and redirect rejection
// for the production owner transport have their own private-CA tests.
type followerRelayFixtureTransport struct{ *clusterHTTP }

func (t *clusterHTTP) ProbeNativePlainMedia(ctx context.Context, origin, relationship, credential, challenge, token string) (map[string]any, error) {
	router := t.routers[origin]
	if router == nil {
		return nil, errors.New("unavailable")
	}
	headers, err := protocol.AuthHeaders(credential, relationship, http.MethodGet, node.NativePlainMediaProbePath, nil, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	request := httptest.NewRequest(http.MethodGet, origin+node.NativePlainMediaProbePath, nil).WithContext(ctx)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	request.Header.Set("X-Fc-Plain-Probe", challenge)
	request.Header.Set("X-Media-Capability", token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		return nil, errors.New("plain media probe failed")
	}
	var result map[string]any
	if err := controlJSON(response.Body.Bytes(), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (t followerRelayFixtureTransport) ProbeNativeMediaEndpoint(ctx context.Context, origin string) error {
	router := t.routers[origin]
	if router == nil {
		return errors.New("unavailable")
	}
	request := httptest.NewRequest(http.MethodGet, origin+"/internal/v1/media/"+strings.Repeat("0", 64), nil).WithContext(ctx)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		return errors.New("invalid owner endpoint")
	}
	return nil
}

func (t followerRelayFixtureTransport) MediaRelayRead(ctx context.Context, origin, object, token, method, byteRange string, size int64) (node.FollowerRelayResponse, error) {
	router := t.routers[origin]
	if router == nil {
		return node.FollowerRelayResponse{}, errors.New("unavailable")
	}
	r := httptest.NewRequest(method, origin+"/internal/v1/media/"+object, nil).WithContext(ctx)
	r.Header.Set("X-Media-Capability", token)
	if byteRange != "" {
		r.Header.Set("Range", byteRange)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	response := w.Result()
	if response.StatusCode != http.StatusPartialContent {
		response.Body.Close()
		return node.FollowerRelayResponse{}, errors.New("owner rejected")
	}
	return node.FollowerRelayResponse{Body: response.Body, Status: response.StatusCode, Length: response.ContentLength, ContentRange: response.Header.Get("Content-Range")}, nil
}

// Exercises actual paired placement, metadata and visibility checks. The
// authenticated ingress and applied policy are injected; this is not a claim
// that non-Master ingress selection or the data stream is implemented.
func TestFollowerRelaySourcePreservesOwnerAndVisibility(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	masterRouter, db, dir, public, master := clusterFixture(t, "https://master.test", transport, false)
	followerRouter, _, _, followerPublic, follower := clusterFixture(t, "https://follower.test", transport, true)
	if _, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := follower.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := follower.ConfigureFollowerResourceOrigin("https://resource.test"); err != nil {
		t.Fatal(err)
	}
	transport.routers["https://resource.test"] = followerRouter
	pair, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := db.Nodes().Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 5*store.GiB
	if err = db.Pool().ConfigureMember(ctx, relation.PeerID, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = master.Tick(ctx, relation); err != nil {
		t.Fatal(err)
	}
	if err = db.Nodes().SetRelationshipMode(ctx, id, "Direct", false, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(10)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{'x'}, int(meta.CiphertextSize))
	ticket, err := public.media.ReserveMasterEncryptedUpload(ctx, "relay.mp3", "music/Relay", "", "direct", int64(len(payload)), 255, store.AdminAudit{}, &meta)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := db.Pool().Upload(ctx, ticket.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = master.UploadStorage(ctx, reservation, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err = public.media.FinalizeMasterUpload(ctx, ticket.ID, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	plainPayload := []byte("ID3plainv1")
	plainTicket, err := public.media.ReserveMasterEncryptedUpload(ctx, "direct-plain.mp3", "music/Relay", "", "direct", int64(len(plainPayload)), 255, store.AdminAudit{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plainReservation, err := db.Pool().Upload(ctx, plainTicket.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = master.UploadStorage(ctx, plainReservation, bytes.NewReader(plainPayload)); err != nil {
		t.Fatal(err)
	}
	if _, err = public.media.FinalizeMasterUpload(ctx, plainTicket.ID, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 5}
	routing := &masterDirectHTTPRouting{selectedIngressRepository: selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: ingress}, policy: store.NativeTransportPolicy{MemberID: relation.PeerID, ConfiguredTransport: "Relay", AppliedTransport: "Relay", State: "applied", Revision: 2}}
	localIdentity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	control := node.NewService(routing, localIdentity, followerRelayFixtureTransport{transport})
	control.ConfigureNativeTransportReadiness(func(context.Context, store.Relationship, string) error { return nil })
	public.media.ConfigureCluster(routing, db.Pool(), control)
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
	admitted, err = public.crypto.WithDirectSession(admitted, binding, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	object, err := public.media.CryptoObject(admitted, "", ticket.MediaID, false)
	if err != nil {
		t.Fatal(err)
	}
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport, routing.policy.AppliedOrigin = "Direct", "Direct", "https://resource.test"
	if err := control.VerifyNativeTransportReadiness(ctx, relation, "Direct"); err != nil {
		t.Fatal("real v4 Direct readiness", err)
	}
	directSource, directOrigin, directToken, err := public.media.FollowerDirectSource(admitted, object, session.ExpiresAt)
	if err != nil || directOrigin != "https://resource.test" || !strings.HasPrefix(directSource, directOrigin+"/internal/v1/media/") || directToken == "" || strings.Contains(directSource, "?") {
		t.Fatal("Direct grant", directSource, err)
	}
	directRequest := httptest.NewRequest(http.MethodGet, directSource, nil)
	directRequest.Header.Set("Origin", ingress.PublicOrigin)
	directRequest.Header.Set("X-Media-Capability", directToken)
	directRequest.Header.Set("Range", "bytes=1-3")
	directResponse := httptest.NewRecorder()
	followerRouter.ServeHTTP(directResponse, directRequest)
	if directResponse.Code != http.StatusPartialContent || !bytes.Equal(directResponse.Body.Bytes(), payload[1:4]) {
		t.Fatal("owner Direct range", directResponse.Code, directResponse.Body.String())
	}
	wrongOrigin := httptest.NewRequest(http.MethodGet, directSource, nil)
	wrongOrigin.Header.Set("Origin", "https://other.test")
	wrongOrigin.Header.Set("X-Media-Capability", directToken)
	wrongResponse := httptest.NewRecorder()
	followerRouter.ServeHTTP(wrongResponse, wrongOrigin)
	if wrongResponse.Code != http.StatusForbidden {
		t.Fatal("Direct grant accepted for another origin", wrongResponse.Code)
	}
	control.ConfigureNativeTransportReadiness(nil)
	if _, _, _, err := public.media.FollowerDirectSource(admitted, object, session.ExpiresAt); err == nil {
		t.Fatal("Direct issued without runtime readiness")
	}
	control.ConfigureNativeTransportReadiness(func(context.Context, store.Relationship, string) error { return nil })
	routing.policy.AppliedOrigin = "https://wrong.test"
	if _, _, _, err := public.media.FollowerDirectSource(admitted, object, session.ExpiresAt); err == nil {
		t.Fatal("unverified Direct origin issued")
	}
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport, routing.policy.AppliedOrigin = "Relay", "Relay", ""
	if _, _, _, err := public.media.FollowerDirectSource(admitted, object, session.ExpiresAt); err == nil {
		t.Fatal("Direct issued after policy changed to Relay")
	}
	directResponse = httptest.NewRecorder()
	followerRouter.ServeHTTP(directResponse, directRequest)
	if directResponse.Code != http.StatusPartialContent {
		t.Fatal("issued Direct grant could not drain", directResponse.Code)
	}
	source, token, err := public.media.FollowerRelaySource(admitted, object)
	if err != nil || source != ingress.PublicOrigin+"/api/v1/media/follower-relay/"+ticket.MediaID || token == "" || strings.Contains(source, "?") {
		t.Fatal("grant", source, err)
	}
	row, claim, err := public.media.FollowerRelayObject(verified, token, ticket.MediaID)
	if err != nil || row.MemberID != relation.PeerID || row.ObjectID != ticket.MediaID || claim.OwnerID != row.MemberID {
		t.Fatal("owner changed", row, claim, err)
	}
	if _, _, err := follower.VerifyOwnedMedia(ctx, token, row.ObjectID); err == nil {
		t.Fatal("browser Relay grant was accepted as a direct owner capability")
	}
	ownerToken, err := control.FollowerRelayOwnerCapability(verified, token, row.ID, row.Bytes, object.Encryption, public.crypto)
	if err != nil {
		t.Fatal("owner grant", err)
	}
	_, ownerClaims, err := follower.VerifyOwnedMedia(ctx, ownerToken, row.ObjectID)
	if err != nil || ownerClaims["session"] != session.SessionID || ownerClaims["descriptor"] != claim.Descriptor {
		t.Fatal("owner grant binding", ownerClaims, err)
	}
	if _, err = control.FollowerRelayOwnerCapability(verified, token, row.ID, row.Bytes+1, object.Encryption, public.crypto); err == nil {
		t.Fatal("changed descriptor accepted")
	}
	readerRouter := gin.New()
	reader, err := registerFollowerRelay(readerRouter, public.media, control, public.crypto)
	if err != nil {
		t.Fatal(err)
	}
	public.followerRelay = reader
	read := func(capability string, auth context.Context) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, source, nil).WithContext(auth)
		r.Header.Set("X-Media-Relay", capability)
		r.Header.Set("Range", "bytes=1-3")
		w := httptest.NewRecorder()
		readerRouter.ServeHTTP(masterDirectRecorder{w}, r)
		return w
	}
	w := read(token, verified)
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), payload[1:4]) || w.Header().Get("Content-Range") != "bytes 1-3/"+strconv.Itoa(len(payload)) {
		t.Fatal("relay range failed", w.Code, w.Header(), w.Body.String())
	}
	if strings.Contains(w.Body.String(), ownerToken) || strings.Contains(w.Header().Get("Location"), ownerToken) || w.Header().Get("X-Media-Capability") != "" {
		t.Fatal("owner grant escaped")
	}
	if w = read(token, ctx); w.Code != http.StatusForbidden {
		t.Fatal("unauthenticated ingress accepted", w.Code)
	}
	if w = read(token+"x", verified); w.Code != http.StatusForbidden {
		t.Fatal("forged relay bearer accepted", w.Code)
	}
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
		t.Fatal("session", httpSession.Code)
	}
	key := call("/api/v1/media/crypto/key", gin.H{"session_id": browserSession.SessionID, "file_path": row.Path, "resource_id": row.ID}, httpSession.Result().Cookies()[0])
	var issued struct {
		SourceURL       string            `json:"source_url"`
		SourceTransport string            `json:"source_transport"`
		SourceHeaders   map[string]string `json:"source_headers"`
		SourceExpiresAt int64             `json:"source_expires_at"`
		SourceExpiresIn int64             `json:"source_expires_in"`
	}
	if key.Code != http.StatusOK || json.Unmarshal(key.Body.Bytes(), &issued) != nil || issued.SourceURL != source || issued.SourceTransport != "Relay" || issued.SourceHeaders["X-Media-Relay"] == "" || strings.Contains(issued.SourceURL, "?") {
		t.Fatal("key route", key.Code, key.Body.String())
	}
	issuedClaim, err := control.VerifyFollowerRelayCapability(verified, issued.SourceHeaders["X-Media-Relay"], row.ID)
	if err != nil || issued.SourceExpiresAt > issuedClaim.ExpiresAt || issued.SourceExpiresIn < 1 || issued.SourceExpiresIn > 300 {
		t.Fatal("key deadline", issued, err)
	}
	if w = read(issued.SourceHeaders["X-Media-Relay"], verified); w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), payload[1:4]) {
		t.Fatal("key-to-range", w.Code)
	}
	// Real TLS peer proxy, signed ingress proof and the real Master/owner HTTP
	// handlers. The paired owner socket remains an in-process fixture; the
	// production owner's TLS and redirect behavior has separate private-CA tests.
	var wrapped atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wrapped.Load().(http.Handler).ServeHTTP(w, r) }))
	defer server.Close()
	current := &relayFixtureCurrent{value: ingress}
	verifier, err := publicproxy.NewVerifier(publicproxy.VerifierConfig{MasterOrigin: server.URL, Authenticator: &relayFixtureAuth{peer: ingress.NodeID, nonces: map[string]bool{}}, Current: current})
	if err != nil {
		t.Fatal(err)
	}
	wrapped.Store(verifier.Wrap(readerRouter))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	peer, err := publicproxy.New(publicproxy.Config{MasterOrigin: server.URL, PublicOrigin: ingress.PublicOrigin, RootCAs: roots, Peer: &publicproxy.PeerConfig{NodeID: ingress.NodeID, Generation: ingress.Generation, Signer: relayFixtureSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.CloseIdleConnections()
	peerRead := func(target, bearer string) *httptest.ResponseRecorder {
		u, e := url.Parse(target)
		if e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest(http.MethodGet, u.RequestURI(), nil)
		r.Host, r.TLS, r.RemoteAddr = u.Host, &tls.ConnectionState{}, "192.0.2.1:1234"
		r.Header.Set("X-Media-Relay", bearer)
		r.Header.Set("Range", "bytes=1-3")
		w := httptest.NewRecorder()
		peer.ServeHTTP(masterDirectRecorder{w}, r)
		return w
	}
	if w = peerRead(issued.SourceURL, issued.SourceHeaders["X-Media-Relay"]); w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), payload[1:4]) {
		t.Fatal("peer relay range", w.Code, w.Body.String())
	}
	peerURL, err := url.Parse(issued.SourceURL)
	if err != nil {
		t.Fatal(err)
	}
	headRequest := httptest.NewRequest(http.MethodHead, peerURL.RequestURI(), nil)
	headRequest.Host, headRequest.TLS, headRequest.RemoteAddr = peerURL.Host, &tls.ConnectionState{}, "192.0.2.1:1234"
	headRequest.Header.Set("X-Media-Relay", issued.SourceHeaders["X-Media-Relay"])
	headRequest.Header.Set("Range", "bytes=1-3")
	headResponse := httptest.NewRecorder()
	peer.ServeHTTP(masterDirectRecorder{headResponse}, headRequest)
	if headResponse.Code != http.StatusPartialContent || headResponse.Body.Len() != 0 || headResponse.Header().Get("Content-Length") != "3" {
		t.Fatal("peer relay HEAD", headResponse.Code, headResponse.Header())
	}
	if w = peerRead(ingress.PublicOrigin+"/api/v1/media/follower-relay/"+strings.Repeat("f", 64), issued.SourceHeaders["X-Media-Relay"]); w.Code != http.StatusForbidden {
		t.Fatal("forged resource accepted", w.Code)
	}
	masterIdentity, err := master.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().Exec("UPDATE global_media_objects SET storage_member_id=? WHERE media_id=?", masterIdentity.ID, row.ID); err != nil {
		t.Fatal(err)
	}
	if w = peerRead(issued.SourceURL, issued.SourceHeaders["X-Media-Relay"]); w.Code != http.StatusForbidden {
		t.Fatal("changed owner accepted", w.Code)
	}
	if _, err = db.Database().Exec("UPDATE global_media_objects SET storage_member_id=? WHERE media_id=?", row.MemberID, row.ID); err != nil {
		t.Fatal(err)
	}
	current.set(store.PublicIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.PublicOrigin, Generation: ingress.Generation + 1})
	if w = peerRead(issued.SourceURL, issued.SourceHeaders["X-Media-Relay"]); w.Code != http.StatusForbidden {
		t.Fatal("stale ingress accepted", w.Code)
	}
	current.set(ingress)
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Direct", "Direct"
	directKey := call("/api/v1/media/crypto/key", gin.H{"session_id": browserSession.SessionID, "file_path": row.Path, "resource_id": row.ID}, httpSession.Result().Cookies()[0])
	if directKey.Code != http.StatusOK || !strings.Contains(directKey.Body.String(), `"source_error":"native_source_unavailable"`) || strings.Contains(directKey.Body.String(), "follower-relay") {
		t.Fatal("Direct silently fell back to Relay", directKey.Code)
	}
	routing.policy.AppliedOrigin = "https://resource.test"
	directKey = call("/api/v1/media/crypto/key", gin.H{"session_id": browserSession.SessionID, "file_path": row.Path, "resource_id": row.ID}, httpSession.Result().Cookies()[0])
	var directIssued struct {
		SourceURL       string            `json:"source_url"`
		SourceOrigin    string            `json:"source_origin"`
		SourceTransport string            `json:"source_transport"`
		SourceHeaders   map[string]string `json:"source_headers"`
	}
	if directKey.Code != http.StatusOK || json.Unmarshal(directKey.Body.Bytes(), &directIssued) != nil || directIssued.SourceURL != directSource || directIssued.SourceOrigin != directOrigin || directIssued.SourceTransport != "Direct" || directIssued.SourceHeaders["X-Media-Capability"] == "" {
		t.Fatal("Direct key plan invalid", directKey.Code)
	}
	directRequest = httptest.NewRequest(http.MethodGet, directIssued.SourceURL, nil)
	directRequest.Header.Set("Origin", ingress.PublicOrigin)
	directRequest.Header.Set("X-Media-Capability", directIssued.SourceHeaders["X-Media-Capability"])
	directRequest.Header.Set("Range", "bytes=1-3")
	directResponse = httptest.NewRecorder()
	followerRouter.ServeHTTP(directResponse, directRequest)
	if directResponse.Code != http.StatusPartialContent || !bytes.Equal(directResponse.Body.Bytes(), payload[1:4]) {
		t.Fatal("Direct key-to-range", directResponse.Code)
	}
	plainPlan := call("/api/v1/media/crypto/native/source", gin.H{"session_id": browserSession.SessionID, "file_path": plainTicket.Path, "resource_id": plainTicket.MediaID, "object_id": plainTicket.MediaID}, httpSession.Result().Cookies()[0])
	var plainGrant struct {
		SourceURL       string            `json:"source_url"`
		SourceOrigin    string            `json:"source_origin"`
		SourceTransport string            `json:"source_transport"`
		SourceHeaders   map[string]string `json:"source_headers"`
	}
	if plainPlan.Code != http.StatusOK || json.Unmarshal(plainPlan.Body.Bytes(), &plainGrant) != nil || plainGrant.SourceTransport != "Direct" || plainGrant.SourceOrigin != "https://resource.test" || plainGrant.SourceHeaders["X-Media-Capability"] == "" {
		t.Fatal("plaintext Direct plan", plainPlan.Code, plainPlan.Body.String())
	}
	plainRequest := httptest.NewRequest(http.MethodGet, plainGrant.SourceURL, nil)
	plainRequest.Header.Set("Origin", ingress.PublicOrigin)
	plainRequest.Header.Set("X-Media-Capability", plainGrant.SourceHeaders["X-Media-Capability"])
	plainRequest.Header.Set("Range", "bytes=1-3")
	plainRead := httptest.NewRecorder()
	followerRouter.ServeHTTP(plainRead, plainRequest)
	if plainRead.Code != http.StatusPartialContent || !bytes.Equal(plainRead.Body.Bytes(), plainPayload[1:4]) {
		t.Fatal("plaintext Direct range", plainRead.Code)
	}
	follower.ConfigurePlainReadProbe(nil)
	if err := control.VerifyNativeTransportReadiness(ctx, relation, "Direct"); err == nil {
		t.Fatal("Direct readiness accepted missing v4 proof")
	}
	withoutProof := call("/api/v1/media/crypto/native/source", gin.H{"session_id": browserSession.SessionID, "file_path": plainTicket.Path, "resource_id": plainTicket.MediaID, "object_id": plainTicket.MediaID}, httpSession.Result().Cookies()[0])
	if withoutProof.Code == http.StatusOK {
		t.Fatal("unproven v4 owner issued Direct source")
	}
	follower.ConfigurePlainReadProbe(followerPublic.media.ProbeVerifiedPlain)
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Relay", "Relay"
	plainRelayPlan := call("/api/v1/media/crypto/native/source", gin.H{"session_id": browserSession.SessionID, "file_path": plainTicket.Path, "resource_id": plainTicket.MediaID, "object_id": plainTicket.MediaID}, httpSession.Result().Cookies()[0])
	var plainRelay struct {
		SourceURL       string            `json:"source_url"`
		SourceTransport string            `json:"source_transport"`
		SourceHeaders   map[string]string `json:"source_headers"`
	}
	if plainRelayPlan.Code != http.StatusOK || json.Unmarshal(plainRelayPlan.Body.Bytes(), &plainRelay) != nil || plainRelay.SourceTransport != "Relay" || plainRelay.SourceHeaders["X-Media-Relay"] == "" {
		t.Fatal("plaintext Relay plan", plainRelayPlan.Code, plainRelayPlan.Body.String())
	}
	plainRelayRead := peerRead(plainRelay.SourceURL, plainRelay.SourceHeaders["X-Media-Relay"])
	if plainRelayRead.Code != http.StatusPartialContent || !bytes.Equal(plainRelayRead.Body.Bytes(), plainPayload[1:4]) {
		t.Fatal("plaintext ingress-to-owner Relay range", plainRelayRead.Code)
	}
	if _, err = db.Database().Exec("UPDATE global_media_objects SET etag='weak' WHERE media_id=?", plainTicket.MediaID); err != nil {
		t.Fatal(err)
	}
	weakPlan := call("/api/v1/media/crypto/native/source", gin.H{"session_id": browserSession.SessionID, "file_path": plainTicket.Path, "resource_id": plainTicket.MediaID, "object_id": plainTicket.MediaID}, httpSession.Result().Cookies()[0])
	if weakPlan.Code == http.StatusOK {
		t.Fatal("weak content version issued Relay source")
	}
	if w := peerRead(plainRelay.SourceURL, plainRelay.SourceHeaders["X-Media-Relay"]); w.Code != http.StatusForbidden {
		t.Fatal("changed plaintext revision remained relay-readable", w.Code)
	}
	routing.policy.AppliedOrigin = ""
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Relay", "Relay"
	if err = db.Media().SetHidden(ctx, []string{object.Path}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if w = read(token, verified); w.Code != http.StatusForbidden {
		t.Fatal("hidden object read", w.Code)
	}
	if err = db.Media().SetHidden(ctx, []string{object.Path}, false, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	public.crypto.RevokeBinding(binding)
	if _, err = control.FollowerRelayOwnerCapability(verified, token, row.ID, row.Bytes, object.Encryption, public.crypto); err == nil {
		t.Fatal("revoked session received owner grant")
	}
	if w = read(token, verified); w.Code != http.StatusForbidden {
		t.Fatal("revoked session read", w.Code)
	}
	if err = db.Media().SetHidden(ctx, []string{object.Path}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = public.media.FollowerRelayObject(verified, token, ticket.MediaID); err == nil {
		t.Fatal("hidden object remained readable")
	}
}
