package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestOpaqueBrowserCipherRangeIsExplicitAndBounded(t *testing.T) {
	for _, tc := range []struct {
		method, value, ifRange string
		want                   bool
	}{
		{http.MethodGet, "bytes=0-1048591", "", true},
		{http.MethodGet, "bytes=10-20", "", true},
		{http.MethodGet, "bytes=0-1048592", "", false},
		{http.MethodGet, "bytes=0-", "", false},
		{http.MethodGet, "bytes=-10", "", false},
		{http.MethodGet, "bytes=1-2,3-4", "", false},
		{http.MethodGet, "bytes=1-2", `"old"`, false},
		{http.MethodHead, "bytes=1-2", "", false},
		{http.MethodGet, "bytes=1-999999999999999999999999", "", false},
	} {
		r := httptest.NewRequest(tc.method, "https://follower.test/", nil)
		r.Header.Set("Range", tc.value)
		if tc.ifRange != "" {
			r.Header.Set("If-Range", tc.ifRange)
		}
		if got := opaqueBrowserCipherRange(r, 2*mediacrypto.ChunkSize); got != tc.want {
			t.Fatalf("%s %s: got %v", tc.method, tc.value, got)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "https://follower.test/", nil)
	r.Header.Add("Range", "bytes=0-1")
	r.Header.Add("Range", "bytes=2-3")
	if opaqueBrowserCipherRange(r, 10) {
		t.Fatal("multiple Range headers admitted")
	}
}

// Synthetic in-process transport for the real Gin owner handler. Production
// TLS pinning and framing are tested independently by node transport tests.
func (t *clusterHTTP) MediaOpaqueRelayRead(ctx context.Context, origin, alias, token, method, byteRange string, size int64) (node.FollowerRelayResponse, error) {
	var empty node.FollowerRelayResponse
	router := t.routers[origin]
	if router == nil {
		return empty, errors.New("offline")
	}
	r := httptest.NewRequest(method, origin+"/internal/v1/opaque-media/"+alias, nil).WithContext(ctx)
	r.Header.Set("X-Media-Capability", token)
	if byteRange != "" {
		r.Header.Set("Range", byteRange)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{w}, r)
	if w.Code != http.StatusOK && w.Code != http.StatusPartialContent {
		return empty, errors.New("opaque owner rejected")
	}
	length, err := strconv.ParseInt(w.Header().Get("Content-Length"), 10, 64)
	if err != nil || length < 0 || length > size || method == http.MethodGet && int64(w.Body.Len()) != length {
		return empty, errors.New("invalid opaque framing")
	}
	return node.FollowerRelayResponse{Body: io.NopCloser(bytes.NewReader(w.Body.Bytes())), Status: w.Code, Length: length, ContentRange: w.Header().Get("Content-Range")}, nil
}

type opaqueDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

type failedOpaqueOwnerFence struct{ checks int }

func (l *failedOpaqueOwnerFence) Check(context.Context) error {
	l.checks++
	if l.checks > 1 {
		return errors.New("synthetic fence failure")
	}
	return nil
}
func (*failedOpaqueOwnerFence) Release() {}

func (w *opaqueDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		w.deadline = deadline
	}
	return nil
}

func (t *clusterHTTP) ProbeNativeOpaqueMedia(ctx context.Context, origin, relationship, credential, challenge, token string) (map[string]any, error) {
	router := t.routers[origin]
	if router == nil {
		return nil, errors.New("offline")
	}
	request := httptest.NewRequest(http.MethodGet, origin+node.NativeOpaqueMediaProbePath, nil).WithContext(ctx)
	headers, err := protocol.AuthHeaders(credential, relationship, http.MethodGet, node.NativeOpaqueMediaProbePath, nil, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	request.Header.Set("X-Fc-Opaque-Probe", challenge)
	request.Header.Set("X-Media-Capability", token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	if w.Code != http.StatusOK {
		return nil, errors.New("opaque probe failed")
	}
	var value map[string]any
	if err := controlJSON(w.Body.Bytes(), &value); err != nil {
		return nil, err
	}
	return value, nil
}

// This isolated fixture explicitly mounts the new route and supplies synthetic
// prerequisite authority. Product startup still does neither.
func TestOpaqueNodeMediaAuthenticatedRangeAndReplacement(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, db, _, public, master := clusterFixture(t, "https://master.test", transport, false)
	router, _, dir, ownerPublic, owner := clusterFixture(t, "https://follower.test", transport, true)
	masterIdentity, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := owner.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := owner.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := db.Nodes().Relationship(ctx, relID)
	if err != nil {
		t.Fatal(err)
	}
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 5*store.GiB
	if err := db.Pool().ConfigureMember(ctx, identity.ID, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := master.Tick(ctx, relation); err != nil {
		t.Fatal(err)
	}
	resolver, _ := network.New(nil)
	RegisterOpaqueNodeMedia(router, ownerPublic.settings, resolver, owner, ownerPublic.media)
	RegisterOpaqueRevocationControl(router, ownerPublic.settings, resolver, owner, ownerPublic.media)
	withoutFence := httptest.NewRequest(http.MethodPost, "https://follower.test"+protocol.OpaqueRevokePath, strings.NewReader(`{}`))
	withoutFenceResult := httptest.NewRecorder()
	router.ServeHTTP(withoutFenceResult, withoutFence)
	if withoutFenceResult.Code != http.StatusServiceUnavailable {
		t.Fatalf("owner control must fail closed without its local fence: %d", withoutFenceResult.Code)
	}
	ownerFence := &relayTreeFixture{}
	owner.ConfigureOpaqueOwnerRequestReadiness(func(ctx context.Context) (node.IngressPrerequisiteLease, error) { return ownerFence.acquire(ctx) })
	if err := master.VerifyFollowerOpaqueReadiness(ctx, relation, "https://follower.test"); err != nil {
		t.Fatal("actual Gin v5 probe", err)
	}
	unauthenticatedProbe := httptest.NewRequest(http.MethodGet, "https://follower.test"+node.NativeOpaqueMediaProbePath, nil)
	unauthenticatedProbe.Header.Set("X-Fc-Opaque-Probe", strings.Repeat("f", 32))
	unauthenticatedProbe.Header.Set("X-Media-Capability", "forged")
	probeResponse := httptest.NewRecorder()
	router.ServeHTTP(probeResponse, unauthenticatedProbe)
	if probeResponse.Code != http.StatusUnauthorized {
		t.Fatal("anonymous opaque probe", probeResponse.Code)
	}
	object, blob := strings.Repeat("a", 64), strings.Repeat("b", 64)
	name, _ := sealedtree.BlobPath(blob)
	full := filepath.Join(dir, "media", filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("opaque synthetic content")
	if err := os.WriteFile(full, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	descriptor, err := protocol.IngressMediaDescriptor(int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := protocol.OpaquePlacementRevision(object, blob, digest, int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	ownerBinding := media.OpaqueOwnerBinding{MasterID: masterIdentity.ID, OwnerID: identity.ID, RelationshipID: relID, Alias: object, Blob: blob, Revision: revision, Digest: digest, Descriptor: descriptor, Size: int64(len(data))}
	if err := ownerPublic.media.RegisterOpaqueOwnerBinding(ctx, ownerBinding); err != nil {
		t.Fatal("register opaque binding", err)
	}
	ingress := network.AuthenticatedIngress{NodeID: strings.Repeat("c", 32), Generation: 2, PublicOrigin: "https://entry.test", ClientIP: "192.0.2.1"}
	verified, err := network.WithAuthenticatedIngress(ctx, ingress)
	if err != nil {
		t.Fatal(err)
	}
	verified, admission := network.WithPublicAdmission(verified)
	defer admission.Abort()
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := "browser:v2:" + strings.Repeat("d", 64)
	session, err := public.crypto.NewSession(binding, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	verified, err = public.crypto.WithDirectSession(verified, binding, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := master.MediaOpaqueIngressCapability(verified, relID, identity.ID, object, blob, int64(len(data)), time.Now().Unix()+60, digest, nil); err == nil {
		t.Fatal("issued without held tree authority")
	}
	fence := &relayTreeFixture{}
	held, _ := fence.acquire(ctx)
	defer held.Release()
	verified = store.WithIngressPrerequisite(verified, held)
	token, err := master.MediaOpaqueIngressCapability(verified, relID, identity.ID, object, blob, int64(len(data)), time.Now().Unix()+60, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A signed v5 encrypted descriptor may use the browser ciphertext path;
	// the independent browser GCM check must reject storage corruption. The
	// same corrupted object cannot use a whole-file server-side read.
	metadata, err := mediacrypto.NewMetadata(32)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(bytes.Repeat([]byte{7}, 32))
	aead, _ := cipher.NewGCM(block)
	nonce, _ := metadata.ChunkNonce(0)
	cipherBytes := aead.Seal(nil, nonce, bytes.Repeat([]byte{'x'}, 32), metadata.ChunkAAD(0))
	cipherAlias, cipherBlob := strings.Repeat("3", 64), strings.Repeat("4", 64)
	cipherName, _ := sealedtree.BlobPath(cipherBlob)
	cipherFile := filepath.Join(dir, "media", filepath.FromSlash(cipherName))
	if err = os.MkdirAll(filepath.Dir(cipherFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cipherFile, cipherBytes, 0600); err != nil {
		t.Fatal(err)
	}
	cipherSum := sha256.Sum256(cipherBytes)
	cipherDigest := hex.EncodeToString(cipherSum[:])
	cipherDescriptor, _ := protocol.IngressMediaDescriptor(int64(len(cipherBytes)), &metadata)
	cipherRevision, _ := protocol.OpaquePlacementRevision(cipherAlias, cipherBlob, cipherDigest, int64(len(cipherBytes)), &metadata)
	cipherBinding := media.OpaqueOwnerBinding{MasterID: masterIdentity.ID, OwnerID: identity.ID, RelationshipID: relID, Alias: cipherAlias, Blob: cipherBlob, Revision: cipherRevision, Digest: cipherDigest, Descriptor: cipherDescriptor, Size: int64(len(cipherBytes))}
	if err = ownerPublic.media.RegisterOpaqueOwnerBinding(ctx, cipherBinding); err != nil {
		t.Fatal(err)
	}
	cipherToken, err := master.MediaOpaqueIngressCapability(verified, relID, identity.ID, cipherAlias, cipherBlob, int64(len(cipherBytes)), time.Now().Unix()+60, cipherDigest, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	legacyCipherToken, err := master.MediaIngressCapability(verified, relID, identity.ID, cipherAlias, cipherAlias, int64(len(cipherBytes)), time.Now().Unix()+60, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	cipherBytes[1] ^= 1
	if err = os.WriteFile(cipherFile, cipherBytes, 0600); err != nil {
		t.Fatal(err)
	}
	cipherRequest := func(cap, origin, byteRange string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://follower.test/internal/v1/opaque-media/"+cipherAlias, nil)
		r.Header.Set("X-Media-Capability", cap)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if byteRange != "" {
			r.Header.Set("Range", byteRange)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(masterDirectRecorder{w}, r)
		return w
	}
	rangeHeader := "bytes=0-" + strconv.Itoa(len(cipherBytes)-1)
	cipherResponse := cipherRequest(cipherToken, ingress.PublicOrigin, rangeHeader)
	if cipherResponse.Code != http.StatusPartialContent || cipherResponse.Header().Get("Content-Range") != "bytes 0-47/48" || cipherResponse.Body.Len() != len(cipherBytes) {
		t.Fatal("encrypted browser range", cipherResponse.Code, cipherResponse.Header())
	}
	if decoded, err := aead.Open(nil, nonce, cipherResponse.Body.Bytes(), metadata.ChunkAAD(0)); err == nil || len(decoded) != 0 {
		t.Fatal("corrupted ciphertext authenticated")
	}
	if response := cipherRequest("forged", ingress.PublicOrigin, rangeHeader); response.Code != http.StatusUnauthorized {
		t.Fatal("forged v5 capability admitted", response.Code)
	}
	if response := cipherRequest(legacyCipherToken, ingress.PublicOrigin, rangeHeader); response.Code != http.StatusUnauthorized {
		t.Fatal("legacy descriptor downgraded to v5", response.Code)
	}
	if response := cipherRequest(cipherToken, "https://untrusted.test", rangeHeader); response.Code != http.StatusForbidden {
		t.Fatal("different browser origin admitted", response.Code)
	}
	if response := cipherRequest(cipherToken, ingress.PublicOrigin, ""); response.Code != http.StatusConflict {
		t.Fatal("whole-file server-side read bypassed verification", response.Code)
	}
	// An existing empty object is a valid owner object. Authenticate its real
	// empty digest and exercise the same endpoint used by Direct and Relay.
	emptyAlias, emptyBlob := strings.Repeat("1", 64), strings.Repeat("2", 64)
	emptyName, err := sealedtree.BlobPath(emptyBlob)
	if err != nil {
		t.Fatal(err)
	}
	emptyFull := filepath.Join(dir, "media", filepath.FromSlash(emptyName))
	if err := os.MkdirAll(filepath.Dir(emptyFull), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(emptyFull, nil, 0600); err != nil {
		t.Fatal(err)
	}
	emptyHash := sha256.Sum256(nil)
	emptyDigest := hex.EncodeToString(emptyHash[:])
	emptyDescriptor, err := protocol.IngressMediaDescriptor(0, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyRevision, err := protocol.OpaquePlacementRevision(emptyAlias, emptyBlob, emptyDigest, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyBinding := media.OpaqueOwnerBinding{MasterID: masterIdentity.ID, OwnerID: identity.ID, RelationshipID: relID, Alias: emptyAlias, Blob: emptyBlob, Revision: emptyRevision, Digest: emptyDigest, Descriptor: emptyDescriptor, Size: 0}
	if err := ownerPublic.media.RegisterOpaqueOwnerBinding(ctx, emptyBinding); err != nil {
		t.Fatal(err)
	}
	emptyToken, err := master.MediaOpaqueIngressCapability(verified, relID, identity.ID, emptyAlias, emptyBlob, 0, time.Now().Unix()+60, emptyDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, useRange := range []bool{false, true} {
			r := httptest.NewRequest(method, "https://follower.test/internal/v1/opaque-media/"+emptyAlias, nil)
			r.Header.Set("Origin", ingress.PublicOrigin)
			r.Header.Set("X-Media-Capability", emptyToken)
			if useRange {
				r.Header.Set("Range", "bytes=0-0")
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(masterDirectRecorder{w}, r)
			if w.Code != http.StatusOK || w.Header().Get("Content-Length") != "0" || w.Body.Len() != 0 {
				t.Fatalf("empty owner %s: status=%d headers=%v body=%q", method, w.Code, w.Header(), w.Body.String())
			}
		}
	}
	nginxRouter := gin.New()
	nginxSettings := ownerPublic.settings
	nginxSettings.NginxMedia = true
	RegisterOpaqueNodeMedia(nginxRouter, nginxSettings, resolver, owner, ownerPublic.media)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		r := httptest.NewRequest(method, "https://follower.test/internal/v1/opaque-media/"+emptyAlias, nil)
		r.Header.Set("X-Media-Capability", emptyToken)
		r.Header.Set("Range", "bytes=-1")
		w := httptest.NewRecorder()
		nginxRouter.ServeHTTP(masterDirectRecorder{w}, r)
		if w.Code != http.StatusOK || w.Header().Get("Content-Length") != "0" || w.Header().Get("Content-Range") != "" {
			t.Fatalf("Nginx empty owner %s: %d %v", method, w.Code, w.Header())
		}
	}
	if err := os.WriteFile(emptyFull, []byte("not empty"), 0600); err != nil {
		t.Fatal(err)
	}
	emptyReplacement := httptest.NewRequest(http.MethodGet, "https://follower.test/internal/v1/opaque-media/"+emptyAlias, nil)
	emptyReplacement.Header.Set("X-Media-Capability", emptyToken)
	emptyRejected := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{emptyRejected}, emptyReplacement)
	if emptyRejected.Code == http.StatusOK {
		t.Fatal("replaced empty owner object admitted")
	}
	request := func(path, cap, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://follower.test"+path, nil)
		if cap != "" {
			r.Header.Set("X-Media-Capability", cap)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r.Header.Set("Range", "bytes=1-4")
		w := httptest.NewRecorder()
		router.ServeHTTP(masterDirectRecorder{w}, r)
		return w
	}
	path := "/internal/v1/opaque-media/" + object
	deadlineRequest := httptest.NewRequest(http.MethodGet, "https://follower.test"+path, nil)
	deadlineRequest.Header.Set("X-Media-Capability", token)
	deadlineWriter := &opaqueDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	router.ServeHTTP(deadlineWriter, deadlineRequest)
	if deadlineWriter.Code != http.StatusOK || deadlineWriter.deadline.IsZero() || deadlineWriter.deadline.After(time.Now().Add(time.Duration(protocol.TokenSeconds)*time.Second)) {
		t.Fatal("opaque read lacked bounded write deadline", deadlineWriter.Code, deadlineWriter.deadline)
	}
	unsupportedRequest := httptest.NewRequest(http.MethodGet, "https://follower.test"+path, nil)
	unsupportedRequest.Header.Set("X-Media-Capability", token)
	unsupported := httptest.NewRecorder()
	router.ServeHTTP(unsupported, unsupportedRequest)
	if unsupported.Code != http.StatusServiceUnavailable {
		t.Fatal("unbounded opaque writer admitted", unsupported.Code)
	}
	if w := request(path, token, ingress.PublicOrigin); w.Code != http.StatusPartialContent || w.Body.String() != string(data[1:5]) || w.Header().Get("Access-Control-Allow-Origin") != ingress.PublicOrigin {
		t.Fatal("opaque range", w.Code, w.Body.String())
	}
	if w := request(path, "", ingress.PublicOrigin); w.Code != http.StatusUnauthorized {
		t.Fatal("anonymous opaque read", w.Code)
	}
	if w := request(path+"?token="+token, "", ingress.PublicOrigin); w.Code != http.StatusUnauthorized {
		t.Fatal("query bearer accepted", w.Code)
	}
	if w := request(path, token, "https://untrusted.test"); w.Code != http.StatusForbidden {
		t.Fatal("untrusted origin", w.Code)
	}
	if w := request("/internal/v1/media/"+object, token, ingress.PublicOrigin); w.Code != http.StatusUnauthorized {
		t.Fatal("legacy endpoint accepted opaque token", w.Code)
	}
	data[1] ^= 0xff
	if err := os.WriteFile(full, data, 0600); err != nil {
		t.Fatal(err)
	}
	// The fixture uses a small file in one chunk, so corruption is detected
	// before a response body is written even after its index has been cached.
	r := httptest.NewRequest(http.MethodGet, "https://follower.test"+path, nil)
	r.Header.Set("X-Media-Capability", token)
	r.Header.Set("Range", "bytes=1-4")
	w := httptest.NewRecorder()
	var interrupted any
	func() {
		defer func() { interrupted = recover() }()
		router.ServeHTTP(masterDirectRecorder{w}, r)
	}()
	if interrupted != http.ErrAbortHandler || w.Body.Len() != 0 {
		t.Fatal("changed bytes returned or stream not aborted", interrupted, w.Body.String())
	}
	server := httptest.NewTLSServer(router)
	defer server.Close()
	networkRequest, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	networkRequest.Header.Set("X-Media-Capability", token)
	networkRequest.Header.Set("Range", "bytes=1-4")
	response, err := server.Client().Do(networkRequest)
	if err == nil {
		defer response.Body.Close()
		body, readErr := io.ReadAll(response.Body)
		if readErr == nil || len(body) != 0 {
			t.Fatal("TLS client did not observe the interrupted stream", readErr, string(body))
		}
	}
	if err := os.WriteFile(full, []byte("opaque synthetic content"), 0600); err != nil {
		t.Fatal(err)
	}
	revoke := protocol.OpaqueRevocationRequest{OperationID: strings.Repeat("e", 32), Binding: ownerBinding}
	relationshipBinding := store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt})
	unsigned := httptest.NewRequest(http.MethodPost, "https://follower.test"+protocol.OpaqueRevokePath, strings.NewReader(`{}`))
	unsignedResponse := httptest.NewRecorder()
	router.ServeHTTP(unsignedResponse, unsigned)
	if unsignedResponse.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated opaque revocation", unsignedResponse.Code)
	}
	if _, err := master.RequestOpaqueOwnerRevocation(ctx, revoke, relationshipBinding); err == nil {
		t.Fatal("missing relationship fence accepted")
	}
	controlGuard := &relayTreeFixture{}
	controlLease, err := controlGuard.acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer controlLease.Release()
	controlCtx := store.WithOpaqueControlAuthority(ctx, relationshipBinding, controlLease)
	if _, err := master.RequestOpaqueOwnerRevocation(controlCtx, revoke, strings.Repeat("0", 64)); err == nil {
		t.Fatal("mismatched relationship instance accepted")
	}
	if w := request(path, token, ingress.PublicOrigin); w.Code != http.StatusPartialContent {
		t.Fatal("mismatched instance modified owner", w.Code)
	}
	owner.ConfigureOpaqueOwnerRequestReadiness(func(context.Context) (node.IngressPrerequisiteLease, error) { return &failedOpaqueOwnerFence{}, nil })
	if _, err := master.RequestOpaqueOwnerRevocation(controlCtx, revoke, relationshipBinding); err == nil {
		t.Fatal("lost owner fence admitted revocation")
	}
	if w := request(path, token, ingress.PublicOrigin); w.Code != http.StatusPartialContent {
		t.Fatal("failed owner fence modified registry", w.Code)
	}
	owner.ConfigureOpaqueOwnerRequestReadiness(func(ctx context.Context) (node.IngressPrerequisiteLease, error) { return ownerFence.acquire(ctx) })
	signed, err := master.RequestOpaqueOwnerRevocation(controlCtx, revoke, relationshipBinding)
	if err != nil {
		t.Fatal("paired opaque revocation", err)
	}
	receipt, err := revoke.Receipt()
	if err != nil || master.VerifyOpaqueRevocationReceipt(ctx, relID, receipt, signed) != nil {
		t.Fatal("owner receipt verification", err)
	}
	if _, err := master.RequestOpaqueOwnerRevocation(controlCtx, revoke, relationshipBinding); err != nil {
		t.Fatal("idempotent owner revocation", err)
	}
	changed := receipt
	changed.OperationID = strings.Repeat("f", 32)
	if master.VerifyOpaqueRevocationReceipt(ctx, relID, changed, signed) == nil {
		t.Fatal("receipt accepted for different operation")
	}
	if w := request(path, token, ingress.PublicOrigin); w.Code != http.StatusConflict || w.Body.Len() == 0 {
		t.Fatal("revoked owner token admitted", w.Code)
	}
}
