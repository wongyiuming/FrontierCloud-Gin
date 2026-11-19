//go:build linux

package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type opaquePeerRouting struct {
	*masterDirectHTTPRouting
	acquireOwner func(context.Context) (store.OwnerControlLease, error)
}

type opaquePeerDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *opaquePeerDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		w.deadline = deadline
	}
	return nil
}

func (r *opaquePeerRouting) AcquireOwnerControlShared(ctx context.Context) (store.OwnerControlLease, error) {
	return r.acquireOwner(ctx)
}

// This exercises the real encrypted tree, signed grants, browser session and
// Gin handlers; the peer ingress assertion is supplied by the test fixture.
func TestOpaqueMasterPeerMediaDirectAndRelay(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	masterRouter, db, dir, public, original := clusterFixture(t, "https://master.test", transport, false)
	identity, err := original.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("synthetic encrypted audio and video")
	metadata, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := public.crypto.FileKey(metadata)
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
	nonce, err := metadata.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, plain, metadata.ChunkAAD(0))
	treeDB, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer treeDB.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, folderID := strings.Repeat("1", 64), strings.Repeat("2", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, treeDB, codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	privateDir := t.TempDir()
	if err = os.Chmod(privateDir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(privateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = sealedtree.InitializeFence(ctx, tree, root, privateDir); err != nil {
		t.Fatal(err)
	}
	if err = tree.CreateDirectoryWithFacts(ctx, sealedtree.Entry{ParentID: rootID, ObjectID: folderID, Kind: "directory", Name: "music"}, sealedtree.Facts{ObjectID: folderID}); err != nil {
		t.Fatal(err)
	}
	publisher, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("3", 64)
	sum := sha256.Sum256(ciphertext)
	placement := sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: identity.ID, Bytes: int64(len(ciphertext)), SHA256: hex.EncodeToString(sum[:]), State: "active", Encryption: &metadata}
	prepared, err := tree.PrepareFileWithFreshLocators(ctx, sealedtree.Entry{ParentID: folderID, ObjectID: id, Kind: "audio", Name: "sample.mp3"}, placement, sealedtree.Facts{ObjectID: id})
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(ciphertext)); err != nil {
		t.Fatal(err)
	}
	name, err := sealedtree.BlobPath(prepared.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "media", filepath.FromSlash(name))
	if err = os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	videoMeta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	videoKey, err := public.crypto.FileKey(videoMeta)
	if err != nil {
		t.Fatal(err)
	}
	videoBlock, err := aes.NewCipher(videoKey)
	if err != nil {
		t.Fatal(err)
	}
	videoAEAD, err := cipher.NewGCM(videoBlock)
	if err != nil {
		t.Fatal(err)
	}
	videoNonce, err := videoMeta.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	videoCipher := videoAEAD.Seal(nil, videoNonce, plain, videoMeta.ChunkAAD(0))
	videoRoot, videoDir, videoID := strings.Repeat("4", 64), strings.Repeat("6", 64), strings.Repeat("5", 64)
	for _, entry := range []sealedtree.Entry{
		{ParentID: rootID, ObjectID: videoRoot, Kind: "directory", Name: "vido"},
		{ParentID: videoRoot, ObjectID: videoDir, Kind: "directory", Name: "clips"},
	} {
		if err = tree.CreateDirectoryWithFacts(ctx, entry, sealedtree.Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	videoSum := sha256.Sum256(videoCipher)
	videoPlacement := sealedtree.Placement{ObjectID: videoID, NativeObjectID: videoID, OwnerID: identity.ID, Bytes: int64(len(videoCipher)), SHA256: hex.EncodeToString(videoSum[:]), State: "active", Encryption: &videoMeta}
	videoPrepared, err := tree.PrepareFileWithFreshLocators(ctx, sealedtree.Entry{ParentID: videoDir, ObjectID: videoID, Kind: "video", Name: "sample.mp4"}, videoPlacement, sealedtree.Facts{ObjectID: videoID})
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.PublishPending(ctx, videoPrepared.OperationID, publisher, bytes.NewReader(videoCipher)); err != nil {
		t.Fatal(err)
	}
	videoName, err := sealedtree.BlobPath(videoPrepared.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	videoFile := filepath.Join(dir, "media", filepath.FromSlash(videoName))
	if err = os.MkdirAll(filepath.Dir(videoFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(videoFile, videoCipher, 0600); err != nil {
		t.Fatal(err)
	}
	videoObject := store.MediaObject{ID: videoID, Path: "vido/clips/sample.mp4", Kind: "video", Encryption: &videoMeta}
	s3Track, providerObject := addOpaqueS3LyricTrack(ctx, t, tree, folderID)
	var lyricMeta mediacrypto.Metadata
	var lyricCipher []byte
	lyricFolder, lyricID := strings.Repeat("9", 64), strings.Repeat("7", 64)
	setLinkedLyric := func(track, id string) {
		t.Helper()
		_, revision, err := tree.GetFacts(ctx, track)
		if err != nil {
			t.Fatal(err)
		}
		var targets []string
		if id != "" {
			targets = []string{id}
		}
		if err = tree.ApplyNativeLyricBatch(ctx, sealedtree.NativeLyricOperation{
			OriginID: track, TargetIDs: targets,
			Changes: []sealedtree.NativeLyricChange{{TrackID: track, LyricID: id, ExpectedFactsRevision: revision}},
		}, store.AdminAudit{}); err != nil {
			t.Fatal(err)
		}
	}
	{
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		_, err = treeDB.ExecContext(ctx, `CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT NOT NULL,role TEXT NOT NULL); CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`)
		must(err)
		_, err = treeDB.ExecContext(ctx, `INSERT INTO node_identity VALUES(1,?,'Master')`, identity.ID)
		must(err)
		must(tree.CreateDirectoryWithFacts(ctx, sealedtree.Entry{ParentID: rootID, ObjectID: lyricFolder, Kind: "directory", Name: "lyrics"}, sealedtree.Facts{ObjectID: lyricFolder}))
		lyricPlain := []byte("[00:01.00] encrypted linked lyric")
		lyricMeta, err = mediacrypto.NewMetadata(int64(len(lyricPlain)))
		must(err)
		lyricKey, err := public.crypto.FileKey(lyricMeta)
		must(err)
		lyricBlock, err := aes.NewCipher(lyricKey)
		clear(lyricKey)
		must(err)
		lyricAEAD, err := cipher.NewGCM(lyricBlock)
		must(err)
		lyricNonce, err := lyricMeta.ChunkNonce(0)
		must(err)
		lyricCipher = lyricAEAD.Seal(nil, lyricNonce, lyricPlain, lyricMeta.ChunkAAD(0))
		lyricSum := sha256.Sum256(lyricCipher)
		lyricEntry := sealedtree.Entry{ParentID: lyricFolder, ObjectID: lyricID, Kind: "lyric", Name: "s3.lrc"}
		lyricPlacement := sealedtree.Placement{ObjectID: lyricID, NativeObjectID: lyricID, OwnerID: identity.ID,
			Bytes: int64(len(lyricCipher)), SHA256: hex.EncodeToString(lyricSum[:]), State: "active", Encryption: &lyricMeta}
		prepared, err := tree.PrepareFileWithFreshLocators(ctx, lyricEntry, lyricPlacement, sealedtree.Facts{ObjectID: lyricID})
		must(err)
		must(tree.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(lyricCipher)))
		blob, err := sealedtree.BlobPath(prepared.BlobID)
		must(err)
		lyricFile := filepath.Join(dir, "media", filepath.FromSlash(blob))
		must(os.MkdirAll(filepath.Dir(lyricFile), 0700))
		must(os.WriteFile(lyricFile, lyricCipher, 0600))
		setLinkedLyric(id, lyricID)
		if s3Track != "" {
			setLinkedLyric(s3Track, lyricID)
		}
	}
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 5}
	routing := &opaquePeerRouting{masterDirectHTTPRouting: &masterDirectHTTPRouting{selectedIngressRepository: selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: ingress}, policy: store.NativeTransportPolicy{MemberID: identity.ID, ConfiguredTransport: "Direct", AppliedTransport: "Direct", State: "applied", Revision: 2}}}
	identityCodec, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	ownerDir := filepath.Join(dir, "media")
	if err = os.MkdirAll(filepath.Join(ownerDir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	ownerRoot, err := os.OpenRoot(ownerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerRoot.Close()
	ownerFence, err := ownerfence.Create(ownerRoot, ownerDir, identityCodec)
	if err != nil {
		t.Fatal(err)
	}
	ownerCoordinator := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if err = ownerCoordinator.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return ownerFence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = ownerCoordinator.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	routing.acquireOwner = ownerCoordinator.AcquireOwnerControlShared
	control := node.NewService(routing, identityCodec, transport)
	prepareMasterHTTPPolicy(t, control)
	public.media.ConfigureCluster(routing, db.Pool(), control)
	router := gin.New()
	settings := public.settings
	settings.TLSEnabled = true
	direct, err := RegisterMasterDirect(router, settings, "https://resource.test", public.media, control, public.crypto)
	if err != nil {
		t.Fatal(err)
	}
	if err = direct.ConfigureOpaqueLyricTree(tree); err != nil {
		t.Fatal(err)
	}
	relay, err := RegisterMasterRelay(router, public.media, control, public.crypto)
	if err != nil {
		t.Fatal(err)
	}
	if err = relay.ConfigureOpaqueLyricTree(tree); err != nil {
		t.Fatal(err)
	}
	public.control, public.opaqueTree, public.masterDirect, public.masterRelay = control, tree, direct, relay
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: ingress.NodeID, Generation: ingress.Generation, PublicOrigin: ingress.PublicOrigin, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	verified, admission := network.WithPublicAdmission(verified)
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
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bound := store.WithIngressPrerequisite(verified, lease)
	object := store.MediaObject{ID: id, Path: "music/sample.mp3", Kind: "audio", Encryption: &metadata}
	details, headers, expiry, err := direct.IssueOpaqueMedia(bound, object, id, binding, session.SessionID)
	if err != nil || details.SourceObjectID != prepared.ReadAlias || details.OwnerID != identity.ID || expiry > session.ExpiresAt {
		t.Fatal("issue Direct", err, details)
	}
	if _, _, _, err = direct.IssueOpaqueMedia(bound, object, id, "wrong", session.SessionID); err == nil {
		t.Fatal("wrong session binding")
	}
	if _, _, _, err = relay.IssueOpaqueMedia(bound, object, id, binding, session.SessionID); err == nil {
		t.Fatal("Relay issued under Direct policy")
	}
	if _, _, _, err = direct.IssueOpaqueMedia(bound, object, videoID, binding, session.SessionID); err == nil {
		t.Fatal("mismatched object accepted")
	}
	videoDirect, videoDirectHeaders, _, err := direct.IssueOpaqueMedia(bound, videoObject, videoID, binding, session.SessionID)
	if err != nil || videoDirect.SourceObjectID != videoPrepared.ReadAlias {
		t.Fatal("issue video Direct", err)
	}
	lease.Release()
	requestRange := func(target, origin, token, byteRange string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, target, nil).WithContext(verified)
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Origin", origin)
		r.Header.Set("Range", byteRange)
		if strings.Contains(target, "master-relay") {
			r.Header.Set("X-Media-Relay", token)
		} else {
			r.Header.Set("X-Media-Capability", token)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(masterDirectRecorder{w}, r)
		return w
	}
	request := func(target, origin, token string) *httptest.ResponseRecorder {
		return requestRange(target, origin, token, "bytes=1-4")
	}
	if w := request(details.Source, ingress.PublicOrigin, headers["X-Media-Capability"]); w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), ciphertext[1:5]) {
		t.Fatal("Direct range", w.Code, w.Body.String())
	}
	drainDeadline := func(target, token, header string) {
		r := httptest.NewRequest(http.MethodGet, target, nil).WithContext(verified)
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Origin", ingress.PublicOrigin)
		r.Header.Set(header, token)
		r.Header.Set("Range", "bytes=1-4")
		w := &opaquePeerDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		router.ServeHTTP(w, r)
		if w.Code != http.StatusPartialContent || w.deadline.Before(time.Now().Add(29*time.Minute)) || w.deadline.After(time.Now().Add(31*time.Minute)) {
			t.Fatal("bounded stream drain deadline", w.Code, w.deadline)
		}
	}
	drainDeadline(details.Source, headers["X-Media-Capability"], "X-Media-Capability")
	exclusive, err := ownerFence.Acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	blockedCtx, cancelBlocked := context.WithTimeout(verified, 100*time.Millisecond)
	blockedReq := httptest.NewRequest(http.MethodGet, details.Source, nil).WithContext(blockedCtx)
	blockedReq.TLS = &tls.ConnectionState{}
	blockedReq.Header.Set("Origin", ingress.PublicOrigin)
	blockedReq.Header.Set("X-Media-Capability", headers["X-Media-Capability"])
	blockedResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{blockedResponse}, blockedReq)
	cancelBlocked()
	exclusive.Release()
	if blockedResponse.Code == http.StatusOK || blockedResponse.Code == http.StatusPartialContent {
		t.Fatal("Direct crossed Owner exclusive fence", blockedResponse.Code)
	}
	if w := request(details.Source, "https://wrong.test", headers["X-Media-Capability"]); w.Code != http.StatusForbidden {
		t.Fatal("Direct wrong origin", w.Code)
	}
	if w := request(details.Source, ingress.PublicOrigin, ""); w.Code != http.StatusUnauthorized {
		t.Fatal("Direct no grant", w.Code)
	}
	if w := request(videoDirect.Source, ingress.PublicOrigin, videoDirectHeaders["X-Media-Capability"]); w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), videoCipher[1:5]) {
		t.Fatal("video Direct range", w.Code)
	}
	if w := request(videoDirect.Source, ingress.PublicOrigin, headers["X-Media-Capability"]); w.Code != http.StatusForbidden {
		t.Fatal("audio grant opened video", w.Code)
	}
	setDisplayHidden := func(id string, hidden bool) {
		t.Helper()
		facts, revision, err := tree.GetFacts(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		facts.Visibility = nil
		if hidden {
			facts.Visibility = &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026-11-05"}
		}
		if _, err = tree.SetFacts(ctx, facts, revision); err != nil {
			t.Fatal(err)
		}
	}
	setDisplayHidden(videoID, true)
	if w := request(videoDirect.Source, ingress.PublicOrigin, videoDirectHeaders["X-Media-Capability"]); w.Code != http.StatusPartialContent ||
		!bytes.Equal(w.Body.Bytes(), videoCipher[1:5]) {
		t.Fatal("existing Direct video grant failed after display hide", w.Code)
	}
	if w := request(videoDirect.Source, ingress.PublicOrigin, ""); w.Code != http.StatusUnauthorized {
		t.Fatal("hidden Direct video admitted without a media grant", w.Code)
	}
	publicCall := func(target string, payload any, cookie *http.Cookie) *httptest.ResponseRecorder {
		body, e := json.Marshal(payload)
		if e != nil {
			t.Fatal(e)
		}
		publicCtx, publicAdmission := network.WithPublicAdmission(verified)
		defer publicAdmission.Abort()
		readLease, e := tree.AcquireReadFence(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer readLease.Release()
		publicCtx = store.WithIngressPrerequisite(publicCtx, readLease)
		r := httptest.NewRequest(http.MethodPost, ingress.PublicOrigin+target, bytes.NewReader(body)).WithContext(publicCtx)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", ingress.PublicOrigin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		masterRouter.ServeHTTP(masterDirectRecorder{w}, r)
		if w.Code == http.StatusOK && !publicAdmission.Commit() {
			t.Fatal("public admission failed")
		}
		return w
	}
	sessionResponse := publicCall("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, nil)
	var httpSession mediacrypto.SessionGrant
	if sessionResponse.Code != http.StatusOK || json.Unmarshal(sessionResponse.Body.Bytes(), &httpSession) != nil || len(sessionResponse.Result().Cookies()) != 1 {
		t.Fatal("peer session", sessionResponse.Code, sessionResponse.Body.String())
	}
	cookie := sessionResponse.Result().Cookies()[0]
	type keyResponse struct {
		Encryption      mediacrypto.Metadata    `json:"encryption"`
		Envelope        mediacrypto.KeyEnvelope `json:"key_envelope"`
		SourceURL       string                  `json:"source_url"`
		SourceHeaders   map[string]string       `json:"source_headers"`
		SourceTransport string                  `json:"source_transport"`
		SourceObjectID  string                  `json:"source_object_id"`
		SourceOwnerID   string                  `json:"source_owner_id"`
		ExpiresAt       int64                   `json:"source_expires_at"`
	}
	readKey := func(object store.MediaObject) keyResponse {
		w := publicCall("/api/v1/media/crypto/key", gin.H{"session_id": httpSession.SessionID, "file_path": object.Path, "resource_id": object.ID, "object_id": object.ID}, cookie)
		var result keyResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Encryption != *object.Encryption || result.Envelope.ExpiresAt == 0 || result.ExpiresAt > httpSession.ExpiresAt || result.SourceOwnerID != identity.ID {
			t.Fatal("peer key response", w.Code, w.Body.String())
		}
		return result
	}
	decode := func(encoded string) []byte {
		t.Helper()
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	serverPublicKey, err := ecdh.P256().NewPublicKey(decode(httpSession.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := client.ECDH(serverPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapKey, err := hkdf.Key(sha256.New, shared, decode(httpSession.Salt), "frontiercloud:browser-wrap:v1:"+httpSession.SessionID, 32)
	if err != nil {
		t.Fatal(err)
	}
	newAEAD := func(key []byte) cipher.AEAD {
		t.Helper()
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return aead
	}
	browserAEAD := newAEAD(wrapKey)
	playHiddenVideo := func(mode, header string) keyResponse {
		t.Helper()
		result := readKey(videoObject)
		if result.SourceTransport != mode || result.SourceObjectID != videoPrepared.ReadAlias || result.SourceHeaders[header] == "" {
			t.Fatalf("exact hidden video source through %s: %s", mode, result.SourceTransport)
		}
		byteRange := "bytes=0-" + strconv.Itoa(len(videoCipher)-1)
		w := requestRange(result.SourceURL, ingress.PublicOrigin, result.SourceHeaders[header], byteRange)
		if w.Code != http.StatusPartialContent {
			t.Fatalf("exact hidden video range through %s: %d", mode, w.Code)
		}
		fileKey, err := browserAEAD.Open(nil, decode(result.Envelope.IV), decode(result.Envelope.WrappedKey),
			[]byte("frontiercloud:key-envelope:v1:"+httpSession.SessionID+":"+result.Encryption.FileID))
		if err != nil {
			t.Fatalf("exact hidden video key did not unwrap through %s: %v", mode, err)
		}
		decoded, err := newAEAD(fileKey).Open(nil, videoNonce, w.Body.Bytes(), result.Encryption.ChunkAAD(0))
		if err != nil || !bytes.Equal(decoded, plain) {
			t.Fatalf("exact hidden video ciphertext did not decrypt through %s: %v", mode, err)
		}
		return result
	}
	playHiddenVideo("Direct", "X-Media-Capability")
	for _, mismatch := range []struct{ name, resource, object string }{
		{videoObject.Path + ".missing", videoID, videoID},
		{videoObject.Path, id, videoID},
		{videoObject.Path, videoID, id},
	} {
		w := publicCall("/api/v1/media/crypto/key", gin.H{"session_id": httpSession.SessionID, "file_path": mismatch.name,
			"resource_id": mismatch.resource, "object_id": mismatch.object}, cookie)
		if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "key_envelope") || strings.Contains(w.Body.String(), "source_url") {
			t.Fatal("hidden video grant accepted wrong path or identity", w.Code)
		}
	}
	setDisplayHidden(videoID, false)
	setDisplayHidden(videoDir, true)
	readLinkedLyric := func(track, mode, header string, allowed bool) keyResponse {
		t.Helper()
		w := publicCall("/api/v1/media/crypto/key", gin.H{"session_id": httpSession.SessionID, "file_path": "lyrics/s3.lrc",
			"resource_id": lyricID, "object_id": lyricID, "track_resource_id": track}, cookie)
		var result keyResponse
		if !allowed {
			if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "source_url") {
				t.Fatalf("incorrect lyric track granted: %d %s", w.Code, w.Body.String())
			}
			return result
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Encryption != lyricMeta ||
			result.SourceTransport != mode || result.SourceOwnerID != identity.ID || result.SourceObjectID == lyricID ||
			result.SourceObjectID == providerObject || result.SourceHeaders[header] == "" || strings.Contains(result.SourceURL, track) {
			t.Fatalf("linked lyric key through %s: %d %s", mode, w.Code, w.Body.String())
		}
		if w := request(result.SourceURL, ingress.PublicOrigin, result.SourceHeaders[header]); w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), lyricCipher[1:5]) {
			t.Fatalf("linked lyric ciphertext Range through %s: %d %s", mode, w.Code, w.Body.String())
		}
		return result
	}
	if s3Track != "" {
		readLinkedLyric(providerObject, "Direct", "X-Media-Capability", false)
		readLinkedLyric(s3Track, "Direct", "X-Media-Capability", true)
	}
	setDisplayHidden(id, true)
	readLinkedLyric(id, "Direct", "X-Media-Capability", true)
	readLinkedLyric(videoID, "Direct", "X-Media-Capability", false)
	setDisplayHidden(id, false)
	keyDirect := readKey(object)
	if keyDirect.SourceTransport != "Direct" || keyDirect.SourceObjectID != prepared.ReadAlias {
		t.Fatal("Direct key source", keyDirect.SourceTransport)
	}
	if w := request(keyDirect.SourceURL, ingress.PublicOrigin, keyDirect.SourceHeaders["X-Media-Capability"]); w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), ciphertext[1:5]) {
		t.Fatal("Direct key Range", w.Code)
	}
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Relay", "Relay"
	if err = control.PrepareMasterResourcePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if err = control.ConfigureIngressSelectionReadiness(ctx, func(c context.Context) (node.IngressPrerequisiteLease, error) {
		return node.AcquireCatalogPrerequisite(c, ownerCoordinator.AcquireOwnerControlShared, tree)
	}); err != nil {
		t.Fatal(err)
	}
	lease, err = tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bound = store.WithIngressPrerequisite(verified, lease)
	relayDetails, relayHeaders, _, err := relay.IssueOpaqueMedia(bound, object, id, binding, session.SessionID)
	if err != nil {
		t.Fatal("issue Relay", err)
	}
	if _, _, _, err = direct.IssueOpaqueMedia(bound, object, id, binding, session.SessionID); err == nil {
		t.Fatal("Direct issued under Relay policy")
	}
	videoRelay, videoRelayHeaders, _, err := relay.IssueOpaqueMedia(bound, videoObject, videoID, binding, session.SessionID)
	if err != nil {
		t.Fatal("issue video Relay", err)
	}
	lease.Release()
	if w := request(relayDetails.Source, ingress.PublicOrigin, relayHeaders["X-Media-Relay"]); w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), ciphertext[1:5]) {
		t.Fatal("Relay range", w.Code, w.Body.String())
	}
	drainDeadline(relayDetails.Source, relayHeaders["X-Media-Relay"], "X-Media-Relay")
	if w := request(relayDetails.Source, ingress.PublicOrigin, headers["X-Media-Capability"]); w.Code != http.StatusForbidden {
		t.Fatal("Direct grant crossed into Relay", w.Code)
	}
	if w := request(videoRelay.Source, ingress.PublicOrigin, videoRelayHeaders["X-Media-Relay"]); w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), videoCipher[1:5]) {
		t.Fatal("video Relay range", w.Code)
	}
	keyRelay := playHiddenVideo("Relay", "X-Media-Relay")
	if s3Track != "" {
		grant := readLinkedLyric(s3Track, "Relay", "X-Media-Relay", true)
		setLinkedLyric(s3Track, "")
		if w := request(grant.SourceURL, ingress.PublicOrigin, grant.SourceHeaders["X-Media-Relay"]); w.Code != http.StatusForbidden {
			t.Fatalf("stale S3 lyric association still authorized bytes: %d", w.Code)
		}
	}
	setDisplayHidden(folderID, true)
	hiddenLyric := readLinkedLyric(id, "Relay", "X-Media-Relay", true)
	setLinkedLyric(id, "")
	if w := request(hiddenLyric.SourceURL, ingress.PublicOrigin, hiddenLyric.SourceHeaders["X-Media-Relay"]); w.Code != http.StatusForbidden {
		t.Fatalf("stale hidden track lyric association still authorized bytes: %d", w.Code)
	}
	if w := request(relayDetails.Source, ingress.PublicOrigin, relayHeaders["X-Media-Relay"]); w.Code != http.StatusPartialContent ||
		!bytes.Equal(w.Body.Bytes(), ciphertext[1:5]) {
		t.Fatal("existing Relay audio grant failed after ancestor display hide", w.Code)
	}
	setDisplayHidden(folderID, false)
	if w := publicCall("/api/v1/media/crypto/revoke", gin.H{}, cookie); w.Code != http.StatusOK {
		t.Fatal("hidden Relay video session revoke failed", w.Code)
	}
	if w := request(keyRelay.SourceURL, ingress.PublicOrigin, keyRelay.SourceHeaders["X-Media-Relay"]); w.Code != http.StatusForbidden {
		t.Fatal("revoked session still opened hidden Relay video", w.Code)
	}
	changed := append([]byte(nil), ciphertext...)
	changed[1] ^= 1
	if err = os.WriteFile(file, changed, 0600); err != nil {
		t.Fatal(err)
	}
	w := request(relayDetails.Source, ingress.PublicOrigin, relayHeaders["X-Media-Relay"])
	if w.Code != http.StatusPartialContent || bytes.Equal(w.Body.Bytes(), ciphertext[1:5]) {
		t.Fatal("ciphertext range not read", w.Code)
	}
	if decoded, e := aead.Open(nil, nonce, changed, metadata.ChunkAAD(0)); e == nil || len(decoded) != 0 {
		t.Fatal("tampered ciphertext authenticated")
	}
	public.crypto.RevokeBinding(binding)
	if w := request(relayDetails.Source, ingress.PublicOrigin, relayHeaders["X-Media-Relay"]); w.Code != http.StatusForbidden {
		t.Fatal("revoked session", w.Code)
	}
}
