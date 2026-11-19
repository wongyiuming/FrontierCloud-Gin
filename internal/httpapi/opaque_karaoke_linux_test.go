//go:build linux

package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestOpaqueKaraokeNativeIngress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	const masterOrigin, directOrigin = "https://example.com", "https://follower.test"
	router, db, dir, public, master := clusterFixture(t, masterOrigin, transport, true)
	_, _, _, _, direct := clusterFixture(t, directOrigin, transport, true)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	m, err := master.Promote(ctx, "Master", masterOrigin, 10*store.GiB, store.NodeAudit{})
	must(err)
	f, err := direct.Promote(ctx, "Follower", directOrigin, 0, store.NodeAudit{})
	must(err)
	must(direct.ConfigureFollowerIngressCandidate(directOrigin))
	pair, err := direct.CreatePair(ctx, store.NodeAudit{})
	must(err)
	relID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	must(err)
	relation, err := db.Nodes().Relationship(ctx, relID)
	must(err)
	must(master.Tick(ctx, relation))
	relation, err = db.Nodes().Relationship(ctx, relID)
	must(err)
	identity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
	must(err)
	routing := db.Nodes().(store.PublicRoutingRepository)
	initial, err := routing.PublicIngress(ctx)
	must(err)

	// A separate real sealed tree fixture supplies native placements and facts;
	// the Master business DB contains no legacy resource rows for these IDs.
	treeDir := t.TempDir()
	must(os.Chmod(treeDir, 0700))
	sqlite, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(treeDir, "tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	must(err)
	defer sqlite.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	must(err)
	rootID, musicID, lyricsID := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, sqlite, codec, rootID)
	must(err)
	root, err := os.OpenRoot(treeDir)
	must(err)
	defer root.Close()
	_, err = sealedtree.InitializeFence(ctx, tree, root, treeDir)
	must(err)
	_, err = sqlite.ExecContext(ctx, `CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT NOT NULL,role TEXT NOT NULL); CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`)
	must(err)
	_, err = sqlite.ExecContext(ctx, `INSERT INTO node_identity VALUES(1,?,'Master')`, m.ID)
	must(err)
	var playbackDDL string
	must(db.Database().QueryRowContext(ctx, `SELECT sql FROM sqlite_schema WHERE type='table' AND name='media_playback_events'`).Scan(&playbackDDL))
	_, err = sqlite.ExecContext(ctx, playbackDDL)
	must(err)
	masterAlbum, directAlbum := strings.Repeat("d", 64), strings.Repeat("e", 64)
	for _, entry := range []sealedtree.Entry{
		{ParentID: rootID, ObjectID: musicID, Kind: "directory", Name: "music"},
		{ParentID: rootID, ObjectID: lyricsID, Kind: "directory", Name: "lyrics"},
		{ParentID: musicID, ObjectID: masterAlbum, Kind: "directory", Name: "master-album"},
		{ParentID: musicID, ObjectID: directAlbum, Kind: "directory", Name: "direct-album"},
	} {
		must(tree.CreateDirectoryWithFacts(ctx, entry, sealedtree.Facts{ObjectID: entry.ObjectID}))
	}
	publisher, err := sealedtree.NewBlobPublisher(root)
	must(err)
	publish := func(id, owner, parent, kind, name, plain string) {
		t.Helper()
		metadata, err := mediacrypto.NewMetadata(int64(len(plain)))
		must(err)
		key, err := public.crypto.FileKey(metadata)
		must(err)
		block, err := aes.NewCipher(key)
		clear(key)
		must(err)
		aead, err := cipher.NewGCM(block)
		must(err)
		nonce, err := metadata.ChunkNonce(0)
		must(err)
		content := aead.Seal(nil, nonce, []byte(plain), metadata.ChunkAAD(0))
		sum := sha256.Sum256(content)
		placement := sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: owner, Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:]), State: "active", Encryption: &metadata}
		entry := sealedtree.Entry{ParentID: parent, ObjectID: id, Kind: kind, Name: name}
		pending, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, sealedtree.Facts{ObjectID: id})
		must(err)
		must(tree.PublishPending(ctx, pending.OperationID, publisher, bytes.NewReader(content)))
	}
	masterTrack, directTrack, lyric := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)
	publish(masterTrack, m.ID, masterAlbum, "audio", "master.mp3", "master audio")
	publish(directTrack, f.ID, directAlbum, "audio", "direct.mp3", "follower audio")
	publish(lyric, m.ID, lyricsID, "lyric", "track.lrc", "[00:01.00] sealed fixture lyric")
	setLyric := func(track, linked string, revision int64) {
		t.Helper()
		var targets []string
		if linked != "" {
			targets = []string{linked}
		}
		must(tree.ApplyNativeLyricBatch(ctx, sealedtree.NativeLyricOperation{OriginID: track, TargetIDs: targets, Changes: []sealedtree.NativeLyricChange{{TrackID: track, LyricID: linked, ExpectedFactsRevision: revision}}}, store.AdminAudit{}))
	}
	setLyric(masterTrack, lyric, 1)
	setLyric(directTrack, lyric, 1)
	s3Track, providerObject := addOpaqueS3LyricTrack(ctx, t, tree, musicID)
	if s3Track != "" {
		setLyric(s3Track, lyric, 1)
	}
	public.opaqueTree = tree
	public.ConfigureNetwork(master)
	ownerPath := filepath.Join(dir, "media")
	must(os.Chmod(ownerPath, 0700))
	must(os.Mkdir(filepath.Join(ownerPath, ".opaque-aliases"), 0700))
	ownerRoot, err := os.OpenRoot(ownerPath)
	must(err)
	defer ownerRoot.Close()
	ownerFence, err := ownerfence.Create(ownerRoot, ownerPath, identity)
	must(err)
	owners := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	must(owners.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return ownerFence.Acquire(c, exclusive)
	}))
	must(owners.InitializeOwnerControlMarker(ctx))
	must(master.ConfigureIngressSelectionReadiness(ctx, func(c context.Context) (node.IngressPrerequisiteLease, error) {
		return node.AcquireCatalogPrerequisite(c, owners.AcquireOwnerControlShared, tree)
	}))
	resolve, err := public.media.NativeCatalogOwnerResolver()
	must(err)
	preparer := &OpaqueCatalogPreparer{Router: router, Resolve: resolve, VerifyFacts: media.NativeCatalogFactsVerifier(tree)}
	resolver, err := network.New([]string{"172.21.0.0/24"})
	must(err)
	RegisterKaraokeMedia(router, public, resolver)
	masterTLS := httptest.NewTLSServer(router)
	defer masterTLS.Close()
	sendMaster := func(method, path string, body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, masterTLS.URL+path, bytes.NewReader(body))
		must(err)
		req.Host = "example.com"
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", masterOrigin)
		}
		resp, err := masterTLS.Client().Do(req)
		must(err)
		defer resp.Body.Close()
		response, err := io.ReadAll(resp.Body)
		must(err)
		return resp.StatusCode, response
	}
	getMaster := func(path string) (int, []byte) { return sendMaster(http.MethodGet, path, nil) }
	const playbackRoute = "/api/v1/media/playback"
	const localSession, directSession = "2775bcdc-9f7d-42b5-a3c3-c10caa131bee", "4886cddd-9f7d-42b5-a3c3-c10caa131bee"
	postPlayback := func(send func(string, string, []byte) (int, []byte), id, session string, seconds int) (int, []byte) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"media_path": "music/master-album/master.mp3", "resource_id": id, "playback_session_id": session, "played_seconds": seconds, "duration": 60})
		must(err)
		return send(http.MethodPost, playbackRoute, body)
	}
	assertPlayback := func(send func(string, string, []byte) (int, []byte), session string, score int64, counted bool) {
		t.Helper()
		code, body := postPlayback(send, masterTrack, session, 30)
		var result store.PlaybackResult
		if code != http.StatusOK || json.Unmarshal(body, &result) != nil || result.MediaID != masterTrack || result.PlayScore != score || result.Counted != counted || result.Threshold != 30 {
			t.Fatalf("sealed playback (want score %d, counted %t): %d %s", score, counted, code, body)
		}
	}
	if code, body := postPlayback(sendMaster, directTrack, localSession, 30); code != http.StatusBadRequest {
		t.Fatalf("playback path and resource mismatch: %d %s", code, body)
	}
	if code, body := postPlayback(sendMaster, masterTrack, localSession, 3); code != http.StatusBadRequest {
		t.Fatalf("playback below threshold: %d %s", code, body)
	}
	assertPlayback(sendMaster, localSession, 1, true)
	assertPlayback(sendMaster, localSession, 1, false)
	mediaPath := func(route, token string) string {
		return "/api/v1/karaoke/" + route + "?media=" + url.QueryEscape(token)
	}
	assertS3 := func(get func(string) (int, []byte), linked bool) {
		t.Helper()
		token, err := identity.KaraokeHandle(s3Track, true)
		must(err)
		code, body := get(mediaPath("context", token))
		var info struct {
			ResourceID string `json:"resource_id"`
			ObjectID   string `json:"object_id"`
			Transport  string `json:"transport"`
			LyricsURL  string `json:"lyrics_url"`
			HasLyrics  bool   `json:"has_lyrics"`
			Native     bool   `json:"native_source"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &info) != nil || info.ResourceID != s3Track || info.ObjectID != providerObject || info.Transport != "S3" || !info.HasLyrics || info.Native || info.LyricsURL != mediaPath("lyrics", token) {
			t.Fatalf("S3 karaoke context: %d %s", code, body)
		}
		query := url.Values{"track": {"music/s3.mp3"}, "resource_id": {s3Track}}
		for _, target := range []string{info.LyricsURL, "/api/v1/media/lyrics/content?" + query.Encode()} {
			code, body = get(target)
			var response struct {
				LyricID string             `json:"resource_id"`
				TrackID string             `json:"track_resource_id"`
				Entries []media.LyricEntry `json:"entries"`
			}
			if code != http.StatusOK || json.Unmarshal(body, &response) != nil {
				t.Fatalf("S3 lyric %s: %d %s", target, code, body)
			}
			if linked && (response.LyricID != lyric || response.TrackID != s3Track || len(response.Entries) != 0) ||
				!linked && (response.LyricID != "" || len(response.Entries) == 0) {
				t.Fatalf("S3 lyric %s (linked %t): %s", target, linked, body)
			}
		}
		query.Set("resource_id", providerObject)
		if code, _ = get("/api/v1/media/lyrics/content?" + query.Encode()); code != http.StatusServiceUnavailable {
			t.Fatalf("provider object ID authorized a lyric: %d", code)
		}
	}
	assertLinked := func(get func(string) (int, []byte), track, title string) string {
		t.Helper()
		token, err := identity.KaraokeHandle(track, true)
		must(err)
		code, body := get(mediaPath("context", token))
		var info struct {
			ResourceID string `json:"resource_id"`
			ObjectID   string `json:"object_id"`
			Title      string `json:"title"`
			LyricsURL  string `json:"lyrics_url"`
			HasLyrics  bool   `json:"has_lyrics"`
			Native     bool   `json:"native_source"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &info) != nil || info.ResourceID != track || info.ObjectID != track || info.Title != title || !info.HasLyrics || !info.Native || info.LyricsURL != mediaPath("lyrics", token) {
			t.Fatalf("native karaoke context: %d %s", code, body)
		}
		code, body = get(info.LyricsURL)
		var linked struct {
			ResourceID string `json:"resource_id"`
			TrackID    string `json:"track_resource_id"`
			Encrypted  bool   `json:"encrypted"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &linked) != nil || linked.ResourceID != lyric || linked.TrackID != track || !linked.Encrypted {
			t.Fatalf("native karaoke lyric: %d %s", code, body)
		}
		return token
	}
	assertInline := func(get func(string) (int, []byte), track, name string) {
		t.Helper()
		query := url.Values{"track": {name}, "resource_id": {track}}
		code, body := get("/api/v1/media/lyrics/content?" + query.Encode())
		var result struct {
			ResourceID string `json:"resource_id"`
			TrackID    string `json:"track_resource_id"`
			Encrypted  bool   `json:"encrypted"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &result) != nil ||
			result.ResourceID != lyric || result.TrackID != track || !result.Encrypted {
			t.Fatalf("exact inline lyric for hidden track: %d %s", code, body)
		}
	}
	hideAlbum := func(id string, hide bool) {
		t.Helper()
		facts, revision, err := tree.GetFacts(ctx, id)
		must(err)
		facts.Visibility = nil
		if hide {
			facts.Visibility = &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026"}
		}
		_, err = tree.SetFacts(ctx, facts, revision)
		must(err)
	}
	hideAlbum(masterAlbum, true)
	masterToken := assertLinked(getMaster, masterTrack, "master")
	assertInline(getMaster, masterTrack, "music/master-album/master.mp3")
	hideAlbum(masterAlbum, false)
	if s3Track != "" {
		assertS3(getMaster, true)
		_, s3Revision, err := tree.GetFacts(ctx, s3Track)
		must(err)
		setLyric(s3Track, "", s3Revision)
		assertS3(getMaster, false)
	}
	peerOnly, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: f.ID, Generation: initial.Generation, PublicOrigin: directOrigin, ClientIP: "192.0.2.1"})
	must(err)
	withoutAdmission := httptest.NewRequestWithContext(peerOnly, http.MethodGet, mediaPath("context", masterToken), nil)
	withoutAdmission.Host, withoutAdmission.RemoteAddr = "example.com", "172.21.0.2:12345"
	withoutAdmissionResult := httptest.NewRecorder()
	router.ServeHTTP(withoutAdmissionResult, withoutAdmission)
	if withoutAdmissionResult.Code != http.StatusForbidden {
		t.Fatalf("peer context without live admission: %d", withoutAdmissionResult.Code)
	}
	spoofedHTTPS := httptest.NewRequestWithContext(ctx, http.MethodGet, mediaPath("context", masterToken), nil)
	spoofedHTTPS.Host, spoofedHTTPS.RemoteAddr = "example.com", "192.0.2.3:12345"
	spoofedHTTPS.Header.Set("X-Forwarded-Proto", "https")
	spoofedHTTPS.Header.Set("X-Real-IP", "192.0.2.1")
	spoofedHTTPSResult := httptest.NewRecorder()
	router.ServeHTTP(spoofedHTTPSResult, spoofedHTTPS)
	if spoofedHTTPSResult.Code != http.StatusForbidden {
		t.Fatalf("untrusted local HTTPS forwarding: %d", spoofedHTTPSResult.Code)
	}
	if code, _ := getMaster(mediaPath("context", "invalid-token")); code != http.StatusServiceUnavailable {
		t.Fatalf("invalid handle: %d", code)
	}
	_, revision, err := tree.GetFacts(ctx, masterTrack)
	must(err)
	setLyric(masterTrack, "", revision)
	if code, body := getMaster(mediaPath("lyrics", masterToken)); code != http.StatusOK || !bytes.Contains(body, []byte(`"entries"`)) {
		t.Fatalf("authenticated no-lyric fallback: %d %s", code, body)
	}
	facts, revision, err := tree.GetFacts(ctx, masterTrack)
	must(err)
	facts.Visibility = &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026"}
	revision, err = tree.SetFacts(ctx, facts, revision)
	must(err)
	if code, _ := getMaster(mediaPath("context", masterToken)); code != http.StatusOK {
		t.Fatalf("hidden track context with proven fallback: %d", code)
	}
	if code, body := getMaster(mediaPath("lyrics", masterToken)); code != http.StatusOK || !bytes.Contains(body, []byte(`"entries"`)) {
		t.Fatalf("hidden track proven fallback: %d %s", code, body)
	}
	facts.Visibility = nil
	revision, err = tree.SetFacts(ctx, facts, revision)
	must(err)
	setLyric(masterTrack, lyric, revision)

	// Stub only the external resource readiness probe. Keep the saved policy,
	// runtime proof and real catalog/Owner/tree admission separate and intact.
	var probedIngress store.PublicIngress
	must(master.ConfigureMasterResourceReadiness(masterOrigin, func(c context.Context, ingress store.PublicIngress, mode, origin string) error {
		if mode != "Direct" || origin != masterOrigin {
			return store.ErrNodeState
		}
		probedIngress = ingress
		return c.Err()
	}))
	_, err = routing.ConfirmNativeTransport(ctx, m.ID, "Direct", 0, store.NodeAudit{})
	must(err)
	must(master.PrepareMasterResourcePolicy(ctx))
	evidence := store.PeerIngressEvidence{MemberID: f.ID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt, LastHeartbeat: relation.LastHeartbeat, PublicOrigin: directOrigin}
	selected, err := db.Nodes().(store.PeerIngressRepository).CommitPeerPublicIngress(ctx, evidence, initial.Generation, store.NodeAudit{})
	must(err)
	verifier, err := publicproxy.NewVerifier(publicproxy.VerifierConfig{MasterOrigin: masterOrigin, Authenticator: master, Current: master, EdgeResolver: resolver, CatalogPreparer: preparer})
	must(err)
	var attestHTTPS atomic.Bool
	attestHTTPS.Store(true)
	goEdge := http.StripPrefix(publicproxy.EdgePrefix, verifier.Wrap(router))
	// Model Nginx terminating the peer's real TLS connection before
	// forwarding to Go from a configured non-loopback Docker address.
	edge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		forwarded := req.Clone(req.Context())
		forwarded.TLS = nil
		forwarded.RemoteAddr = "172.21.0.2:12345"
		forwarded.Header.Set("X-Real-IP", "192.0.2.2")
		scheme := "http"
		if attestHTTPS.Load() {
			scheme = "https"
		}
		forwarded.Header.Set("X-Forwarded-Proto", scheme)
		goEdge.ServeHTTP(w, forwarded)
	}))
	defer edge.Close()
	roots := x509.NewCertPool()
	roots.AddCert(edge.Certificate())
	signer, err := direct.NewPublicIngressSigner(relID)
	must(err)
	proxy, err := publicproxy.New(publicproxy.Config{MasterOrigin: masterOrigin, PublicOrigin: directOrigin, RootCAs: roots, MasterEdge: true, Peer: &publicproxy.PeerConfig{NodeID: selected.NodeID, Generation: selected.Generation, Signer: catalogLoopbackSigner{PublicIngressSigner: signer, address: edge.Listener.Addr().String()}}})
	must(err)
	defer proxy.CloseIdleConnections()
	sendDirect := func(method, path string, body []byte) (int, []byte) {
		req := httptest.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
		req.Host, req.RemoteAddr, req.TLS = strings.TrimPrefix(directOrigin, "https://"), "192.0.2.1:12345", &tls.ConnectionState{}
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", directOrigin)
		}
		record := httptest.NewRecorder()
		proxy.ServeHTTP(opaqueProxyRecorder{record}, req)
		return record.Code, record.Body.Bytes()
	}
	getDirect := func(path string) (int, []byte) { return sendDirect(http.MethodGet, path, nil) }
	if code, body := postPlayback(sendMaster, masterTrack, directSession, 30); code != http.StatusServiceUnavailable {
		t.Fatalf("playback accepted on the inactive Master public origin: %d %s", code, body)
	}
	assertPlayback(sendDirect, localSession, 1, false)
	assertPlayback(sendDirect, directSession, 2, true)
	assertPlayback(sendDirect, directSession, 2, false)
	catalog := "/api/v1/media/catalog/media?media_type=music&path=music%2Fmaster-album&playback_session_id=fixture"
	if code, _ := getDirect(catalog); code != http.StatusServiceUnavailable {
		t.Fatalf("catalog accepted a Master policy from the old ingress: %d", code)
	}
	if code, _ := getDirect(mediaPath("context", masterToken)); code != http.StatusServiceUnavailable {
		t.Fatalf("Karaoke accepted a Master policy from the old ingress: %d", code)
	}
	must(master.PrepareMasterResourcePolicy(ctx))
	if probedIngress != selected {
		t.Fatal("Master resource proof is not bound to the selected ingress")
	}
	code, body := getDirect(catalog)
	var listing struct {
		Entries []media.Track `json:"entries"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &listing) != nil || len(listing.Entries) != 1 || listing.Entries[0].ResourceID != masterTrack || listing.Entries[0].Transport != "Direct" {
		t.Fatalf("peer catalog for a Master-owned album: %d %s", code, body)
	}
	attestHTTPS.Store(false)
	if code, _ := getDirect(mediaPath("context", masterToken)); code != http.StatusForbidden {
		t.Fatalf("peer forwarding without HTTPS attestation: %d", code)
	}
	attestHTTPS.Store(true)
	assertLinked(getDirect, masterTrack, "master")
	hideAlbum(directAlbum, true)
	directToken := assertLinked(getDirect, directTrack, "direct")
	assertInline(getDirect, directTrack, "music/direct-album/direct.mp3")
	hideAlbum(directAlbum, false)
	if s3Track != "" {
		assertS3(getDirect, false)
		_, s3Revision, err := tree.GetFacts(ctx, s3Track)
		must(err)
		setLyric(s3Track, lyric, s3Revision)
		assertS3(getDirect, true)
	}
	_, err = routing.CommitMasterPublicIngress(ctx, masterOrigin, selected.Generation, store.NodeAudit{})
	must(err)
	if code, body := getDirect(mediaPath("context", directToken)); code < 400 || bytes.Contains(body, []byte(directTrack)) {
		t.Fatalf("stale ingress published metadata: %d %s", code, body)
	}
	if code, body := postPlayback(sendDirect, masterTrack, "1775bcdc-9f7d-42b5-a3c3-c10caa131bee", 30); code < 400 {
		t.Fatalf("stale signed ingress counted playback: %d %s", code, body)
	}
	assertPlayback(sendMaster, directSession, 2, false)
}
