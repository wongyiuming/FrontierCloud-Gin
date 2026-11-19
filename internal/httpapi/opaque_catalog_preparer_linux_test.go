//go:build linux

package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type catalogLoopbackSigner struct {
	*node.PublicIngressSigner
	address string
}
type catalogSyntheticLease struct{ check func(context.Context) error }

func (l *catalogSyntheticLease) Check(ctx context.Context) error { return l.check(ctx) }
func (*catalogSyntheticLease) Release()                          {}
func (l *catalogSyntheticLease) Binding(ctx context.Context) (string, error) {
	if err := l.Check(ctx); err != nil {
		return "", err
	}
	return strings.Repeat("a", 64), nil
}

type catalogFixtureScope struct {
	lease      *sealedtree.TreeLease
	finalizers []func()
}

func (f catalogFixtureScope) Check(ctx context.Context) error { return f.lease.Check(ctx) }
func (f catalogFixtureScope) CheckCatalogScopes(ctx context.Context, tree *sealedtree.SQLStore, checks []sealedtree.CatalogScopeCheck) error {
	return tree.CheckCatalogScopesWithLease(ctx, f.lease, checks)
}
func (f *catalogFixtureScope) HoldCatalogResource(release func()) error {
	f.finalizers = append(f.finalizers, release)
	return nil
}
func (f *catalogFixtureScope) CancelCatalogAdmission() {}
func (f *catalogFixtureScope) finish() {
	for i := len(f.finalizers) - 1; i >= 0; i-- {
		f.finalizers[i]()
	}
	f.finalizers = nil
}

type catalogEvidenceLease struct {
	inner media.CatalogResourceLease
	valid *bool
}

func (l *catalogEvidenceLease) Check(ctx context.Context) error {
	if !*l.valid {
		return store.ErrNodeState
	}
	return l.inner.Check(ctx)
}
func (l *catalogEvidenceLease) Release() { l.inner.Release() }

type catalogPreparationBarrier struct {
	inner  *OpaqueCatalogPreparer
	ready  chan struct{}
	resume chan struct{}
}
type catalogPreparationTracking struct {
	inner *OpaqueCatalogPreparer
	calls atomic.Int32
}

func (p *catalogPreparationTracking) PrepareCatalog(r *http.Request) (publicproxy.PreparedCatalog, error) {
	p.calls.Add(1)
	return p.inner.PrepareCatalog(r)
}

func (b *catalogPreparationBarrier) PrepareCatalog(req *http.Request) (publicproxy.PreparedCatalog, error) {
	prepared, err := b.inner.PrepareCatalog(req)
	if err != nil {
		return prepared, err
	}
	close(b.ready)
	select {
	case <-b.resume:
		return prepared, nil
	case <-req.Context().Done():
		if prepared.Release != nil {
			prepared.Release()
		}
		return publicproxy.PreparedCatalog{}, req.Context().Err()
	}
}

func (s catalogLoopbackSigner) DialPublicIngress(ctx context.Context, _, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", s.address)
}

// Uses real Gin, Master identity and encrypted tree. Owner policy and the
// authenticated ingress assertion are synthetic, so this is not a full
// deployed ingress or a production readiness test.
func TestOpaqueCatalogPreparerUsesRealGinAndTree(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, masterDB, masterDir, public, master := clusterFixture(t, "https://example.com", transport, false)
	identity, err := master.Promote(ctx, "Master", "https://example.com", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, musicID, albumID := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, db, codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := sealedtree.InitializeFence(ctx, tree, root, dir); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []sealedtree.Entry{{ParentID: rootID, ObjectID: musicID, Kind: "directory", Name: "music"}, {ParentID: musicID, ObjectID: albumID, Kind: "directory", Name: "album"}} {
		if err := tree.CreateDirectoryWithFacts(ctx, entry, sealedtree.Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	emptySubdir := sealedtree.Entry{ParentID: albumID, ObjectID: strings.Repeat("ab", 32), Kind: "directory", Name: "empty-subdir"}
	if err := tree.CreateDirectoryWithFacts(ctx, emptySubdir, sealedtree.Facts{ObjectID: emptySubdir.ObjectID}); err != nil {
		t.Fatal(err)
	}
	pub, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(nil)
	nativeTrackIDs := []string{}
	for i, name := range []string{"z.mp3", "a.mp3", "hidden.mp3"} {
		id := strings.Repeat(string(rune('d'+i)), 64)
		nativeTrackIDs = append(nativeTrackIDs, id)
		facts := sealedtree.Facts{ObjectID: id, Playback: &sealedtree.PlaybackFact{LegacyMediaPath: "music/album/" + name, Preference: int64(5 - i), CreatedAt: "2026", UpdatedAt: "2026"}}
		if i == 2 {
			facts.Visibility = &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026"}
		}
		entry := sealedtree.Entry{ParentID: albumID, ObjectID: id, Kind: "audio", Name: name}
		placement := sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: identity.ID, Bytes: 0, SHA256: hex.EncodeToString(digest[:]), State: "active"}
		prepared, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, facts)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(nil)); err != nil {
			t.Fatal(err)
		}
	}
	nestedID := strings.Repeat("5a", 32)
	if err := tree.CreateDirectoryWithFacts(ctx, sealedtree.Entry{ParentID: musicID, ObjectID: nestedID, Kind: "directory", Name: "Nested"}, sealedtree.Facts{ObjectID: nestedID}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		childID := fmt.Sprintf("%064x", 1000+i)
		name := fmt.Sprintf("sub-%d", i)
		facts := sealedtree.Facts{ObjectID: childID, Playback: &sealedtree.PlaybackFact{LegacyMediaPath: "music/Nested/" + name, Preference: int64(8 - i), CreatedAt: "2026", UpdatedAt: "2026"}}
		if err := tree.CreateDirectoryWithFacts(ctx, sealedtree.Entry{ParentID: nestedID, ObjectID: childID, Kind: "directory", Name: name}, facts); err != nil {
			t.Fatal(err)
		}
		names := []string{"cover.mp3"}
		if i == 0 {
			names = []string{"cover.MP3", "skip.wav"}
		}
		if i == 6 {
			names = []string{"one.mp3", "two.mp3"}
		}
		if i == 7 {
			names = []string{"excluded.mp3"}
		}
		for j, trackName := range names {
			id := fmt.Sprintf("%064x", 2000+i*3+j)
			nativeTrackIDs = append(nativeTrackIDs, id)
			entry := sealedtree.Entry{ParentID: childID, ObjectID: id, Kind: "audio", Name: trackName}
			placement := sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: identity.ID, Bytes: 0, SHA256: hex.EncodeToString(digest[:]), State: "active"}
			op, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, sealedtree.Facts{ObjectID: id})
			if err != nil {
				t.Fatal(err)
			}
			if err := tree.PublishPending(ctx, op.OperationID, pub, bytes.NewReader(nil)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, group := range []struct {
		id, track, name string
		hidden          bool
		preference      int64
	}{
		{strings.Repeat("1", 64), strings.Repeat("3", 64), "Preferred", false, 10},
		{strings.Repeat("2", 64), strings.Repeat("4", 64), "HiddenAlbum", true, 0},
	} {
		facts := sealedtree.Facts{ObjectID: group.id, Playback: &sealedtree.PlaybackFact{LegacyMediaPath: "music/" + group.name, Preference: group.preference, CreatedAt: "2026", UpdatedAt: "2026"}}
		if group.hidden {
			facts.Visibility = &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026"}
		}
		if err := tree.CreateDirectoryWithFacts(ctx, sealedtree.Entry{ParentID: musicID, ObjectID: group.id, Kind: "directory", Name: group.name}, facts); err != nil {
			t.Fatal(err)
		}
		entry := sealedtree.Entry{ParentID: group.id, ObjectID: group.track, Kind: "audio", Name: "song.mp3"}
		placement := sealedtree.Placement{ObjectID: group.track, NativeObjectID: group.track, OwnerID: identity.ID, Bytes: 0, SHA256: hex.EncodeToString(digest[:]), State: "active"}
		op, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, sealedtree.Facts{ObjectID: group.track})
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.PublishPending(ctx, op.OperationID, pub, bytes.NewReader(nil)); err != nil {
			t.Fatal(err)
		}
		nativeTrackIDs = append(nativeTrackIDs, group.track)
	}
	s3Member := addCatalogS3Fixture(ctx, t, tree, albumID)
	var nativeVerifier media.CatalogFactsVerifier
	if s3Member == "" {
		for _, q := range []string{`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT NOT NULL,role TEXT NOT NULL)`, `CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`} {
			if _, err := db.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO node_identity VALUES(1,?,'Master')`, identity.ID); err != nil {
			t.Fatal(err)
		}
		for _, id := range nativeTrackIDs {
			if err := tree.ApplyNativeLyricBatch(ctx, sealedtree.NativeLyricOperation{OriginID: id, Changes: []sealedtree.NativeLyricChange{{TrackID: id, ExpectedFactsRevision: 1}}}, store.AdminAudit{}); err != nil {
				t.Fatal("native lyric fixture", err)
			}
		}
		nativeVerifier = media.NativeCatalogFactsVerifier(tree)
	}
	public.opaqueTree = tree
	validOwner := true
	validEvidence := true
	// Native-only fixture verifies real tree-keyed lyric evidence. The S3
	// mixed fixture still uses synthetic evidence and is not a production path.
	preparer := &OpaqueCatalogPreparer{Router: router, VerifyFacts: func(ctx context.Context, lease *sealedtree.TreeLease, items []sealedtree.CatalogItem) (media.CatalogResourceSnapshot, error) {
		if nativeVerifier != nil {
			snapshot, err := nativeVerifier(ctx, lease, items)
			if err != nil {
				return nil, err
			}
			return func(c context.Context, prerequisite store.IngressPrerequisite) (media.CatalogResourceLease, error) {
				inner, err := snapshot(c, prerequisite)
				if err != nil {
					return nil, err
				}
				return &catalogEvidenceLease{inner: inner, valid: &validEvidence}, nil
			}, nil
		}
		return func(context.Context, store.IngressPrerequisite) (media.CatalogResourceLease, error) {
			return &catalogSyntheticLease{check: func(context.Context) error {
				if !validEvidence {
					return store.ErrNodeState
				}
				return nil
			}}, nil
		}, lease.Check(ctx)
	}, Resolve: func(_ context.Context, owner string) (media.CatalogOwnerSnapshot, error) {
		if s3Member != "" && owner == s3Member {
			return media.CatalogOwnerSnapshot{Transport: "S3", Acquire: func(context.Context, store.IngressPrerequisite) (media.CatalogResourceLease, error) {
				return &catalogSyntheticLease{check: func(context.Context) error {
					if !validOwner {
						return store.ErrNodeState
					}
					return nil
				}}, nil
			}, CheckS3: func(p *sealedtree.S3Placement) error {
				expected := s3store.Config{Endpoint: "https://s3.us-east-1.amazonaws.com", Bucket: "fixture-private", Region: "us-east-1", Prefix: "managed", AddressStyle: "path"}
				if p == nil || !p.MatchesCurrentMember(s3Member, expected) {
					return store.ErrNodeState
				}
				return nil
			}}, nil
		}
		if owner != identity.ID {
			t.Fatal("unexpected owner")
		}
		return media.CatalogOwnerSnapshot{Transport: "Direct", Acquire: func(context.Context, store.IngressPrerequisite) (media.CatalogResourceLease, error) {
			return &catalogSyntheticLease{check: func(context.Context) error {
				if !validOwner {
					return store.ErrNodeState
				}
				return nil
			}}, nil
		}}, nil
	}}
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: strings.Repeat("1", 32), Generation: 1, PublicOrigin: "https://entry.test", ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(hidden bool) *http.Request {
		return httptest.NewRequest("GET", "https://entry.test/api/v1/media/catalog/media?media_type=music&path=music%2Falbum&playback_session_id=test&include_hidden="+strconv.FormatBool(hidden), nil).WithContext(verified)
	}
	missingVerifier := *preparer
	missingVerifier.VerifyFacts = nil
	if _, err := missingVerifier.PrepareCatalog(request(false)); err == nil {
		t.Fatal("missing source evidence verifier accepted")
	}
	categoryRequest := httptest.NewRequest("GET", "https://entry.test/api/v1/media/catalog/categories?media_type=music", nil).WithContext(verified)
	category, err := preparer.PrepareCatalog(categoryRequest)
	if err != nil {
		t.Fatal("tree categories", err)
	}
	defer category.Release()
	var categories struct {
		Entries []media.CategoryArtwork `json:"entries"`
	}
	if err := json.Unmarshal(category.Body, &categories); err != nil || len(categories.Entries) != 3 || categories.Entries[0].Name != "Preferred" || categories.Entries[1].Name != "album" || categories.Entries[2].Name != "Nested" {
		t.Fatal("tree categories", categories, err)
	}
	for _, tc := range []struct {
		path  string
		count int
	}{{"music%2FNested", 8}, {"music%2Falbum", 0}, {"music%2FHiddenAlbum", 0}} {
		req := httptest.NewRequest("GET", "https://entry.test/api/v1/media/catalog/categories?media_type=music&path="+tc.path, nil).WithContext(verified)
		prepared, e := preparer.PrepareCatalog(req)
		if e != nil {
			t.Fatal("subcategories", e)
		}
		var got struct {
			Entries []media.CategoryArtwork `json:"entries"`
		}
		if e = json.Unmarshal(prepared.Body, &got); e != nil || len(got.Entries) != tc.count {
			prepared.Release()
			t.Fatal("subcategories", tc.path, len(got.Entries), e)
		}
		prepared.Release()
	}
	for _, bad := range []string{"music%2Fmissing", "music%2FNested%2Fsub-0", "vido%2FNested"} {
		req := httptest.NewRequest("GET", "https://entry.test/api/v1/media/catalog/categories?media_type=music&path="+bad, nil).WithContext(verified)
		if result, e := preparer.PrepareCatalog(req); e == nil {
			result.Release()
			t.Fatal("inaccessible subcategory accepted", bad)
		}
	}
	knownHidden := httptest.NewRequest(http.MethodGet, "https://entry.test/api/v1/media/catalog/media?media_type=music&path=music%2FHiddenAlbum&playback_session_id=test", nil).WithContext(verified)
	hiddenAlbum, err := preparer.PrepareCatalog(knownHidden)
	if err != nil {
		t.Fatal("known hidden directory URL", err)
	}
	var hiddenTracks struct {
		Entries []media.Track `json:"entries"`
	}
	err = json.Unmarshal(hiddenAlbum.Body, &hiddenTracks)
	hiddenAlbum.Release()
	if err != nil || len(hiddenTracks.Entries) != 1 || hiddenTracks.Entries[0].MediaPath != "music/HiddenAlbum/song.mp3" {
		t.Fatal("known hidden directory did not return its exact media", err)
	}
	for _, tc := range []struct{ target, want string }{
		{"/api/v1/media/music/category?path=music%2FNested", "emptyRedirect"},
		{"/api/v1/media/music/category?path=music%2FNested%2Fsub-0", "frontierCloudPlayerCatalogConfig"},
		{"/api/v1/media/video/category?path=vido%2Fdirector&direct=true", "frontierCloudPlayerCatalogConfig"},
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", tc.target, nil).WithContext(verified))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatal("opaque category page", tc.target, w.Code)
		}
	}
	allCategoryRequest := httptest.NewRequest("GET", "https://entry.test/api/v1/media/catalog/categories?media_type=music&include_hidden=true", nil).WithContext(verified)
	allCategories, err := preparer.PrepareCatalog(allCategoryRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer allCategories.Release()
	if err := json.Unmarshal(allCategories.Body, &categories); err != nil || len(categories.Entries) != 4 || categories.Entries[0].Name != "Preferred" {
		t.Fatal("hidden category scope", categories, err)
	}
	nestedArtworkReq := httptest.NewRequest("GET", "https://entry.test/api/v1/media/catalog/artwork?path=music%2FNested", nil).WithContext(verified)
	nestedArtwork, err := preparer.PrepareCatalog(nestedArtworkReq)
	if err != nil {
		t.Fatal("nested artwork", err)
	}
	defer nestedArtwork.Release()
	var nestedResult media.CategoryArtwork
	if err := json.Unmarshal(nestedArtwork.Body, &nestedResult); err != nil || len(nestedResult.MetadataTracks) != 8 {
		t.Fatal("nested shared budget", len(nestedResult.MetadataTracks), err)
	}
	uppercase := false
	for _, track := range nestedResult.MetadataTracks {
		if strings.Contains(track.MediaPath, "sub-7/") || strings.HasSuffix(strings.ToLower(track.MediaPath), ".wav") {
			t.Fatal("nested bound/filter", track.MediaPath)
		}
		uppercase = uppercase || strings.HasSuffix(track.MediaPath, ".MP3")
	}
	if !uppercase {
		t.Fatal("uppercase MP3 omitted")
	}
	result, err := preparer.PrepareCatalog(request(false))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Release()
	var decoded struct {
		Entries []media.Track `json:"entries"`
	}
	visibleCount := 2
	if s3Member != "" {
		visibleCount++
	}
	if err := json.Unmarshal(result.Body, &decoded); err != nil || len(decoded.Entries) != visibleCount || decoded.Entries[0].Title != "z" || decoded.Entries[0].Transport != "Direct" {
		t.Fatal("visible order/offline owner", decoded, err)
	}
	if nativeVerifier != nil && (decoded.Entries[0].HasLyrics == nil || !*decoded.Entries[0].HasLyrics) {
		t.Fatal("native default lyric relation lost")
	}
	if s3Member != "" {
		found := false
		for _, entry := range decoded.Entries {
			if entry.Transport == "S3" {
				found = true
				if entry.NativeSource || entry.ObjectID != strings.Repeat("6", 64) {
					t.Fatal("S3 treated as native", entry)
				}
			}
		}
		if !found || strings.Contains(string(result.Body), "private-provider-key") {
			t.Fatal("S3 mixed listing missing or leaked provider key")
		}
	}
	all, err := preparer.PrepareCatalog(request(true))
	if err != nil {
		t.Fatal(err)
	}
	defer all.Release()
	if err := json.Unmarshal(all.Body, &decoded); err != nil || len(decoded.Entries) != visibleCount+1 {
		t.Fatal("include hidden", err)
	}
	// Synthetic loopback dialing, but real TLS certificate validation, paired
	// node HMAC/nonce verification, Gin handler, Master final admission and
	// encrypted tree. The selected ingress repository itself is a fixture.
	_, _, _, _, follower := clusterFixture(t, "https://follower.test", transport, true)
	followerID, err := follower.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	masterIdentity, err := node.Initialize(ctx, masterDB.Nodes(), filepath.Join(masterDir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	ingress := store.PublicIngress{NodeID: followerID.ID, Generation: 1, PublicOrigin: "https://entry.test"}
	routing := &localIngressRouting{masterDirectHTTPRouting: &masterDirectHTTPRouting{selectedIngressRepository: selectedIngressRepository{NodeRepository: masterDB.Nodes(), PublicRoutingRepository: masterDB.Nodes().(store.PublicRoutingRepository), selected: ingress}}}
	routing.state.Store(&ingress)
	control := node.NewService(routing, masterIdentity, transport)
	acquireComposite := func(c context.Context) (node.IngressPrerequisiteLease, error) {
		return node.AcquireCatalogPrerequisite(c, func(context.Context) (store.OwnerControlLease, error) {
			return &catalogSyntheticLease{check: func(context.Context) error { return nil }}, nil
		}, tree)
	}
	if err := control.ConfigureIngressSelectionReadiness(ctx, acquireComposite); err != nil {
		t.Fatal(err)
	}
	var handler atomic.Value
	var edgePath, strippedPath, ginPath atomic.Value
	var ginCalls atomic.Int32
	preparer.Router = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ginPath.Store(r.URL.Path)
		ginCalls.Add(1)
		router.ServeHTTP(w, r)
	})
	tracked := &catalogPreparationTracking{inner: preparer}
	edge := http.StripPrefix(publicproxy.EdgePrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strippedPath.Store(r.URL.Path)
		handler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { edgePath.Store(r.URL.Path); edge.ServeHTTP(w, r) }))
	defer server.Close()
	verifier, err := publicproxy.NewVerifier(publicproxy.VerifierConfig{MasterOrigin: "https://example.com", Authenticator: control, Current: control, CatalogPreparer: tracked})
	if err != nil {
		t.Fatal(err)
	}
	handler.Store(verifier.Wrap(router))
	signer, err := follower.NewPublicIngressSigner(relID)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	proxy, err := publicproxy.New(publicproxy.Config{MasterOrigin: "https://example.com", PublicOrigin: ingress.PublicOrigin, RootCAs: roots, MasterEdge: true, Peer: &publicproxy.PeerConfig{NodeID: ingress.NodeID, Generation: ingress.Generation, Signer: catalogLoopbackSigner{PublicIngressSigner: signer, address: server.Listener.Addr().String()}}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.CloseIdleConnections()
	proxyReq := httptest.NewRequest("GET", "/api/v1/media/catalog/media?media_type=music&path=music%2Falbum&playback_session_id=test", nil)
	proxyReq.Host, proxyReq.RemoteAddr, proxyReq.TLS = "entry.test", "192.0.2.1:12345", &tls.ConnectionState{}
	response := httptest.NewRecorder()
	proxy.ServeHTTP(opaqueProxyRecorder{response}, proxyReq)
	t.Logf("catalog_route_trace peer_path=%q master_edge=%t tls_edge_path=%v verifier_path=%v verifier_preparer_calls=%d gin_path=%v gin_calls=%d status=%d", proxyReq.URL.Path, true, edgePath.Load(), strippedPath.Load(), tracked.calls.Load(), ginPath.Load(), ginCalls.Load(), response.Code)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "z.mp3") || strings.Contains(response.Body.String(), "hidden.mp3") {
		t.Fatal("paired TLS tree catalog", response.Code, response.Body.String())
	}
	// Direct verifier listener is a separate supported test topology; real
	// Master Nginx + masterIngressEdge instead require MasterEdge=true.
	directServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.Load().(http.Handler).ServeHTTP(w, r) }))
	defer directServer.Close()
	directRoots := x509.NewCertPool()
	directRoots.AddCert(directServer.Certificate())
	directProxy, err := publicproxy.New(publicproxy.Config{MasterOrigin: "https://example.com", PublicOrigin: ingress.PublicOrigin, RootCAs: directRoots, MasterEdge: false, Peer: &publicproxy.PeerConfig{NodeID: ingress.NodeID, Generation: ingress.Generation, Signer: catalogLoopbackSigner{PublicIngressSigner: signer, address: directServer.Listener.Addr().String()}}})
	if err != nil {
		t.Fatal(err)
	}
	defer directProxy.CloseIdleConnections()
	directReq := httptest.NewRequest("GET", "/api/v1/media/catalog/media?media_type=music&path=music%2Falbum&playback_session_id=test", nil)
	directReq.Host, directReq.RemoteAddr, directReq.TLS = "entry.test", "192.0.2.1:12345", &tls.ConnectionState{}
	directResponse := httptest.NewRecorder()
	directProxy.ServeHTTP(opaqueProxyRecorder{directResponse}, directReq)
	if directResponse.Code != 200 || !strings.Contains(directResponse.Body.String(), "z.mp3") {
		t.Fatal("direct verifier tree catalog", directResponse.Code, directResponse.Body.String())
	}
	proxyCategories := httptest.NewRequest("GET", "/api/v1/media/catalog/categories?media_type=music", nil)
	proxyCategories.Host, proxyCategories.RemoteAddr, proxyCategories.TLS = "entry.test", "192.0.2.1:12345", &tls.ConnectionState{}
	categoryResponse := httptest.NewRecorder()
	proxy.ServeHTTP(opaqueProxyRecorder{categoryResponse}, proxyCategories)
	if categoryResponse.Code != 200 || !strings.Contains(categoryResponse.Body.String(), "album") {
		t.Fatal("paired TLS tree categories", categoryResponse.Code, categoryResponse.Body.String())
	}
	peerSubcategories := httptest.NewRequest("GET", "/api/v1/media/catalog/categories?media_type=music&path=music%2FNested", nil)
	peerSubcategories.Host, peerSubcategories.RemoteAddr, peerSubcategories.TLS = "entry.test", "192.0.2.1:12345", &tls.ConnectionState{}
	peerSubcategoryResponse := httptest.NewRecorder()
	proxy.ServeHTTP(opaqueProxyRecorder{peerSubcategoryResponse}, peerSubcategories)
	if peerSubcategoryResponse.Code != 200 || !strings.Contains(peerSubcategoryResponse.Body.String(), "sub-0") {
		t.Fatal("paired TLS tree subcategories", peerSubcategoryResponse.Code)
	}
	peerArtwork := httptest.NewRequest("GET", "/api/v1/media/catalog/artwork?path=music%2Falbum", nil)
	peerArtwork.Host, peerArtwork.RemoteAddr, peerArtwork.TLS = "entry.test", "192.0.2.1:12345", &tls.ConnectionState{}
	artworkResponse := httptest.NewRecorder()
	proxy.ServeHTTP(opaqueProxyRecorder{artworkResponse}, peerArtwork)
	if artworkResponse.Code != 200 || !strings.Contains(artworkResponse.Body.String(), "z.mp3") || strings.Contains(artworkResponse.Body.String(), "private-provider-key") {
		t.Fatal("paired TLS tree artwork", artworkResponse.Code, artworkResponse.Body.String())
	}
	// Initialize the default while no Owner/tree prerequisite is held. Once
	// readiness is installed, admission deliberately never performs lazy writes.
	if err := master.ConfigurePublicOrigin("https://example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := masterDB.Nodes().(store.PublicRoutingRepository).PublicIngress(ctx); err != nil {
		t.Fatal(err)
	}
	if err := master.ConfigureIngressSelectionReadiness(ctx, acquireComposite); err != nil {
		t.Fatal(err)
	}
	public.ConfigureNetwork(master)
	public.localCatalogPreparer = preparer // Explicitly installed only in this synthetic fixture.
	localReq := httptest.NewRequest("GET", "https://example.com/api/v1/media/catalog/media?media_type=music&path=music%2Falbum&playback_session_id=test", nil)
	localReq.Host, localReq.TLS = "example.com", &tls.ConnectionState{}
	observedIdentity, identityErr := public.media.IdentityState(ctx)
	observedIngress, observedLease, ingressErr := master.AcquireCurrentIngress(ctx)
	if observedLease != nil {
		observedLease.Release()
	}
	t.Logf("catalog_local_trace tls=%t host=%q identity_role=%q identity_matches_ingress=%t ingress_node=%q ingress_origin=%q ingress_generation=%d identity_error=%t ingress_error=%t", localReq.TLS != nil, localReq.Host, observedIdentity.Role, observedIdentity.ID == observedIngress.NodeID, observedIngress.NodeID, observedIngress.PublicOrigin, observedIngress.Generation, identityErr != nil, ingressErr != nil)
	localResponse := httptest.NewRecorder()
	router.ServeHTTP(localResponse, localReq)
	if localResponse.Code != 200 || !strings.Contains(localResponse.Body.String(), "z.mp3") {
		t.Fatal("Master local tree catalog", localResponse.Code, localResponse.Body.String())
	}
	localCategoryReq := httptest.NewRequest("GET", "https://example.com/api/v1/media/catalog/categories?media_type=music", nil)
	localCategoryReq.Host, localCategoryReq.TLS = "example.com", &tls.ConnectionState{}
	localCategoryResponse := httptest.NewRecorder()
	router.ServeHTTP(localCategoryResponse, localCategoryReq)
	if localCategoryResponse.Code != 200 || !strings.Contains(localCategoryResponse.Body.String(), "album") {
		t.Fatal("Master local tree categories", localCategoryResponse.Code, localCategoryResponse.Body.String())
	}
	localArtwork := httptest.NewRequest("GET", "https://example.com/api/v1/media/catalog/artwork?path=music%2Falbum", nil)
	localArtwork.Host, localArtwork.TLS = "example.com", &tls.ConnectionState{}
	localArtworkResponse := httptest.NewRecorder()
	router.ServeHTTP(localArtworkResponse, localArtwork)
	if localArtworkResponse.Code != 200 || !strings.Contains(localArtworkResponse.Body.String(), "z.mp3") {
		t.Fatal("Master local tree artwork", localArtworkResponse.Code, localArtworkResponse.Body.String())
	}
	unsafeReq := localReq.Clone(ctx)
	unsafeReq.TLS = nil
	unsafeReq.RemoteAddr = "192.0.2.1:12345"
	unsafeReq.Header.Set("X-Forwarded-Proto", "https")
	unsafeResponse := httptest.NewRecorder()
	router.ServeHTTP(unsafeResponse, unsafeReq)
	if unsafeResponse.Code != http.StatusForbidden {
		t.Fatal("untrusted forwarded proto accepted", unsafeResponse.Code)
	}
	public.ConfigureNetwork(control) // Fixture currently selects the peer.
	wrongIngress := httptest.NewRecorder()
	router.ServeHTTP(wrongIngress, localReq)
	if wrongIngress.Code != http.StatusForbidden {
		t.Fatal("Master served when not ingress", wrongIngress.Code)
	}
	public.ConfigureNetwork(master)
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	authority := &catalogFixtureScope{lease: lease}
	if err := result.CheckScope(ctx, authority); err != nil {
		t.Fatal("initial scope", err)
	}
	authority.finish()
	result, err = preparer.PrepareCatalog(request(false))
	if err != nil {
		t.Fatal(err)
	}
	validEvidence = false
	if err := result.CheckScope(ctx, authority); err == nil {
		t.Fatal("changed evidence accepted")
	}
	authority.finish()
	validEvidence = true
	result, err = preparer.PrepareCatalog(request(false))
	if err != nil {
		t.Fatal(err)
	}
	validOwner = false
	if err := result.CheckScope(ctx, authority); err == nil {
		t.Fatal("changed owner policy accepted")
	}
	authority.finish()
	validOwner = true
	lease.Release()
	result, err = preparer.PrepareCatalog(request(false))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Release()
	barrier := &catalogPreparationBarrier{inner: preparer, ready: make(chan struct{}), resume: make(chan struct{})}
	blockedVerifier, err := publicproxy.NewVerifier(publicproxy.VerifierConfig{MasterOrigin: "https://example.com", Authenticator: control, Current: control, CatalogPreparer: barrier})
	if err != nil {
		t.Fatal(err)
	}
	handler.Store(blockedVerifier.Wrap(router))
	blockedResponse := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("GET", "/api/v1/media/catalog/media?media_type=music&path=music%2Falbum&playback_session_id=test", nil)
		r.Host, r.RemoteAddr, r.TLS = "entry.test", "192.0.2.1:12345", &tls.ConnectionState{}
		w := httptest.NewRecorder()
		proxy.ServeHTTP(opaqueProxyRecorder{w}, r)
		blockedResponse <- w
	}()
	select {
	case <-barrier.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("preparation barrier not reached")
	}
	child := strings.Repeat("9", 64)
	if err := tree.CreateDirectoryWithFacts(ctx, sealedtree.Entry{ParentID: albumID, ObjectID: child, Kind: "directory", Name: "changed"}, sealedtree.Facts{ObjectID: child}); err != nil {
		t.Fatal(err)
	}
	close(barrier.resume)
	select {
	case w := <-blockedResponse:
		if w.Code == 200 || strings.Contains(w.Body.String(), "z.mp3") {
			t.Fatal("changed scope leaked prepared catalog", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("catalog final admission hung")
	}
	lease, err = tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	authority = &catalogFixtureScope{lease: lease}
	if err := result.CheckScope(ctx, authority); err == nil {
		t.Fatal("changed directory scope accepted")
	}
	if err := category.CheckScope(ctx, authority); err == nil {
		t.Fatal("changed category descendant scope accepted")
	}
	authority.finish()
	result.Release()
	if err := result.CheckScope(ctx, authority); err == nil {
		t.Fatal("released catalog fence reused")
	}
}
