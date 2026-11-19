//go:build linux

package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestOpaqueMasterLocalMediaThroughGin(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, db, dir, public, original := clusterFixture(t, "https://master.test", transport, false)
	plain := []byte("ID3 synthetic Master-owned audio")
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
	type item struct {
		name        string
		data        []byte
		encryption  *mediacrypto.Metadata
		row         store.GlobalMedia
		blob, alias string
	}
	firstMetadata, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	firstKey, err := public.crypto.FileKey(firstMetadata)
	if err != nil {
		t.Fatal(err)
	}
	firstBlock, err := aes.NewCipher(firstKey)
	if err != nil {
		t.Fatal(err)
	}
	firstAEAD, err := cipher.NewGCM(firstBlock)
	if err != nil {
		t.Fatal(err)
	}
	firstNonce, err := firstMetadata.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	firstCiphertext := firstAEAD.Seal(nil, firstNonce, plain, firstMetadata.ChunkAAD(0))
	items := []item{{name: "master-local.mp3", data: firstCiphertext, encryption: &firstMetadata}, {name: "master-local-encrypted.mp3", data: ciphertext, encryption: &metadata}, {name: "master-empty.mp3", data: []byte{}}}
	for i := range items {
		if len(items[i].data) == 0 {
			// Historical files may be empty even though new uploads reject them.
			path := filepath.Join(dir, "media", "music", "artist", items[i].name)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: "music/artist/" + items[i].name, Kind: "audio"}}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		stage, err := public.media.Stage(ctx, bytes.NewReader(items[i].data), int64(len(items[i].data)))
		if err != nil {
			t.Fatal(err)
		}
		_, err = public.media.PublishEncrypted(ctx, stage, items[i].name, "music/artist", "", false, 255, store.AdminAudit{}, items[i].encryption)
		stage.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	identity, err := original.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	treeDB, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "local-tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer treeDB.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, musicID, albumID := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, treeDB, codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	privateDir := t.TempDir()
	if err := os.Chmod(privateDir, 0700); err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(privateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	if _, err := sealedtree.InitializeFence(ctx, tree, treeRoot, privateDir); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []sealedtree.Entry{{ParentID: rootID, ObjectID: musicID, Kind: "directory", Name: "music"}, {ParentID: musicID, ObjectID: albumID, Kind: "directory", Name: "artist"}} {
		if err := tree.CreateDirectoryWithFacts(ctx, entry, sealedtree.Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	publisher, err := sealedtree.NewBlobPublisher(treeRoot)
	if err != nil {
		t.Fatal(err)
	}
	for i := range items {
		rows, err := db.Pool().Resources(ctx, "music/artist/"+items[i].name, true)
		if err != nil || len(rows) != 1 || rows[0].MemberID != identity.ID {
			t.Fatal("Master placement", err)
		}
		items[i].row = rows[0]
		sum := sha256.Sum256(items[i].data)
		placement := sealedtree.Placement{ObjectID: rows[0].ID, NativeObjectID: rows[0].ObjectID, OwnerID: identity.ID, Bytes: rows[0].Bytes, ETag: rows[0].ETag, SHA256: hex.EncodeToString(sum[:]), State: "active", Encryption: items[i].encryption}
		prepared, err := tree.PrepareFileWithFreshLocators(ctx, sealedtree.Entry{ParentID: albumID, ObjectID: rows[0].ID, Kind: "audio", Name: items[i].name}, placement, sealedtree.Facts{ObjectID: rows[0].ID})
		if err != nil {
			t.Fatal(err)
		}
		items[i].blob, items[i].alias = prepared.BlobID, prepared.ReadAlias
		if err := tree.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(items[i].data)); err != nil {
			t.Fatal(err)
		}
		blobPath, err := sealedtree.BlobPath(prepared.BlobID)
		if err != nil {
			t.Fatal(err)
		}
		physical := filepath.Join(dir, "media", filepath.FromSlash(blobPath))
		if err := os.MkdirAll(filepath.Dir(physical), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(physical, items[i].data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ingress := store.PublicIngress{NodeID: identity.ID, PublicOrigin: "https://master.test", Generation: 4}
	routing := &localIngressRouting{masterDirectHTTPRouting: &masterDirectHTTPRouting{selectedIngressRepository: selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: ingress}}}
	routing.state.Store(&ingress)
	identityCodec, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	control := node.NewService(routing, identityCodec, nil) // no network transport
	if err := control.ConfigureIngressSelectionReadiness(ctx, func(ctx context.Context) (node.IngressPrerequisiteLease, error) {
		return node.AcquireCatalogPrerequisite(ctx, func(context.Context) (store.OwnerControlLease, error) {
			return &catalogSyntheticLease{check: func(context.Context) error { return nil }}, nil
		}, tree)
	}); err != nil {
		t.Fatal(err)
	}
	public.media.ConfigureCluster(routing, db.Pool(), control)
	public.control, public.opaqueTree = control, tree
	reader, err := RegisterOpaqueMasterLocalMedia(router, public.settings, ingress.PublicOrigin, public.media, control, public.crypto, tree)
	if err != nil {
		t.Fatal(err)
	}
	public.masterLocalMedia = reader
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, target string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		r := httptest.NewRequest(method, ingress.PublicOrigin+target, bytes.NewReader(raw))
		r.Header.Set("Origin", ingress.PublicOrigin)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(masterDirectRecorder{w}, r)
		return w
	}
	sessionResponse := call(http.MethodPost, "/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, nil)
	var session mediacrypto.SessionGrant
	if sessionResponse.Code != http.StatusOK || json.Unmarshal(sessionResponse.Body.Bytes(), &session) != nil || len(sessionResponse.Result().Cookies()) != 1 {
		t.Fatal("session", sessionResponse.Code, sessionResponse.Body.String())
	}
	public.masterLocalMedia = nil
	blocked := call(http.MethodPost, "/api/v1/media/crypto/key", gin.H{"session_id": session.SessionID, "file_path": items[0].row.Path, "resource_id": items[0].row.ID, "object_id": items[0].row.ObjectID}, sessionResponse.Result().Cookies()[0])
	if blocked.Code != http.StatusServiceUnavailable {
		t.Fatal("missing Local reader authorized", blocked.Code)
	}
	public.masterLocalMedia = reader
	var grants []string
	for _, item := range items {
		target := "/api/v1/media/crypto/native/source"
		if item.encryption != nil {
			target = "/api/v1/media/crypto/key"
		}
		response := call(http.MethodPost, target, gin.H{"session_id": session.SessionID, "file_path": item.row.Path, "resource_id": item.row.ID, "object_id": item.row.ObjectID}, sessionResponse.Result().Cookies()[0])
		if item.encryption == nil {
			if response.Code != http.StatusServiceUnavailable {
				t.Fatal("unencrypted Local source admitted", response.Code)
			}
			grants = append(grants, "")
			continue
		}
		var plan struct {
			Transport string            `json:"source_transport"`
			Alias     string            `json:"source_object_id"`
			URL       string            `json:"source_url"`
			Headers   map[string]string `json:"source_headers"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &plan) != nil || plan.Transport != "Local" || plan.Alias != item.alias || plan.URL != ingress.PublicOrigin+"/api/v1/media/master-local/"+item.alias || plan.Headers["X-Media-Capability"] == "" {
			t.Fatal("Local source", response.Code, response.Body.String())
		}
		grants = append(grants, plan.Headers["X-Media-Capability"])
		r := httptest.NewRequest(http.MethodGet, plan.URL, nil)
		r.Header.Set("Origin", ingress.PublicOrigin)
		r.Header.Set("Range", "bytes=1-4")
		r.Header.Set("X-Media-Capability", grants[len(grants)-1])
		w := httptest.NewRecorder()
		router.ServeHTTP(masterDirectRecorder{w}, r)
		if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), item.data[1:5]) {
			t.Fatal("Local range", w.Code, w.Body.String())
		}
	}
	// The encrypted browser path avoids a full scan but must never return
	// unauthenticated plaintext or relax full-file reads.
	cipherPath, err := sealedtree.BlobPath(items[1].blob)
	if err != nil {
		t.Fatal(err)
	}
	cipherFile := filepath.Join(dir, "media", filepath.FromSlash(cipherPath))
	changedCipher := append([]byte(nil), items[1].data...)
	changedCipher[1] ^= 1
	if err = os.WriteFile(cipherFile, changedCipher, 0600); err != nil {
		t.Fatal(err)
	}
	localCipherRequest := func(token, byteRange string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, ingress.PublicOrigin+"/api/v1/media/master-local/"+items[1].alias, nil)
		r.Header.Set("Origin", ingress.PublicOrigin)
		r.Header.Set("X-Media-Capability", token)
		if byteRange != "" {
			r.Header.Set("Range", byteRange)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(masterDirectRecorder{w}, r)
		return w
	}
	cipherRange := "bytes=0-" + strconv.Itoa(len(changedCipher)-1)
	cipherResponse := localCipherRequest(grants[1], cipherRange)
	if cipherResponse.Code != http.StatusPartialContent || cipherResponse.Body.Len() != len(changedCipher) {
		t.Fatal("Local encrypted range", cipherResponse.Code)
	}
	if decoded, err := aead.Open(nil, nonce, cipherResponse.Body.Bytes(), metadata.ChunkAAD(0)); err == nil || len(decoded) != 0 {
		t.Fatal("changed Local ciphertext authenticated")
	}
	if response := localCipherRequest(grants[0], cipherRange); response.Code != http.StatusForbidden {
		t.Fatal("different object capability admitted", response.Code)
	}
	if response := localCipherRequest(grants[1], ""); response.Code != http.StatusForbidden || bytes.Equal(response.Body.Bytes(), changedCipher) {
		t.Fatal("whole-file server read bypassed verification", response.Code)
	}
	setAlbumHidden := func(hidden bool) {
		t.Helper()
		facts, revision, err := tree.GetFacts(ctx, albumID)
		if err != nil {
			t.Fatal(err)
		}
		value := int64(0)
		if hidden {
			value = 1
		}
		facts.Visibility = &sealedtree.VisibilityFact{Hidden: value, UpdatedAt: "2026-01-01"}
		if _, err := tree.SetFacts(ctx, facts, revision); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(cipherFile, items[1].data, 0600); err != nil {
		t.Fatal(err)
	}
	setAlbumHidden(true)
	if response := localCipherRequest(grants[1], cipherRange); response.Code != http.StatusPartialContent ||
		!bytes.Equal(response.Body.Bytes(), items[1].data) {
		t.Fatal("existing encrypted range grant failed after display hide", response.Code)
	}
	if response := localCipherRequest(grants[1], ""); response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), items[1].data) {
		t.Fatal("exact authenticated whole-object read failed after display hide", response.Code)
	}
	setAlbumHidden(false)
	anonymous := httptest.NewRequest(http.MethodGet, ingress.PublicOrigin+"/api/v1/media/master-local/"+items[0].alias, nil)
	anonymousResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{anonymousResponse}, anonymous)
	if anonymousResponse.Code == http.StatusOK || bytes.Contains(anonymousResponse.Body.Bytes(), items[0].data) {
		t.Fatal("anonymous composite request exposed bytes", anonymousResponse.Code)
	}
	failedCommit := httptest.NewRequest(http.MethodGet, ingress.PublicOrigin+"/api/v1/media/master-local/"+items[0].alias, nil)
	failedCommit.Header.Set("X-Media-Capability", grants[0])
	routing.failCommit.Store(true)
	failedResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{failedResponse}, failedCommit)
	routing.failCommit.Store(false)
	if failedResponse.Code != http.StatusServiceUnavailable || bytes.Contains(failedResponse.Body.Bytes(), items[0].data) {
		t.Fatal("failed composite commit exposed bytes", failedResponse.Code)
	}
	cancelled, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	cancelledRequest := httptest.NewRequest(http.MethodGet, ingress.PublicOrigin+"/api/v1/media/master-local/"+items[0].alias, nil).WithContext(cancelled)
	cancelledRequest.Header.Set("X-Media-Capability", grants[0])
	cancelledResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{cancelledResponse}, cancelledRequest)
	if cancelledResponse.Code == http.StatusOK || bytes.Contains(cancelledResponse.Body.Bytes(), items[0].data) {
		t.Fatal("cancelled composite request exposed bytes", cancelledResponse.Code)
	}
	queryRequest := httptest.NewRequest(http.MethodGet, ingress.PublicOrigin+"/api/v1/media/master-local/"+items[0].alias+"?token="+grants[0], nil)
	queryRequest.Header.Set("X-Media-Capability", grants[0])
	queryResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{queryResponse}, queryRequest)
	if queryResponse.Code != http.StatusForbidden || queryResponse.Header().Get("Location") != "" || strings.Contains(queryResponse.Body.String(), grants[0]) {
		t.Fatal("Local capability accepted or disclosed in query", queryResponse.Code)
	}
	rows, err := treeDB.Query(`SELECT object_index,sealed FROM sealed_tree_placements ORDER BY object_index`)
	if err != nil {
		t.Fatal(err)
	}
	type sealedRow struct {
		index string
		value []byte
	}
	var placements []sealedRow
	for rows.Next() {
		var row sealedRow
		if err := rows.Scan(&row.index, &row.value); err != nil {
			t.Fatal(err)
		}
		placements = append(placements, row)
	}
	if err := rows.Close(); err != nil || len(placements) != len(items) {
		t.Fatal("placement fixture", err, len(placements))
	}
	for i := range placements {
		if _, err := treeDB.Exec(`UPDATE sealed_tree_placements SET sealed=? WHERE object_index=?`, placements[(i+1)%len(placements)].value, placements[i].index); err != nil {
			t.Fatal(err)
		}
	}
	replacedRequest := httptest.NewRequest(http.MethodGet, ingress.PublicOrigin+"/api/v1/media/master-local/"+items[0].alias, nil)
	replacedRequest.Header.Set("X-Media-Capability", grants[0])
	replacedResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{replacedResponse}, replacedRequest)
	if replacedResponse.Code != http.StatusForbidden || replacedResponse.Body.String() == string(items[0].data) {
		t.Fatal("replaced sealed placement admitted", replacedResponse.Code)
	}
	for _, row := range placements {
		if _, err := treeDB.Exec(`UPDATE sealed_tree_placements SET sealed=? WHERE object_index=?`, row.value, row.index); err != nil {
			t.Fatal(err)
		}
	}
	setAlbumHidden(true)
	hiddenKey := call(http.MethodPost, "/api/v1/media/crypto/key",
		gin.H{"session_id": session.SessionID, "file_path": items[1].row.Path, "resource_id": items[1].row.ID, "object_id": items[1].row.ObjectID},
		sessionResponse.Result().Cookies()[0])
	var hiddenPlan struct {
		Headers map[string]string `json:"source_headers"`
	}
	if hiddenKey.Code != http.StatusOK || json.Unmarshal(hiddenKey.Body.Bytes(), &hiddenPlan) != nil ||
		hiddenPlan.Headers["X-Media-Capability"] == "" {
		t.Fatal("fresh anonymous session key failed for exact hidden Local path", hiddenKey.Code)
	}
	if response := localCipherRequest(hiddenPlan.Headers["X-Media-Capability"], cipherRange); response.Code != http.StatusPartialContent ||
		!bytes.Equal(response.Body.Bytes(), items[1].data) {
		t.Fatal("fresh hidden Local range failed", response.Code)
	}
	setAlbumHidden(false)
	otherSessionResponse := call(http.MethodPost, "/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, nil)
	var otherSession mediacrypto.SessionGrant
	if otherSessionResponse.Code != http.StatusOK || json.Unmarshal(otherSessionResponse.Body.Bytes(), &otherSession) != nil || len(otherSessionResponse.Result().Cookies()) != 1 {
		t.Fatal("second session", otherSessionResponse.Code)
	}
	otherSource := call(http.MethodPost, "/api/v1/media/crypto/key", gin.H{"session_id": otherSession.SessionID, "file_path": items[0].row.Path, "resource_id": items[0].row.ID, "object_id": items[0].row.ObjectID}, otherSessionResponse.Result().Cookies()[0])
	var otherPlan struct {
		Headers map[string]string `json:"source_headers"`
	}
	if otherSource.Code != http.StatusOK || json.Unmarshal(otherSource.Body.Bytes(), &otherPlan) != nil || otherPlan.Headers["X-Media-Capability"] == "" {
		t.Fatal("second session source", otherSource.Code)
	}
	if revoked := call(http.MethodPost, "/api/v1/media/crypto/revoke", gin.H{}, otherSessionResponse.Result().Cookies()[0]); revoked.Code != http.StatusOK {
		t.Fatal("second session revoke", revoked.Code)
	}
	revokedRequest := httptest.NewRequest(http.MethodGet, ingress.PublicOrigin+"/api/v1/media/master-local/"+items[0].alias, nil)
	revokedRequest.Header.Set("X-Media-Capability", otherPlan.Headers["X-Media-Capability"])
	revokedResponse := httptest.NewRecorder()
	router.ServeHTTP(masterDirectRecorder{revokedResponse}, revokedRequest)
	if revokedResponse.Code != http.StatusForbidden {
		t.Fatal("revoked Local session admitted", revokedResponse.Code)
	}
	changed := ingress
	changed.Generation++
	drain := &localDrainRecorder{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), resume: make(chan struct{})}
	drainRequest := httptest.NewRequest(http.MethodGet, ingress.PublicOrigin+"/api/v1/media/master-local/"+items[0].alias, nil)
	drainRequest.Header.Set("Range", "bytes=1-4")
	drainRequest.Header.Set("X-Media-Capability", grants[0])
	drainDone := make(chan struct{})
	go func() { router.ServeHTTP(drain, drainRequest); close(drainDone) }()
	select {
	case <-drain.started:
	case <-time.After(5 * time.Second):
		t.Fatal("Local media stream did not open")
	}
	switched := make(chan struct{})
	go func() { routing.change(changed); close(switched) }()
	select {
	case <-switched:
	case <-time.After(5 * time.Second):
		close(drain.resume)
		t.Fatal("Local media retained ingress lease during byte stream")
	}
	close(drain.resume)
	<-drainDone
	if drain.Code != http.StatusPartialContent || !bytes.Equal(drain.Body.Bytes(), items[0].data[1:5]) {
		t.Fatal("admitted Local media did not drain", drain.Code)
	}
	for i, item := range items {
		r := httptest.NewRequest(http.MethodGet, ingress.PublicOrigin+"/api/v1/media/master-local/"+item.alias, nil)
		r.Header.Set("X-Media-Capability", grants[i])
		w := httptest.NewRecorder()
		router.ServeHTTP(masterDirectRecorder{w}, r)
		want := http.StatusForbidden
		if grants[i] == "" {
			want = http.StatusUnauthorized
		}
		if w.Code != want {
			t.Fatal("old or absent Local media grant admitted", w.Code)
		}
	}
}
