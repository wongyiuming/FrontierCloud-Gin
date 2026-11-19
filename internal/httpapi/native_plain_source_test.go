package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestNativePlainMasterSourcePolicyAndRevision(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	masterRouter, db, dir, public, original := clusterFixture(t, "https://master.test", transport, false)
	encryptedMeta, err := mediacrypto.NewMetadata(10)
	if err != nil {
		t.Fatal(err)
	}
	encryptedPayload := bytes.Repeat([]byte{'x'}, int(encryptedMeta.CiphertextSize))
	stage, err := public.media.Stage(ctx, bytes.NewReader(encryptedPayload), int64(len(encryptedPayload)))
	if err != nil {
		t.Fatal(err)
	}
	encryptedPath, err := public.media.PublishEncrypted(ctx, stage, "encrypted.mp3", "music/artist", "", false, 255, store.AdminAudit{}, &encryptedMeta)
	stage.Close()
	if err != nil {
		t.Fatal(err)
	}
	lyricText := "[00:01.00] lyric body must not cross metadata proxy\n"
	lyricStage, err := public.media.Stage(ctx, strings.NewReader(lyricText), int64(len(lyricText)))
	if err != nil {
		t.Fatal(err)
	}
	lyricPath, err := public.media.Publish(ctx, lyricStage, "plain.lrc", "", "", true, 255, store.AdminAudit{})
	lyricStage.Close()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := original.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Pool().Resources(ctx, "music/artist/song.mp3", true)
	if err != nil || len(rows) != 1 {
		t.Fatal("fixture", err)
	}
	row := rows[0]
	if _, err := public.media.ReplaceLyrics(ctx, "track", row.Path, []string{lyricPath}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 5}
	routing := &masterDirectHTTPRouting{selectedIngressRepository: selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: ingress}, policy: store.NativeTransportPolicy{MemberID: identity.ID, ConfiguredTransport: "Direct", AppliedTransport: "Direct", State: "applied", Revision: 2}}
	localIdentity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	control := node.NewService(routing, localIdentity, transport)
	prepareMasterHTTPPolicy(t, control)
	public.media.ConfigureCluster(routing, db.Pool(), control)
	settings := public.settings
	settings.TLSEnabled = true
	readerRouter := gin.New()
	public.masterDirect, err = RegisterMasterDirect(readerRouter, settings, "https://resource.test", public.media, control, public.crypto)
	if err != nil {
		t.Fatal(err)
	}
	public.masterRelay, err = RegisterMasterRelay(readerRouter, public.media, control, public.crypto)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.PublicOrigin, Generation: ingress.Generation, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	call := func(route string, value any, cookie *http.Cookie) *httptest.ResponseRecorder {
		body, _ := json.Marshal(value)
		admitted, lease := network.WithPublicAdmission(verified)
		defer lease.Abort()
		r := httptest.NewRequest(http.MethodPost, ingress.PublicOrigin+route, bytes.NewReader(body)).WithContext(admitted)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", ingress.PublicOrigin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		masterRouter.ServeHTTP(w, r)
		if w.Code == http.StatusOK && !lease.Commit() {
			t.Fatal("admission")
		}
		return w
	}
	sessionResponse := call("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, nil)
	var session mediacrypto.SessionGrant
	if sessionResponse.Code != 200 || json.Unmarshal(sessionResponse.Body.Bytes(), &session) != nil || len(sessionResponse.Result().Cookies()) != 1 {
		t.Fatal("session", sessionResponse.Code)
	}
	cookie := sessionResponse.Result().Cookies()[0]
	metadataRequest := func() *httptest.ResponseRecorder {
		admitted, lease := network.WithPublicAdmission(verified)
		defer lease.Abort()
		r := httptest.NewRequest(http.MethodGet, ingress.PublicOrigin+"/api/v1/media/lyrics/content?track=music%2Fartist%2Fsong.mp3", nil).WithContext(admitted)
		w := httptest.NewRecorder()
		masterRouter.ServeHTTP(w, r)
		if w.Code == http.StatusOK && !lease.Commit() {
			t.Fatal("metadata admission")
		}
		return w
	}
	metadata := metadataRequest()
	var lyric struct {
		Native     bool   `json:"native_lyric"`
		FilePath   string `json:"file_path"`
		ResourceID string `json:"resource_id"`
		ObjectID   string `json:"object_id"`
		Size       int64  `json:"size_bytes"`
	}
	if metadata.Code != http.StatusOK || strings.Contains(metadata.Body.String(), lyricText) || json.Unmarshal(metadata.Body.Bytes(), &lyric) != nil || !lyric.Native || lyric.FilePath != lyricPath || lyric.Size != int64(len(lyricText)) {
		t.Fatal("plain lyric metadata", metadata.Code, metadata.Body.String())
	}
	requestBody := gin.H{"session_id": session.SessionID, "file_path": row.Path, "resource_id": row.ID, "object_id": row.ObjectID}
	type grant struct {
		SourceURL       string            `json:"source_url"`
		SourceTransport string            `json:"source_transport"`
		SourceHeaders   map[string]string `json:"source_headers"`
		Revision        string            `json:"source_revision"`
		Size            int64             `json:"size_bytes"`
	}
	var direct grant
	var lyricDirect grant
	for _, mode := range []string{"Direct", "Relay"} {
		routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = mode, mode
		if err := control.PrepareMasterResourcePolicy(ctx); err != nil {
			t.Fatal(err)
		}
		response := call("/api/v1/media/crypto/native/source", requestBody, cookie)
		var g grant
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &g) != nil || g.SourceTransport != mode || g.Size != row.Bytes || len(g.Revision) != 64 || strings.Contains(g.SourceURL, "?") {
			t.Fatal("plan", mode, response.Code)
		}
		read := httptest.NewRequest(http.MethodGet, g.SourceURL, nil)
		if mode == "Relay" {
			read = read.WithContext(verified)
		}
		read.Header.Set("Origin", ingress.PublicOrigin)
		read.Header.Set("Range", "bytes=1-3")
		for name, value := range g.SourceHeaders {
			read.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		readerRouter.ServeHTTP(masterDirectRecorder{w}, read)
		if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), []byte("123")) {
			t.Fatal("range", mode, w.Code)
		}
		if mode == "Direct" {
			direct = g
		}
		lyricPlan := call("/api/v1/media/crypto/native/source", gin.H{"session_id": session.SessionID, "file_path": lyric.FilePath, "resource_id": lyric.ResourceID, "object_id": lyric.ObjectID}, cookie)
		var lg grant
		if lyricPlan.Code != http.StatusOK || json.Unmarshal(lyricPlan.Body.Bytes(), &lg) != nil || lg.SourceTransport != mode || lg.Size != lyric.Size {
			t.Fatal("lyric plan", mode, lyricPlan.Code)
		}
		lyricRead := httptest.NewRequest(http.MethodGet, lg.SourceURL, nil)
		if mode == "Relay" {
			lyricRead = lyricRead.WithContext(verified)
		}
		lyricRead.Header.Set("Origin", ingress.PublicOrigin)
		lyricRead.Header.Set("Range", "bytes=0-3")
		for name, value := range lg.SourceHeaders {
			lyricRead.Header.Set(name, value)
		}
		lw := httptest.NewRecorder()
		readerRouter.ServeHTTP(masterDirectRecorder{lw}, lyricRead)
		if lw.Code != http.StatusPartialContent || lw.Body.String() != lyricText[:4] {
			t.Fatal("lyric range", mode, lw.Code)
		}
		if mode == "Direct" {
			lyricDirect = lg
		}
	}
	if err := db.Media().SetHidden(ctx, []string{row.Path}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if metadata = metadataRequest(); metadata.Code == http.StatusOK {
		t.Fatal("hidden track returned lyric metadata")
	}
	lyricRead := httptest.NewRequest(http.MethodGet, lyricDirect.SourceURL, nil)
	lyricRead.Header.Set("Origin", ingress.PublicOrigin)
	lyricRead.Header.Set("X-Media-Capability", lyricDirect.SourceHeaders["X-Media-Capability"])
	lyricResponse := httptest.NewRecorder()
	readerRouter.ServeHTTP(masterDirectRecorder{lyricResponse}, lyricRead)
	if lyricResponse.Code != http.StatusForbidden {
		t.Fatal("hidden lyric grant readable", lyricResponse.Code)
	}
	if err := db.Media().SetHidden(ctx, []string{row.Path}, false, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Direct", "Relay"
	if response := call("/api/v1/media/crypto/native/source", requestBody, cookie); response.Code != http.StatusServiceUnavailable {
		t.Fatal("unapplied policy issued", response.Code)
	}
	requestBody["object_id"] = strings.Repeat("f", 64)
	if response := call("/api/v1/media/crypto/native/source", requestBody, cookie); response.Code == http.StatusOK {
		t.Fatal("wrong object accepted")
	}
	encryptedRows, err := db.Pool().Resources(ctx, encryptedPath, true)
	if err != nil || len(encryptedRows) != 1 {
		t.Fatal("encrypted fixture", err)
	}
	encrypted := encryptedRows[0]
	if response := call("/api/v1/media/crypto/native/source", gin.H{"session_id": session.SessionID, "file_path": encrypted.Path, "resource_id": encrypted.ID, "object_id": encrypted.ObjectID}, cookie); response.Code != http.StatusConflict {
		t.Fatal("encrypted object accepted as plain", response.Code)
	}
	if _, err := db.Database().Exec("UPDATE global_media_objects SET etag=? WHERE media_id=?", "replacement", row.ID); err != nil {
		t.Fatal(err)
	}
	read := httptest.NewRequest(http.MethodGet, direct.SourceURL, nil)
	read.Header.Set("Origin", ingress.PublicOrigin)
	read.Header.Set("X-Media-Capability", direct.SourceHeaders["X-Media-Capability"])
	w := httptest.NewRecorder()
	readerRouter.ServeHTTP(masterDirectRecorder{w}, read)
	if w.Code != http.StatusForbidden {
		t.Fatal("changed revision remained readable", w.Code)
	}
}
