package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Business handlers, durable SQLite state, signed node control and storage
// capabilities are real. Established Admin authentication is injected and the
// X-Accel relay is explicitly simulated; this is not Nginx/TLS/deployment proof.
func TestDownloadPlanIdentityHTTPPrimaryDirectRelay(t *testing.T) {
	for _, site := range []string{"primary", "direct", "relay"} {
		t.Run(site, func(t *testing.T) { testDownloadPlanIdentityHTTP(t, site) })
	}
}

func testDownloadPlanIdentityHTTP(t *testing.T, site string) {
	t.Helper()
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	mr, db, _, public, master := clusterFixture(t, "https://master.test", transport, false)
	fr, _, _, _, follower := clusterFixture(t, "https://follower.test", transport, true)
	if _, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := follower.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	pair, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relationshipID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := db.Nodes().Relationship(ctx, relationshipID)
	if err != nil {
		t.Fatal(err)
	}
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 5*store.GiB
	if err := db.Pool().ConfigureMember(ctx, relation.PeerID, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := master.Tick(ctx, relation); err != nil {
		t.Fatal(err)
	}
	if site != "primary" {
		mode := "Direct"
		if site == "relay" {
			mode = "Relay"
		}
		if err := db.Nodes().SetRelationshipMode(ctx, relationshipID, mode, false, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := public.settings
	// Also prove local plan bytes use a pinned descriptor even with Nginx on.
	cfg.NginxMedia = true
	public.settings.NginxMedia = true
	cfg.SecretsDirectory = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.SecretsDirectory, "admin_key"), []byte("identity-audit-fixture-key"), 0600); err != nil {
		t.Fatal(err)
	}
	auth, err := admin.New(cfg, nil, db.Admin())
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &Admin{settings: cfg, public: public, auth: auth, network: resolver}
	g := mr.Group("/api/v1/media/admin", func(c *gin.Context) {
		c.Set("admin_session", admin.Session{Hash: "download-identity-fixture"})
		c.Next()
	})
	g.POST("/upload/session", a.reserveUpload)
	g.PUT("/upload/session/:upload/bytes", a.uploadBytes)
	g.POST("/upload/session/:upload/finalize", a.finalizeUpload)
	g.GET("/download/plan", a.downloadPlan)
	g.GET("/download/bytes", a.downloadPlanBytes)
	g.HEAD("/download/bytes", a.downloadPlanBytes)
	g.GET("/download", a.download)
	g.POST("/delete", a.delete)
	g.POST("/directory/rename", a.renameDirectory)
	perform := func(method, target string, body []byte, span string) *httptest.ResponseRecorder {
		t.Helper()
		if !strings.HasPrefix(target, "https://") {
			target = "https://master.test" + target
		}
		r := httptest.NewRequest(method, target, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Range", span)
		w := httptest.NewRecorder()
		mr.ServeHTTP(w, r)
		return w
	}
	call := func(method, target string, body any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return perform(method, target, encoded, "")
	}
	finish := func(ticket media.UploadTicket, payload []byte) {
		t.Helper()
		var w *httptest.ResponseRecorder
		if site == "direct" {
			r := httptest.NewRequest("PUT", ticket.URL, bytes.NewReader(payload))
			r.Header.Set("Origin", "https://master.test")
			w = httptest.NewRecorder()
			fr.ServeHTTP(w, r)
		} else {
			w = perform("PUT", ticket.URL, payload, "")
		}
		if w.Code != 200 {
			t.Fatal("normal storage upload", w.Code, w.Body.String())
		}
		w = call("POST", "/api/v1/media/admin/upload/session/"+ticket.ID+"/finalize", struct{}{})
		if w.Code != 200 {
			t.Fatal("normal storage finalize", w.Code, w.Body.String())
		}
	}
	folder := "music/Identity-" + site
	plainPath := folder + "/song.mp3"
	uploadPlain := func(payload string) media.UploadTicket {
		t.Helper()
		w := call("POST", "/api/v1/media/admin/upload/session", gin.H{"storage_mode": "plain", "site_type": site, "target_dir": folder, "filename": "song.mp3", "size_bytes": len(payload)})
		var ticket media.UploadTicket
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ticket) != nil || ticket.Site != site {
			t.Fatal("normal plain reservation", w.Code, w.Body.String())
		}
		finish(ticket, []byte(payload))
		return ticket
	}
	uploadPlain("ID3firstAA")
	// An actual encrypted companion ensures this is the browser mixed-ZIP
	// plan, with the existing AES format and signed storage descriptor lifecycle.
	meta, err := mediacrypto.NewMetadata(10)
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
	ciphertext := aead.Seal(nil, nonce, []byte("ID3cipherA"), meta.ChunkAAD(0))
	encrypted, err := public.media.ReserveMasterEncryptedUpload(ctx, "encrypted.mp3", folder, "", site, meta.CiphertextSize, 255, store.AdminAudit{}, &meta)
	if err != nil {
		t.Fatal(err)
	}
	finish(encrypted, ciphertext)
	plan := func(scope, filename string, extra ...string) media.DownloadEntry {
		t.Helper()
		paths, _ := json.Marshal(append([]string{scope}, extra...))
		w := perform("GET", "/api/v1/media/admin/download/plan?"+url.Values{"paths": {string(paths)}}.Encode(), nil, "")
		var result struct {
			Items []media.DownloadEntry `json:"items"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatal("issued plan", w.Code, w.Body.String())
		}
		for _, entry := range result.Items {
			if entry.Path == filename && entry.Encryption == nil && strings.HasPrefix(entry.URL, "/api/v1/media/admin/download/bytes?") {
				return entry
			}
		}
		t.Fatal("plain plan member missing", w.Body.String())
		return media.DownloadEntry{}
	}
	auditCount := func() int {
		t.Helper()
		var n int
		if err := db.Database().QueryRow("SELECT COUNT(*) FROM admin_audit_log WHERE action='download'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Follow Direct's actual signed URL or mirror Nginx's internal Relay mapping.
	// The follower handler itself verifies all real capabilities and object IDs.
	resolve := func(response *httptest.ResponseRecorder, span string) *httptest.ResponseRecorder {
		t.Helper()
		target, capability := response.Header().Get("Location"), ""
		if relay := response.Header().Get("X-Accel-Redirect"); relay != "" {
			parts := strings.Split(relay, "/")
			if len(parts) != 6 || parts[1] != "_relay_media" || parts[2] != "follower.test" || parts[3] != "443" {
				t.Fatal("unexpected relay mapping", relay)
			}
			target, capability = "https://follower.test/internal/v1/media/"+parts[4], parts[5]
		}
		if target == "" {
			return response
		}
		parsed, err := url.Parse(target)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "follower.test" || !strings.HasPrefix(parsed.Path, "/internal/v1/media/") {
			t.Fatal("unexpected signed data destination", target)
		}
		r := httptest.NewRequest("GET", target, nil)
		r.Header.Set("Range", span)
		if capability != "" {
			r.Header.Set("X-Media-Capability", capability)
		} else {
			r.Header.Set("Origin", "https://master.test")
		}
		w := httptest.NewRecorder()
		fr.ServeHTTP(w, r)
		return w
	}
	read := func(entry media.DownloadEntry, expected string) *httptest.ResponseRecorder {
		t.Helper()
		before := auditCount()
		edge := perform("GET", entry.URL, nil, "")
		if site == "primary" && edge.Header().Get("X-Accel-Redirect") != "" || site == "direct" && edge.Code != 307 || site == "relay" && edge.Header().Get("X-Accel-Redirect") == "" {
			t.Fatal("plan did not follow expected transport", site, edge.Code, edge.Header())
		}
		w := resolve(edge, "")
		if w.Code != 200 || w.Body.String() != expected {
			t.Fatal("pinned bytes", site, w.Code, w.Body.String())
		}
		w = resolve(perform("GET", entry.URL, nil, "bytes=3-6"), "bytes=3-6")
		if w.Code != 206 || w.Body.String() != expected[3:7] || w.Header().Get("Content-Range") != "bytes 3-6/10" || auditCount() != before {
			t.Fatal("pinned Range or audit count changed", site, w.Code, w.Header(), w.Body.String(), auditCount(), before)
		}
		return edge
	}
	reject := func(entry media.DownloadEntry) {
		t.Helper()
		w := perform("GET", entry.URL, nil, "bytes=0-3")
		if w.Code != 404 && w.Code != 409 || w.Header().Get("Location") != "" || w.Header().Get("X-Accel-Redirect") != "" {
			t.Fatal("stale plan reached replacement bytes", site, w.Code, w.Header(), w.Body.String())
		}
	}
	original := plan(folder, plainPath)
	if auditCount() != 1 {
		t.Fatal("mixed plan audit missing")
	}
	originalEdge := read(original, "ID3firstAA")
	w := call("POST", "/api/v1/media/admin/delete", gin.H{"paths": []string{plainPath}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"deleted":1`) {
		t.Fatal("normal object deletion", w.Code, w.Body.String())
	}
	uploadPlain("ID3otherBB")
	reject(original)
	if site != "primary" {
		staleCapability := resolve(originalEdge, "")
		if staleCapability.Code != 401 && staleCapability.Code != 404 {
			t.Fatal("old storage capability read same-path replacement", site, staleCapability.Code, staleCapability.Body.String())
		}
	}
	replacement := plan(folder, plainPath)
	if replacement.URL == original.URL {
		t.Fatal("same-size replacement reused source identity")
	}
	read(replacement, "ID3otherBB")
	renamedFolder := "music/Renamed-" + site
	w = call("POST", "/api/v1/media/admin/directory/rename", gin.H{"path": folder, "new_name": "Renamed-" + site})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"new_path":"`+renamedFolder+`"`) {
		t.Fatal("normal directory rename", w.Code, w.Body.String())
	}
	reject(replacement)
	uploadPlain("ID3thirdCC")
	reject(replacement)
	read(plan(renamedFolder, renamedFolder+"/song.mp3"), "ID3otherBB")
	read(plan(plainPath, plainPath, renamedFolder+"/encrypted.mp3"), "ID3thirdCC")
	beforePlain := auditCount()
	paths, _ := json.Marshal([]string{plainPath})
	w = perform("GET", "/api/v1/media/admin/download/plan?"+url.Values{"paths": {string(paths)}}.Encode(), nil, "")
	var plainPlan struct {
		Items []media.DownloadEntry `json:"items"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &plainPlan) != nil || len(plainPlan.Items) != 1 || !strings.HasPrefix(plainPlan.Items[0].URL, "/api/v1/media/admin/download?") || auditCount() != beforePlain {
		t.Fatal("plain-only plan changed legacy source or duplicated audit", w.Code, w.Body.String(), auditCount(), beforePlain)
	}
	w = perform("GET", plainPlan.Items[0].URL, nil, "")
	if w.Code != 200 || auditCount() != beforePlain+1 {
		t.Fatal("legacy plain attachment lost its one audit", site, w.Code, auditCount(), beforePlain)
	}
}
