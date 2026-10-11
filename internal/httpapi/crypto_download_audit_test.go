package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestEncryptedDownloadPlanAuditHTTP(t *testing.T) {
	router, db, _, public := publicFixture(t, false)
	ctx := context.Background()
	meta, err := mediacrypto.NewMetadata(23)
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
	content := aead.Seal(nil, nonce, bytes.Repeat([]byte{'a'}, int(meta.PlaintextSize)), meta.ChunkAAD(0))
	stage, err := public.media.Stage(ctx, bytes.NewReader(content), meta.CiphertextSize)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	encryptedPath, err := public.media.PublishEncrypted(ctx, stage, "encrypted.mp3", "music/artist", "", false, 255, store.AdminAudit{}, &meta)
	if err != nil {
		t.Fatal(err)
	}
	cfg := public.settings
	cfg.SecretsDirectory = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.SecretsDirectory, "admin_key"), []byte("audit-fixture-key"), 0600); err != nil {
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
	g := router.Group("/audit-admin", func(c *gin.Context) {
		c.Set("admin_session", admin.Session{Hash: "audit-session"})
		c.Set("request_id", "plan-audit-request")
		c.Set("trace_id", "plan-audit-trace")
		c.Next()
	})
	g.GET("/plan", a.downloadPlan)
	g.GET("/download", a.download)
	g.GET("/bytes", a.cryptoBytes)
	g.GET("/download/bytes", a.downloadPlanBytes)
	count := func() int {
		t.Helper()
		var n int
		if err := db.Database().QueryRow("SELECT COUNT(*) FROM admin_audit_log WHERE action='download'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	target := func(route string, paths ...string) string {
		encoded, _ := json.Marshal(paths)
		return "/audit-admin/" + route + "?" + url.Values{"paths": {string(encoded)}}.Encode()
	}
	// A directory/file overlap produces one issued plan, not one audit per
	// expanded file. Request spellings cannot leak into the canonical scopes.
	w := request(router, "GET", target("plan", " music\\artist ", "music/artist", encryptedPath), "")
	if w.Code != 200 || count() != 1 {
		t.Fatal("mixed plan was not audited once", w.Code, count(), w.Body.String())
	}
	var plan struct {
		Items []media.DownloadEntry `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	var source, detail, sessionHash, requestID, traceID, result string
	var targetCount int
	if err := db.Database().QueryRow("SELECT source_summary,detail,session_id_hash,request_id,trace_id,result,target_count FROM admin_audit_log WHERE action='download'").Scan(&source, &detail, &sessionHash, &requestID, &traceID, &result, &targetCount); err != nil {
		t.Fatal(err)
	}
	canonical, _ := json.Marshal([]string{"music/artist", encryptedPath})
	if source != string(canonical) || targetCount != 2 || sessionHash != "audit-session" || requestID != "plan-audit-request" || traceID != "plan-audit-trace" || result != "success" {
		t.Fatal("audit lost canonical selection or actor", source, targetCount, sessionHash, requestID, traceID, result)
	}
	var details struct {
		Kind           string `json:"kind"`
		Files          int    `json:"files"`
		EncryptedFiles int    `json:"encrypted_files"`
	}
	if json.Unmarshal([]byte(detail), &details) != nil || details.Kind != "encrypted_download_plan" || details.Files != 2 || details.EncryptedFiles != 1 || strings.Contains(detail, meta.FileID) {
		t.Fatal("audit did not identify the download plan without key metadata", detail)
	}
	for _, span := range []string{"bytes=0-3", "bytes=4-7"} {
		r := httptest.NewRequest("GET", "/audit-admin/bytes?"+url.Values{"file_path": {encryptedPath}}.Encode(), nil)
		r.Header.Set("Range", span)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != 206 || count() != 1 {
			t.Fatal("cipher Range created duplicate download audit", w.Code, count())
		}
	}
	plainURL := ""
	for _, entry := range plan.Items {
		if entry.Path == "music/artist/song.mp3" {
			plainURL = strings.Replace(entry.URL, "/api/v1/media/admin/", "/audit-admin/", 1)
		}
	}
	if !strings.HasPrefix(plainURL, "/audit-admin/download/bytes?") {
		t.Fatal("mixed plain member does not use identity-bound plan source", plainURL)
	}
	for i, span := range []string{"bytes=0-3", "bytes=4-7"} {
		r := httptest.NewRequest("GET", plainURL, nil)
		r.Header.Set("Range", span)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != 206 || w.Body.String() != []string{"0123", "4567"}[i] || count() != 1 {
			t.Fatal("plain mixed Range changed bytes or duplicated audit", w.Code, count(), w.Body.String())
		}
	}
	// Plain plans leave the existing actual attachment audit responsible.
	w = request(router, "GET", target("plan", "music/artist/song.mp3"), "")
	if w.Code != 200 || count() != 1 {
		t.Fatal("plain plan duplicated attachment audit", w.Code, count())
	}
	w = request(router, "GET", target("download", "music/artist/song.mp3"), "")
	if w.Code != 200 || count() != 2 {
		t.Fatal("plain attachment lost its audit", w.Code, count())
	}
	w = request(router, "GET", target("plan", "music/artist/missing.mp3"), "")
	if w.Code != 404 || count() != 2 {
		t.Fatal("rejected plan recorded success", w.Code, count())
	}
	if _, err := db.Database().Exec("CREATE TRIGGER reject_plan_audit BEFORE INSERT ON admin_audit_log WHEN NEW.action='download' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"); err != nil {
		t.Fatal(err)
	}
	w = request(router, "GET", target("plan", encryptedPath), "")
	if w.Code != 500 || count() != 2 || strings.Contains(w.Body.String(), `"items"`) {
		t.Fatal("plan issued successfully after audit failure", w.Code, count(), w.Body.String())
	}
}

func TestEncryptedDownloadPlanAuditLargeSelection(t *testing.T) {
	_, db, _, public := publicFixture(t, false)
	cfg := public.settings
	cfg.SecretsDirectory = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.SecretsDirectory, "admin_key"), []byte("audit-fixture-key"), 0600); err != nil {
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
	a := &Admin{settings: cfg, auth: auth, network: resolver}
	download := &media.Download{}
	paths := []string{}
	for i := 0; i < 100; i++ {
		name := "music/" + strings.Repeat("音", 100) + "/" + strings.Repeat("曲", i+1) + ".mp3"
		paths = append(paths, name)
		download.Items = append(download.Items, store.DeleteItem{Path: name})
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/plan", nil)
	c.Set("admin_session", admin.Session{Hash: "large-plan"})
	if err := a.auditEncryptedDownloadPlan(c, download, []media.DownloadEntry{{Encryption: &mediacrypto.Metadata{}}}); err != nil {
		t.Fatal(err)
	}
	var source, detail string
	var count, targets int
	if err := db.Database().QueryRow("SELECT COUNT(*),source_summary,detail,target_count FROM admin_audit_log WHERE action='download'").Scan(&count, &source, &detail, &targets); err != nil {
		t.Fatal(err)
	}
	var retained []string
	var proof struct {
		Total   int    `json:"source_paths_total"`
		Omitted int    `json:"source_paths_omitted"`
		SHA256  string `json:"source_sha256"`
	}
	complete, _ := json.Marshal(paths)
	sum := sha256.Sum256(complete)
	if count != 1 || targets != len(paths) || utf8.RuneCountInString(source) > 8000 || json.Unmarshal([]byte(source), &retained) != nil || json.Unmarshal([]byte(detail), &proof) != nil || proof.Total != len(paths) || proof.Omitted != len(paths)-len(retained) || proof.Omitted == 0 || proof.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("large selection evidence was silently truncated or duplicated", count, targets, source, detail)
	}
	for i, path := range retained {
		if path != paths[i] {
			t.Fatal("retained selection differs from canonical prefix")
		}
	}
}
