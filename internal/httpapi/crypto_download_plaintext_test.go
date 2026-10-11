package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

func TestPlaintextDownloadPlanKeepsLargeLegacyZIPAndRejectsOversizeMixedSelection(t *testing.T) {
	router, db, dir, public := publicFixture(t, false)
	ctx := context.Background()
	for i := 1; i <= 5000; i++ {
		name := fmt.Sprintf("media/music/artist/%04d.mp3", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("ID3plain"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Media().SetHidden(ctx, []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	cfg := public.settings
	cfg.SecretsDirectory = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.SecretsDirectory, "admin_key"), []byte("download-boundary-audit-fixture"), 0600); err != nil {
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
	group := router.Group("/plain-admin", func(c *gin.Context) {
		c.Set("admin_session", admin.Session{Hash: "large-plaintext-download"})
		c.Next()
	})
	group.GET("/plan", a.downloadPlan)
	group.GET("/download", a.download)
	target := func(route string, paths ...string) string {
		encoded, _ := json.Marshal(paths)
		return "/plain-admin/" + route + "?" + url.Values{"paths": {string(encoded)}}.Encode()
	}
	countAudits := func() int {
		t.Helper()
		var count int
		if err := db.Database().QueryRow("SELECT COUNT(*) FROM admin_audit_log WHERE action='download'").Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	response := request(router, "GET", target("plan", "music/artist", "music/artist/song.mp3"), "")
	var plan struct {
		Items []media.DownloadEntry `json:"items"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &plan) != nil || plan.Items == nil || len(plan.Items) != 0 || countAudits() != 0 {
		t.Fatal("all-plaintext directory was browser-limited or duplicated the attachment audit", response.Code, countAudits(), response.Body.String())
	}
	response = request(router, "GET", target("download", "music/artist", "music/artist/song.mp3"), "")
	if response.Code != 200 || response.Header().Get("Content-Type") != "application/zip" || countAudits() != 1 {
		t.Fatal("legacy plaintext ZIP was rejected", response.Code, countAudits(), response.Body.String())
	}
	archive, err := zip.NewReader(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
	if err != nil || len(archive.File) != 5001 {
		t.Fatal("archive selection was truncated or duplicated", err)
	}
	for _, file := range archive.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, readErr := io.ReadAll(reader)
		reader.Close()
		if readErr != nil || string(content) != "ID3plain" && string(content) != "0123456789" {
			t.Fatal("legacy ZIP changed file bytes", file.Name, readErr)
		}
	}
	// Encrypt an existing tail member, keeping the total at 5001. CompleteUpload
	// is the real descriptor transaction; bytes are opaque to the server route.
	meta, err := mediacrypto.NewMetadata(8)
	if err != nil {
		t.Fatal(err)
	}
	name := "music/artist/5000.mp3"
	if err := os.WriteFile(filepath.Join(dir, "media", filepath.FromSlash(name)), bytes.Repeat([]byte{0x91}, int(meta.CiphertextSize)), 0644); err != nil {
		t.Fatal(err)
	}
	if err := db.Media().CompleteUpload(ctx, store.MediaObject{Path: name, Kind: "audio", Encryption: &meta}, strings.Repeat("9", 32), store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	response = request(router, "GET", target("plan", "music/artist"), "")
	if response.Code != 413 || strings.Contains(response.Body.String(), `"items"`) || countAudits() != 1 {
		t.Fatal("oversize mixed selection became a legacy fallback or successful audit", response.Code, countAudits(), response.Body.String())
	}
	response = request(router, "GET", target("plan", name), "")
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &plan) != nil || len(plan.Items) != 1 || plan.Items[0].Encryption == nil || *plan.Items[0].Encryption != meta || countAudits() != 2 {
		t.Fatal("single encrypted selection lost its descriptor, identity or audit", response.Code, response.Body.String())
	}
	source, err := url.Parse(plan.Items[0].URL)
	if err != nil || len(source.Query().Get("snapshot")) != 64 || source.Query().Get("media_id") != plan.Items[0].MediaID {
		t.Fatal("encrypted plan source was not bound to its identity and snapshot", source, err)
	}
}
