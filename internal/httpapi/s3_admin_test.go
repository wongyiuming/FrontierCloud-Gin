package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// Only the transient cache is in memory. Login, CSRF, node authority, audit,
// reservations, encryption and source identities use the real Gin/SQL services.
type s3HTTPTestCache struct {
	mu       sync.Mutex
	sessions map[string]map[string]string
	attempts map[string]int64
}

func (c *s3HTTPTestCache) ReserveAttempt(_ context.Context, key string, _ int) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts[key]++
	return c.attempts[key], nil
}
func (c *s3HTTPTestCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, key)
	delete(c.attempts, key)
	return nil
}
func (c *s3HTTPTestCache) TakeTemporary(context.Context, string) (string, error) { return "", nil }
func (c *s3HTTPTestCache) PutTemporary(context.Context, string, string, int) (bool, error) {
	return false, errors.New("unsupported test operation")
}
func (c *s3HTTPTestCache) SaveSession(_ context.Context, key string, value map[string]string, _ int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions[key] = value
	return nil
}
func (c *s3HTTPTestCache) Session(_ context.Context, key string) (map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := map[string]string{}
	for k, v := range c.sessions[key] {
		result[k] = v
	}
	return result, nil
}
func (c *s3HTTPTestCache) Refresh(_ context.Context, key string, _ int) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[key] != nil, nil
}
func (c *s3HTTPTestCache) RotationLock(context.Context, string, int) (bool, error) {
	return false, errors.New("unsupported test operation")
}
func (c *s3HTTPTestCache) RotationUnlock(context.Context, string) error {
	return errors.New("unsupported test operation")
}
func (c *s3HTTPTestCache) ReplaceSessions(context.Context, string, string, int) error {
	return errors.New("unsupported test operation")
}

type s3HTTPFixture struct {
	router  *gin.Engine
	db      *sqlitestore.Store
	public  *Public
	admin   *Admin
	cookies map[string]*http.Cookie
}

func newS3HTTP(t *testing.T, role string) *s3HTTPFixture {
	t.Helper()
	router, db, dir, p := publicFixture(t, false)
	cfg := p.settings
	cfg.TLSEnabled = true
	cfg.PublicOrigin = "https://master.example"
	cfg.SecretsDirectory = filepath.Join(dir, "secrets")
	p.settings = cfg
	ctx := context.Background()
	if role == "Master" {
		if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: cfg.PublicOrigin, Allocation: 20 * store.GiB, PhysicalFree: 20 * store.GiB}, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
	}
	if role == "Follower" {
		if _, err := db.Database().Exec("UPDATE node_identity SET role='Follower' WHERE singleton=1"); err != nil {
			t.Fatal(err)
		}
	}
	p.media.ConfigureCluster(db.Nodes(), db.Pool(), nil)
	private, err := vault.OpenExisting(cfg.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	p.media.ConfigureS3(s3media.New(db.Pool().(store.S3Repository), db.Nodes(), private))
	if err = os.WriteFile(filepath.Join(cfg.SecretsDirectory, "admin_key"), []byte("s3-http-test-admin-key"), 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := node.OpenExisting(ctx, db.Nodes(), cfg.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	cache := &s3HTTPTestCache{sessions: map[string]map[string]string{}, attempts: map[string]int64{}}
	auth, err := admin.New(cfg, cache, db.Admin())
	if err != nil {
		t.Fatal(err)
	}
	a, err := RegisterAdmin(router, cfg, auth, p, identity)
	if err != nil {
		t.Fatal(err)
	}
	f := &s3HTTPFixture{router: router, db: db, public: p, admin: a, cookies: map[string]*http.Cookie{}}
	w := f.call("POST", "/api/v1/media/admin/elevate", "token=s3-http-test-admin-key", true, false, true)
	if w.Code != 200 {
		t.Fatal("actual Admin login", w.Code, w.Body.String())
	}
	return f
}
func (f *s3HTTPFixture) call(method, target, body string, authenticated, csrf, secure bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://master.example"+target, strings.NewReader(body))
	r.RemoteAddr = "198.51.100.20:12345"
	if secure {
		r.TLS = &tls.ConnectionState{}
	} else {
		r.TLS = nil
		r.URL.Scheme = "http"
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if strings.HasSuffix(target, "/elevate") {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("Origin", "https://master.example")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if authenticated {
		for _, cookie := range f.cookies {
			r.AddCookie(cookie)
		}
	}
	if csrf && f.cookies[f.admin.settings.CSRFCookieName()] != nil {
		r.Header.Set("X-CSRF-Token", f.cookies[f.admin.settings.CSRFCookieName()].Value)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	for _, cookie := range w.Result().Cookies() {
		f.cookies[cookie.Name] = cookie
	}
	return w
}
func s3HTTPConfiguration() string {
	return fmt.Sprintf(`{"name":"HTTP object store","location":{"endpoint":"https://10.20.30.40","bucket":"http-fixture","region":"us-east-1","prefix":"http-owned","style":"path"},"allocated_bytes":1073741824,"enabled":false,"credentials":{"access_key":"HTTPTESTACCESS0001","secret_key":"http-test-secret-012345","session_token":"http-test-session-token","expires_at":%d}}`, time.Now().Unix()+3600)
}
func (f *s3HTTPFixture) add(t *testing.T) store.S3Member {
	t.Helper()
	w := f.call("POST", "/api/v1/media/admin/nodes/s3", s3HTTPConfiguration(), true, true, true)
	if w.Code != 200 {
		t.Fatal("add", w.Code, w.Body.String())
	}
	var value store.S3Member
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func (f *s3HTTPFixture) enable(t *testing.T, member store.S3Member) store.S3Member {
	t.Helper()
	ctx := context.Background()
	repo := f.db.Pool().(store.S3Repository)
	probe, err := repo.S3StartProbe(ctx, member.ID, member.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	member, err = repo.S3FinishProbe(ctx, probe.ID, probe.Revision, store.S3ProbeResult{Key: probe.Key, ProviderUploadID: "observed-probe", ChecksPassed: true, CleanupSettled: true}, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	member, err = repo.S3ConfigureMember(ctx, member.ID, member.Revision, store.S3MemberConfiguration{Name: member.Name, Location: member.Location, Quota: member.Allocation, Enabled: true}, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	return member
}

func TestS3HTTPActualAdminTLSCSRFRoleAndCredentials(t *testing.T) {
	for _, role := range []string{"Standalone", "Follower", "Master"} {
		t.Run(role, func(t *testing.T) {
			f := newS3HTTP(t, role)
			target := "/api/v1/media/admin/nodes/s3"
			if w := f.call("GET", target, "", false, false, true); w.Code != 401 {
				t.Fatal("anonymous", w.Code)
			}
			if w := f.call("POST", target, s3HTTPConfiguration(), true, false, true); w.Code != 403 {
				t.Fatal("CSRF", w.Code)
			}
			if w := f.call("POST", target, s3HTTPConfiguration(), true, true, false); w.Code != 426 {
				t.Fatal("HTTP", w.Code)
			}
			w := f.call("GET", target, "", true, false, true)
			if role != "Master" {
				if w.Code != 409 {
					t.Fatal("non-Master read", w.Code)
				}
				w = f.call("POST", target, s3HTTPConfiguration(), true, true, true)
				if w.Code != 409 {
					t.Fatal("non-Master write", w.Code)
				}
				for _, source := range []string{"/api/v1/media/crypto/source", "/api/v1/media/admin/crypto/source"} {
					if w := f.call("POST", source, `{"file_path":"music/artist/file.mp3","object_id":"owned"}`, true, true, true); w.Code != 409 {
						t.Fatal("non-Master source", w.Code)
					}
				}
				return
			}
			if w.Code != 200 {
				t.Fatal("Master read", w.Code)
			}
			member := f.add(t)
			if member.ID == "" || member.Revision != 1 {
				t.Fatal("member identity")
			}
			w = f.call("GET", target, "", true, false, true)
			for _, secret := range []string{"HTTPTESTACCESS0001", "http-test-secret-012345", "http-test-session-token", "sealed_credentials"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("credential response leak")
				}
			}
			if !strings.Contains(w.Body.String(), `"physical_capacity_known":false`) || !strings.Contains(w.Body.String(), `"physical_total_bytes":null`) {
				t.Fatal("invented provider capacity", w.Body.String())
			}
			var count int
			if err := f.db.Database().QueryRow("SELECT COUNT(*) FROM node_audit WHERE action='s3-member-added'").Scan(&count); err != nil || count != 1 {
				t.Fatal("actual node audit", count, err)
			}
			payload := fmt.Sprintf(`{"revision":%d,"name":"Updated","location":{"endpoint":"https://10.20.30.40","bucket":"http-fixture","region":"us-east-1","prefix":"http-owned","style":"path"},"allocated_bytes":1073741824,"enabled":false}`, member.Revision)
			w = f.call("PATCH", target+"/"+member.ID, payload, true, true, true)
			if w.Code != 200 {
				t.Fatal("configure", w.Code, w.Body.String())
			}
			w = f.call("PATCH", target+"/"+member.ID, payload, true, true, true)
			if w.Code != 409 {
				t.Fatal("stale CAS", w.Code)
			}
			w = f.call("DELETE", target+"/"+member.ID, `{"revision":2}`, true, true, true)
			if w.Code != 200 {
				t.Fatal("remove", w.Code, w.Body.String())
			}
		})
	}
}

func TestS3HTTPRejectsHostileControlBeforeSQL(t *testing.T) {
	f := newS3HTTP(t, "Master")
	target := "/api/v1/media/admin/nodes/s3"
	for _, body := range []string{`null`, `[]`, `{} {}`, `{"name":"one","name":"two"}`, `{"name":"one","Name":"two"}`, `{"provider_upload_id":"attacker"}`, `{"credentials":{"access_key":"one","access_key":"two"}}`, strings.Repeat(" ", s3HTTPBodyLimit) + `{}`, "{\"name\":\"\xff\"}"} {
		w := f.call("POST", target, body, true, true, true)
		if w.Code != 422 && w.Code != 413 {
			t.Fatal("hostile control", w.Code)
		}
	}
	var count int
	if err := f.db.Database().QueryRow("SELECT COUNT(*) FROM s3_members").Scan(&count); err != nil || count != 0 {
		t.Fatal("malformed input wrote SQL", count, err)
	}
	if w := f.call("GET", target+"?credentials=must-not-accept", "", true, false, true); w.Code != 422 {
		t.Fatal("query authority", w.Code)
	}
	if w := f.call("POST", "/api/v1/media/admin/upload/s3/invalid/begin", `{}`, true, true, true); w.Code != 422 {
		t.Fatal("path identity", w.Code)
	}
}

func TestS3HTTPReservePartGrantAndPendingCancelUseRealSQL(t *testing.T) {
	f := newS3HTTP(t, "Master")
	member := f.enable(t, f.add(t))
	w := f.call("POST", "/api/v1/media/admin/upload/session", `{"site_type":"s3","target_dir":"music/artist","filename":"s3.mp3","size_bytes":128,"storage_mode":"plain"}`, true, true, true)
	if w.Code != 200 {
		t.Fatal("reserve", w.Code, w.Body.String())
	}
	var ticket struct {
		ID        string `json:"upload_id"`
		Transport string `json:"transport"`
	}
	json.Unmarshal(w.Body.Bytes(), &ticket)
	if ticket.Transport != "S3" || ticket.ID == "" || strings.Contains(w.Body.String(), "upload_url\":\"https:") {
		t.Fatal("payload relay or missing S3 ticket", w.Body.String())
	}
	base := "/api/v1/media/admin/upload/s3/" + ticket.ID
	repo := f.db.Pool().(store.S3Repository)
	ctx := context.Background()
	u, err := repo.S3Upload(ctx, ticket.ID)
	if err != nil {
		t.Fatal(err)
	}
	u, err = repo.S3StartCreate(ctx, ticket.ID, u.Revision)
	if err != nil {
		t.Fatal(err)
	}
	u, err = repo.S3FinishCreate(ctx, ticket.ID, u.Revision, "provider-upload", "created", "")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("part-observation"))
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	w = f.call("POST", base+"/parts/1/grant", fmt.Sprintf(`{"size_bytes":128,"checksum_sha256":%q}`, checksum), true, true, true)
	if w.Code != 200 {
		t.Fatal("real SDK presign", w.Code, w.Body.String())
	}
	var grant s3store.Grant
	json.Unmarshal(w.Body.Bytes(), &grant)
	if !strings.HasPrefix(grant.URL, "https://10.20.30.40/") || grant.Headers["X-Amz-Checksum-Sha256"] != checksum {
		t.Fatal("grant contract")
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("cacheable bearer")
	}
	if w := f.call("POST", base+"/parts/1/confirm", `{"etag":"untrusted"}`, true, true, true); w.Code != 422 {
		t.Fatal("client proof accepted", w.Code)
	}
	if w := f.call("POST", base+"/parts/01/grant", `{}`, true, true, true); w.Code != 422 {
		t.Fatal("noncanonical part")
	}
	w = f.call("DELETE", base, "", true, true, true)
	if w.Code != 202 || !strings.Contains(w.Body.String(), `"state":"aborting"`) {
		t.Fatal("pending cancel was claimed complete", w.Code, w.Body.String())
	}
	stored, err := repo.S3Member(ctx, member.ID)
	if err != nil || stored.Reserved != 128 {
		t.Fatal("live grant refunded quota", stored.Reserved, err)
	}
	u, err = repo.S3Upload(ctx, ticket.ID)
	if err != nil || u.State != "aborting" {
		t.Fatal("durable abort intent", err)
	}
	if w := f.call("PUT", base+"/bytes", "payload", true, true, true); w.Code != 404 && w.Code != 405 {
		t.Fatal("unexpected Master data relay")
	}
}

func TestS3HTTPErrorRedactsProviderAndGrantJSONKeepsHeaders(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(old)
	router := New(pass, pass)
	router.GET("/redacted", func(c *gin.Context) {
		s3HTTPError(c, fmt.Errorf("secret https://provider.example/?X-Amz-Signature=private accesskey: %w", s3store.ErrDenied))
	})
	w := request(router, "GET", "/redacted", "")
	if w.Code != 502 || strings.Contains(w.Body.String(), "provider.example") || strings.Contains(logs.String(), "X-Amz-Signature") || strings.Contains(logs.String(), "accesskey") {
		t.Fatal("raw provider error leaked")
	}
	read := s3media.SourceGrant{ObjectID: strings.Repeat("a", 64), SizeBytes: 128, GET: s3store.Grant{URL: "https://provider.example/get?sig=get", Headers: map[string]string{"If-Match": `"opaque"`}, ExpiresAt: time.Now().Unix() + 240}, HEAD: s3store.Grant{URL: "https://provider.example/head?sig=head", Headers: map[string]string{"If-Match": `"opaque"`, "X-Amz-Checksum-Mode": "ENABLED"}, ExpiresAt: time.Now().Unix() + 200}}
	router.GET("/grant", func(c *gin.Context) {
		value, ok := s3SourceJSON(c, "music/a.mp3", read)
		if ok {
			c.JSON(200, value)
		}
	})
	w = request(router, "GET", "/grant", "")
	if w.Code != 200 || w.Header().Get("Location") != "" {
		t.Fatal("lost-header redirect")
	}
	var value map[string]any
	json.Unmarshal(w.Body.Bytes(), &value)
	if value["expires_at"] != float64(read.HEAD.ExpiresAt) || value["expires_in"].(float64) > 200 || value["source_headers"].(map[string]any)["If-Match"] != `"opaque"` || value["source_head_url"] != read.HEAD.URL || value["source_head_headers"].(map[string]any)["X-Amz-Checksum-Mode"] != "ENABLED" {
		t.Fatal("source grant binding")
	}
	for _, invalid := range []map[string]string{
		{"If-Match": `"opaque"`, "X-Amz-Checksum-Mode": "DISABLED"},
		{"If-Match": `"opaque"`, "Authorization": "forbidden"},
	} {
		read.HEAD.Headers = invalid
		if w = request(router, "GET", "/grant", ""); w.Code != 502 {
			t.Fatal("unexpected signed HEAD authority", w.Code)
		}
	}
	read.HEAD.Headers = map[string]string{"If-Match": `"different"`}
	if w = request(router, "GET", "/grant", ""); w.Code != 502 || strings.Contains(w.Body.String(), "sig=") {
		t.Fatal("mismatched headers exposed")
	}
}

// Publish only bounded synthetic provider observations to SQL. The actual HTTP
// authorization below signs through the real SDK without a network request;
// provider write/read/CORS compatibility remains a separate live acceptance.
func (f *s3HTTPFixture) publish(t *testing.T, name string, meta *mediacrypto.Metadata) store.GlobalMedia {
	t.Helper()
	ctx := context.Background()
	repo := f.db.Pool().(store.S3Repository)
	size := int64(128)
	if meta != nil {
		size = meta.CiphertextSize
	}
	r, err := f.db.Pool().(store.EncryptionRepository).ReserveEncryptedUpload(ctx, name, "s3", size, 0, store.AdminAudit{}, meta)
	if err != nil {
		t.Fatal(err)
	}
	u, err := repo.S3Upload(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	u, err = repo.S3StartCreate(ctx, r.ID, u.Revision)
	if err != nil {
		t.Fatal(err)
	}
	u, err = repo.S3FinishCreate(ctx, r.ID, u.Revision, "observed-provider-upload", "created", "")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("observed-part"))
	p, err := repo.S3IssuePart(ctx, r.ID, 1, base64.StdEncoding.EncodeToString(digest[:]), size)
	if err != nil {
		t.Fatal(err)
	}
	p.ETag = `"observed-part"`
	u, err = repo.S3ConfirmPart(ctx, r.ID, p)
	if err != nil {
		t.Fatal(err)
	}
	u, err = repo.S3StartComplete(ctx, r.ID, u.Revision)
	if err != nil {
		t.Fatal(err)
	}
	composite := sha256.Sum256(digest[:])
	proof := store.S3ObjectProof{Key: u.Key, SessionID: r.ID, ObjectID: u.ObjectID, MemberID: r.MemberID, MediaID: r.MediaID, Bytes: size, ETag: `"observed-object"`, VersionID: "version-1", CompositeSHA256: base64.StdEncoding.EncodeToString(composite[:]) + "-1"}
	row, err := repo.S3FinalizeUpload(ctx, r.ID, u.Revision, proof, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestS3HTTPPlainSourceUsesExactCurrentPublicIdentity(t *testing.T) {
	f := newS3HTTP(t, "Master")
	f.enable(t, f.add(t))
	row := f.publish(t, "music/artist/plain.mp3", nil)
	target := "/api/v1/media/crypto/source"
	payload := fmt.Sprintf(`{"file_path":%q,"object_id":%q}`, row.Path, row.ObjectID)
	w := f.call("POST", target, payload, false, false, true)
	if w.Code != 200 || w.Header().Get("Location") != "" {
		t.Fatal("plain source", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) != 1 || !w.Result().Cookies()[0].HttpOnly {
		t.Fatal("missing page binding")
	}
	var source map[string]any
	json.Unmarshal(w.Body.Bytes(), &source)
	if source["source_headers"].(map[string]any)["If-Match"] != row.ETag || source["object_id"] != row.ObjectID || source["transport"] != "S3" {
		t.Fatal("signed identity lost")
	}
	if len(f.public.cryptoSessionLimit.windows) != 0 {
		t.Fatal("plain source created an ECDH admission")
	}
	parsed, err := url.Parse(source["source_url"].(string))
	if err != nil || parsed.Query().Get("versionId") != "version-1" {
		t.Fatal("version binding")
	}
	for _, body := range []string{fmt.Sprintf(`{"file_path":%q,"object_id":%q}`, row.Path, strings.Repeat("f", 64)), fmt.Sprintf(`{"file_path":"music/artist/other.mp3","object_id":%q}`, row.ObjectID), `{"file_path":"../secrets","object_id":"x"}`, `{"file_path":"music/artist/plain.mp3"}`} {
		if w := f.call("POST", target, body, true, false, true); w.Code == 200 {
			t.Fatal("source identity bypass")
		}
	}
	if err := f.public.media.Hide(context.Background(), []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if w := f.call("POST", target, payload, true, false, true); w.Code != 404 {
		t.Fatal("hidden public source", w.Code, w.Body.String())
	}
	if w := f.call("POST", "/api/v1/media/admin/crypto/source", payload, true, false, true); w.Code != 403 {
		t.Fatal("Admin source CSRF")
	}
	if w := f.call("POST", "/api/v1/media/admin/crypto/source", payload, true, true, true); w.Code != 200 {
		t.Fatal("authorized Admin hidden source", w.Code, w.Body.String())
	}
	r := httptest.NewRequest("POST", "https://master.example"+target, strings.NewReader(payload))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin source")
	}
}

func TestS3HTTPEncryptedKeyCarriesSignedSourceAndRejectsPlainShortcut(t *testing.T) {
	f := newS3HTTP(t, "Master")
	f.enable(t, f.add(t))
	meta, err := mediacrypto.NewMetadata(128)
	if err != nil {
		t.Fatal(err)
	}
	row := f.publish(t, "music/artist/encrypted.mp3", &meta)
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w := f.call("POST", "/api/v1/media/crypto/session", fmt.Sprintf(`{"public_key":%q}`, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())), false, false, true)
	if w.Code != 200 {
		t.Fatal("ECDH session", w.Code, w.Body.String())
	}
	var active mediacrypto.SessionGrant
	json.Unmarshal(w.Body.Bytes(), &active)
	body := fmt.Sprintf(`{"session_id":%q,"file_path":%q,"object_id":%q}`, active.SessionID, row.Path, row.ObjectID)
	w = f.call("POST", "/api/v1/media/crypto/key", body, true, false, true)
	if w.Code != 200 {
		t.Fatal("S3 key", w.Code, w.Body.String())
	}
	var result map[string]any
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["transport"] != "S3" || result["object_id"] != row.ObjectID || result["source_headers"].(map[string]any)["If-Match"] != row.ETag || result["source_expires_in"].(float64) > 300 || result["key_envelope"].(map[string]any)["wrapped_key"] == "" {
		t.Fatal("lost S3 key/source binding")
	}
	if w := f.call("POST", "/api/v1/media/crypto/source", fmt.Sprintf(`{"file_path":%q,"object_id":%q}`, row.Path, row.ObjectID), true, false, true); w.Code != 422 {
		t.Fatal("encrypted object escaped plaintext endpoint", w.Code)
	}
	if w := f.call("POST", "/api/v1/media/crypto/key", fmt.Sprintf(`{"session_id":%q,"file_path":%q}`, active.SessionID, row.Path), true, false, true); w.Code == 200 {
		t.Fatal("missing immutable S3 identity returned native URL")
	}
	if w := f.call("POST", "/api/v1/media/crypto/key", fmt.Sprintf(`{"session_id":%q,"file_path":%q,"object_id":%q}`, active.SessionID, row.Path, strings.Repeat("e", 64)), true, false, true); w.Code == 200 {
		t.Fatal("wrong object/key source")
	}
}

func TestS3HTTPLegacyURLsRefuseRelayAndSuccessAudit(t *testing.T) {
	f := newS3HTTP(t, "Master")
	f.enable(t, f.add(t))
	row := f.publish(t, "music/artist/plain.mp3", nil)
	for _, method := range []string{"GET", "HEAD"} {
		w := f.call(method, "/api/v1/media/stream?"+url.Values{"file_path": {row.Path}, "resource_id": {row.ID}}.Encode(), "", false, false, true)
		if w.Code != 409 || w.Header().Get("Location") != "" || w.Header().Get("X-Accel-Redirect") != "" {
			t.Fatal("legacy stream fell back", method, w.Code)
		}
	}
	paths, _ := json.Marshal([]string{row.Path})
	w := f.call("GET", "/api/v1/media/admin/download?"+url.Values{"paths": {string(paths)}}.Encode(), "", true, false, true)
	if w.Code != 409 {
		t.Fatal("legacy download", w.Code, w.Body.String())
	}
	var count int
	if err := f.db.Database().QueryRow("SELECT COUNT(*) FROM admin_audit_log WHERE action='download' AND result='success'").Scan(&count); err != nil || count != 0 {
		t.Fatal("unsupported download audited successful", count, err)
	}
	w = f.call("GET", "/api/v1/media/admin/download/plan?"+url.Values{"paths": {string(paths)}}.Encode(), "", true, false, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"transport":"S3"`) || !strings.Contains(w.Body.String(), row.ObjectID) {
		t.Fatal("browser plan", w.Code, w.Body.String())
	}
	if err := f.db.Database().QueryRow("SELECT COUNT(*) FROM admin_audit_log WHERE action='download' AND result='success' AND detail LIKE '%s3_download_plan%'").Scan(&count); err != nil || count != 1 {
		t.Fatal("S3 browser plan lost download audit", count, err)
	}
}

func TestS3HTTPPublicSourceAdmissionIndependentAndBounded(t *testing.T) {
	f := newS3HTTP(t, "Master")
	f.enable(t, f.add(t))
	row := f.publish(t, "music/artist/plain.mp3", nil)
	body := fmt.Sprintf(`{"file_path":%q,"object_id":%q}`, row.Path, row.ObjectID)
	for i := 0; i < s3SourceCookieGrants; i++ {
		if w := f.call("POST", "/api/v1/media/crypto/source", body, true, false, true); w.Code != 200 {
			t.Fatal("source window", i, w.Code, w.Body.String())
		}
	}
	if w := f.call("POST", "/api/v1/media/crypto/source", body, true, false, true); w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("source limiter", w.Code)
	}
	if len(f.public.cryptoSessionLimit.windows) != 0 || len(f.public.cryptoSourceLimit.windows) > s3SourceAdmissionEntries {
		t.Fatal("shared or unbounded ECDH/source state")
	}
}
