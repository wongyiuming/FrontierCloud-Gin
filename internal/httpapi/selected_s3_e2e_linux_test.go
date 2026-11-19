//go:build linux && ledger_fixture

package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

var _ SealedS3RuntimeGate = (*business.SelectedS3FileGate)(nil)

// Fake provider and fixture lifecycle prove HTTP/transaction composition,
// not live S3 compatibility or production startup readiness.
type selectedS3HTTPProvider struct {
	s3store.Provider
	key, owner         string
	parts              []s3store.Part
	proof              s3store.Proof
	completed          bool
	creates, completes int
	onSign             func()
}

func (p *selectedS3HTTPProvider) WithSelectedProvider(ctx context.Context, m store.S3Member, fn func(context.Context, s3store.Provider) error) error {
	if m.Kind != "S3" || m.Revision != 1 {
		return store.ErrNodeState
	}
	return fn(ctx, p)
}
func (p *selectedS3HTTPProvider) CreateMultipart(_ context.Context, key string, metadata map[string]string) (string, error) {
	if _, ok := store.S3OpaqueOwner(key); !ok || metadata["fc-format"] != store.S3OpaqueMetadata || metadata["fc-owner"] == "" || len(metadata) != 2 {
		return "", store.ErrNodeState
	}
	p.key, p.owner = key, metadata["fc-owner"]
	p.creates++
	return "fixture-upload", nil
}
func (p *selectedS3HTTPProvider) PresignPart(_ context.Context, key, upload string, number int32, size int64, checksum string, expiry time.Duration) (s3store.Grant, error) {
	if key != p.key || upload != "fixture-upload" || number != 1 || size < 1 {
		return s3store.Grant{}, store.ErrNodeState
	}
	if p.onSign != nil {
		p.onSign()
	}
	return s3store.Grant{URL: "https://s3.fixture.test/part", Headers: map[string]string{"x-amz-checksum-sha256": checksum}, ExpiresAt: time.Now().Add(expiry).Unix()}, nil
}
func (p *selectedS3HTTPProvider) ListParts(_ context.Context, key, upload string) ([]s3store.Part, error) {
	if key != p.key || upload != "fixture-upload" {
		return nil, store.ErrNodeState
	}
	return p.parts, nil
}
func (p *selectedS3HTTPProvider) Head(_ context.Context, key, _ string) (s3store.Proof, error) {
	if key != p.key {
		return s3store.Proof{}, store.ErrNodeState
	}
	if !p.completed {
		return s3store.Proof{}, s3store.ErrNotFound
	}
	return p.proof, nil
}
func (p *selectedS3HTTPProvider) Complete(_ context.Context, key, upload string, _ []s3store.Part) (s3store.Proof, error) {
	if key != p.key || upload != "fixture-upload" {
		return s3store.Proof{}, store.ErrNodeState
	}
	p.completed = true
	p.completes++
	return p.proof, nil
}

func TestSelectedS3AdminMultipartHTTPWithFakeProvider(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 60*time.Second)
	defer stop()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, database, dir, public, master := clusterFixture(t, "https://master.test", transport, false)
	if _, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	var sequence int
	var dbName, dbPath string
	if err := database.Database().QueryRowContext(ctx, "PRAGMA database_list").Scan(&sequence, &dbName, &dbPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := public.settings
	cfg.DataRoot, cfg.SQLitePath, cfg.DatabaseType, cfg.AdminOrigin, cfg.PublicOrigin, cfg.TLSEnabled = dir, dbPath, config.DatabaseSQLite, "https://admin.test", "https://master.test", true
	public.settings.AdminOrigin = cfg.AdminOrigin
	treeDir := filepath.Join(dir, "s3-tree")
	if err := os.Mkdir(treeDir, 0700); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = deployment.Bind(ctx, cfg, func(c context.Context) error { return master.ValidateRetainedIdentity(c, cfg.SecretsDirectory) }); err != nil {
		t.Fatal(err)
	}
	codec, err := sealedtree.New(bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID := strings.Repeat("a", 64)
	if err = sealedtree.FixtureInitializeExisting(ctx, cfg, gate, codec, rootID, treeDir); err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.OpenSQLite(ctx, database.Database(), codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(treeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	if _, err = sealedtree.OpenFence(ctx, tree, treeRoot, treeDir); err != nil {
		t.Fatal(err)
	}
	private, err := vault.OpenExisting(cfg.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err = gate.Resume(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	mediaPath := filepath.Join(dir, "media")
	if err = os.Chmod(mediaPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(mediaPath, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	mediaRoot, err := os.OpenRoot(mediaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer mediaRoot.Close()
	identity, err := node.Initialize(ctx, database.Nodes(), cfg.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := ownerfence.Create(mediaRoot, mediaPath, identity)
	if err != nil {
		t.Fatal(err)
	}
	repo := database.Pool().(*business.Repository)
	if err = repo.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = repo.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	if err = repo.ConfigurePublicOrigin(cfg.PublicOrigin); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.PublicIngress(ctx); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err = repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	member := strings.Repeat("2", 32)
	if _, err = database.Database().Exec(`INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES(?,NULL,'S3','S3',1,?,0,0,0,'online',1,1)`, member, store.GiB); err != nil {
		t.Fatal(err)
	}
	if _, err = database.Database().Exec(`INSERT INTO s3_members(member_id,name,endpoint,region,bucket,prefix,address_style,namespace_key,sealed_credentials,credential_revision,revision,probe_revision,probe_state,created_at,updated_at) VALUES(?,'fixture','https://s3.us-east-1.amazonaws.com','us-east-1','fixture-private','managed','path','fixture-namespace','sealed-credentials',1,1,1,'ready',1,1)`, member); err != nil {
		t.Fatal(err)
	}
	if _, err = database.Database().Exec(`UPDATE s3_members SET namespace_key=? WHERE member_id=?`, "aws\nfixture-private", member); err != nil {
		t.Fatal(err)
	}
	runtime, err := business.NewSelectedUploadRuntime(repo, tree, key, public.crypto, private, cfg.AdminOrigin, selectedE2EGate{})
	if err != nil {
		t.Fatal(err)
	}
	provider := &selectedS3HTTPProvider{}
	public.media.ConfigureS3(s3media.New(repo, database.Nodes(), private))
	controlRoot, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer controlRoot.Close()
	if err = business.PrepareSelectedS3FileGate(controlRoot, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	s3Gate, err := business.OpenSelectedS3FileGate(controlRoot, tree, func(c context.Context) error { return c.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer s3Gate.Close()
	adminKey := "s3-http-test-key"
	if err = os.WriteFile(filepath.Join(cfg.SecretsDirectory, "admin_key"), []byte(adminKey), 0600); err != nil {
		t.Fatal(err)
	}
	auth, err := admin.New(cfg, &selectedAdminTestCache{sessions: map[string]map[string]string{}}, database.Admin())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := RegisterAdmin(router, cfg, auth, public, identity)
	if err != nil {
		t.Fatal(err)
	}
	public.opaqueTree = tree
	if err = handler.ConfigureSelectedUploadRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	if err = handler.ConfigureSealedS3(provider, nil); err == nil {
		t.Fatal("nil lifecycle gate accepted")
	}
	if err = handler.ConfigureSealedS3(provider, s3Gate); err != nil {
		t.Fatal("S3 runtime assembly", err)
	}
	// This test isolates HTTP/SQL composition; the origin probe itself is
	// simulated here and independently exercised against the TLS supplier.
	memberSnapshot, err := repo.S3Member(ctx, member)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s3Gate.WithSelectedS3Probe(ctx, tree, member, cfg.AdminOrigin, cfg.PublicOrigin, func(context.Context) (store.S3Member, error) { return memberSnapshot, nil }); err != nil {
		t.Fatal("test origin proof", err)
	}
	for _, enabled := range []bool{false, true} {
		if _, err = public.media.S3ConfigureMember(ctx, member, memberSnapshot.Revision, s3media.Configuration{Name: "changed", Location: memberSnapshot.Location, Quota: memberSnapshot.Allocation, Enabled: enabled}, store.NodeAudit{}); err == nil {
			t.Fatal("enabled selected member changed without a drain")
		}
	}
	unchanged, err := repo.S3Member(ctx, member)
	if err != nil || unchanged.Revision != memberSnapshot.Revision {
		t.Fatal("failed configuration changed selected member", err)
	}
	login, err := auth.Login(ctx, adminKey, admin.RequestInfo{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, route string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var raw []byte
		if body != nil {
			var e error
			raw, e = json.Marshal(body)
			if e != nil {
				t.Fatal(e)
			}
		}
		r := httptest.NewRequest(method, cfg.AdminOrigin+"/api/v1/media/admin"+route, bytes.NewReader(raw))
		r.Header.Set("Origin", cfg.AdminOrigin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", login.CSRF)
		r.AddCookie(&http.Cookie{Name: cfg.AdminCookieName(), Value: login.Cookie})
		r.AddCookie(&http.Cookie{Name: cfg.CSRFCookieName(), Value: login.CSRF})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	added := request("POST", "/nodes/s3", s3media.Configuration{Name: "new member", Location: store.S3Location{Endpoint: "https://s3.us-east-1.amazonaws.com", Bucket: "second-bucket", Region: "us-east-1", Prefix: "managed", Style: "path"}, Quota: store.GiB, Credentials: &s3store.Credentials{AccessKey: "EXAMPLEACCESSKEY", SecretKey: "fixture-only-secret-key"}})
	if added.Code != http.StatusOK || strings.Contains(added.Body.String(), "fixture-only-secret-key") {
		t.Fatal("selected S3 member addition", added.Code)
	}
	var sealedCredentials string
	if err = database.Database().QueryRow(`SELECT sealed_credentials FROM s3_members WHERE name=?`, "new member").Scan(&sealedCredentials); err != nil || strings.Contains(sealedCredentials, "fixture-only-secret-key") {
		t.Fatal("S3 credentials were not sealed", err)
	}
	unsealedCredentials, err := private.Unseal(sealedCredentials)
	if err != nil || !strings.Contains(unsealedCredentials, "fixture-only-secret-key") {
		t.Fatal("sealed S3 credentials do not recover", err)
	}
	var newMemberID string
	if err = database.Database().QueryRow(`SELECT member_id FROM s3_members WHERE name=?`, "new member").Scan(&newMemberID); err != nil {
		t.Fatal(err)
	}
	newMember, err := repo.S3Member(ctx, newMemberID)
	if err != nil {
		t.Fatal(err)
	}
	newMember, err = s3Gate.WithSelectedS3Probe(ctx, tree, newMemberID, cfg.AdminOrigin, cfg.PublicOrigin, func(c context.Context) (store.S3Member, error) {
		probe, e := repo.S3StartProbe(c, newMemberID, newMember.Revision, store.NodeAudit{})
		if e != nil {
			return store.S3Member{}, e
		}
		return repo.S3FinishProbe(c, probe.ID, probe.Revision, store.S3ProbeResult{Key: probe.Key, ProviderUploadID: "fixture-probe", ETag: "fixture-etag", ChecksPassed: true, CleanupSettled: true}, store.NodeAudit{})
	})
	if err != nil {
		t.Fatal("fixture probe", err)
	}
	enabledMember, err := public.media.S3ConfigureMember(ctx, newMemberID, newMember.Revision, s3media.Configuration{Name: newMember.Name, Location: newMember.Location, Quota: newMember.Allocation, Enabled: true}, store.NodeAudit{})
	if err != nil || enabledMember.Enabled == 0 {
		t.Fatal("verified new member was not enabled", err)
	}
	members := request("GET", "/nodes/s3", nil)
	if members.Code != http.StatusOK || strings.Contains(members.Body.String(), "fixture-only-secret-key") || !strings.Contains(members.Body.String(), "second-bucket") {
		t.Fatal("selected S3 member list", members.Code)
	}
	browser, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session := request("POST", "/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(browser.PublicKey().Bytes())})
	var sessionValue mediacrypto.SessionGrant
	if session.Code != 200 || json.Unmarshal(session.Body.Bytes(), &sessionValue) != nil {
		t.Fatal("session", session.Code, session.Body.String())
	}
	prepare := request("POST", "/crypto/prepare", gin.H{"session_id": sessionValue.SessionID, "plaintext_size": 7})
	var generated struct {
		Encryption mediacrypto.Metadata `json:"encryption"`
		Token      string               `json:"preparation_token"`
	}
	if prepare.Code != 200 || json.Unmarshal(prepare.Body.Bytes(), &generated) != nil || generated.Token == "" {
		t.Fatal("prepare", prepare.Code, prepare.Body.String())
	}
	ciphertext := bytes.Repeat([]byte{9}, int(generated.Encryption.CiphertextSize))
	digest := sha256.Sum256(ciphertext)
	uploadID := strings.Repeat("3", 32)
	uploadRequest := business.SelectedPrepareRequest{UploadID: uploadID, ParentPath: "music/category", Filename: "song.mp3", MemberID: member, CipherSHA256: hex.EncodeToString(digest[:]), S3PartSHA256: []string{base64.StdEncoding.EncodeToString(digest[:])}, Encryption: generated.Encryption, Preparation: generated.Token}
	missingCommitment := uploadRequest
	missingCommitment.S3PartSHA256 = nil
	if rejected := request("POST", "/upload/selected/prepare", missingCommitment); rejected.Code == http.StatusOK || provider.creates != 0 {
		t.Fatal("uncommitted S3 reservation accepted", rejected.Code)
	}
	if _, err = database.Database().Exec(`UPDATE public_ingress_config SET public_origin=? WHERE singleton=1`, "https://other.example"); err != nil {
		t.Fatal(err)
	}
	if stale := request("POST", "/upload/selected/prepare", uploadRequest); stale.Code == http.StatusOK || provider.creates != 0 {
		t.Fatal("unprobed ingress accepted a reservation", stale.Code)
	}
	if _, err = database.Database().Exec(`UPDATE public_ingress_config SET public_origin=? WHERE singleton=1`, cfg.PublicOrigin); err != nil {
		t.Fatal(err)
	}
	ticket := request("POST", "/upload/selected/prepare", uploadRequest)
	var selected business.SelectedDirectTicket
	if ticket.Code != 200 || json.Unmarshal(ticket.Body.Bytes(), &selected) != nil || selected.Transport != "S3" || selected.MemberID != member {
		t.Fatal("S3 ticket", ticket.Code, ticket.Body.String())
	}
	base := "/upload/s3/" + uploadID
	status := request("GET", base, nil)
	if status.Code != 200 || !strings.Contains(status.Body.String(), `"state":"reserved"`) {
		t.Fatal("status", status.Code, status.Body.String())
	}
	if _, err = database.Database().Exec(`UPDATE public_ingress_config SET public_origin=? WHERE singleton=1`, "https://other.example"); err != nil {
		t.Fatal(err)
	}
	if stale := request("POST", base+"/begin", gin.H{}); stale.Code == http.StatusOK || provider.creates != 0 {
		t.Fatal("unprobed ingress reached provider", stale.Code)
	}
	if _, err = database.Database().Exec(`UPDATE public_ingress_config SET public_origin=? WHERE singleton=1`, cfg.PublicOrigin); err != nil {
		t.Fatal(err)
	}
	begin := request("POST", base+"/begin", gin.H{})
	if begin.Code != 200 || !strings.Contains(begin.Body.String(), `"state":"created"`) {
		t.Fatal("begin", begin.Code, begin.Body.String())
	}
	begin = request("POST", base+"/begin", gin.H{})
	if begin.Code != 200 || provider.creates != 1 {
		t.Fatal("begin replay", begin.Code)
	}
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	wrongDigest := sha256.Sum256([]byte("different ciphertext"))
	if rejected := request("POST", base+"/parts/1/grant", gin.H{"size_bytes": len(ciphertext), "checksum_sha256": base64.StdEncoding.EncodeToString(wrongDigest[:])}); rejected.Code == http.StatusOK {
		t.Fatal("substituted part grant accepted", rejected.Code)
	}
	provider.onSign = func() {
		if _, e := database.Database().Exec(`UPDATE public_ingress_config SET public_origin=? WHERE singleton=1`, "https://other.example"); e != nil {
			t.Fatal(e)
		}
	}
	if stale := request("POST", base+"/parts/1/grant", gin.H{"size_bytes": len(ciphertext), "checksum_sha256": checksum}); stale.Code == http.StatusOK || strings.Contains(stale.Body.String(), "s3.fixture.test") {
		t.Fatal("changed ingress exposed a signed grant", stale.Code)
	}
	provider.onSign = nil
	if _, err = database.Database().Exec(`UPDATE public_ingress_config SET public_origin=? WHERE singleton=1`, cfg.PublicOrigin); err != nil {
		t.Fatal(err)
	}
	grant := request("POST", base+"/parts/1/grant", gin.H{"size_bytes": len(ciphertext), "checksum_sha256": checksum})
	if grant.Code != 200 || !strings.Contains(grant.Body.String(), `"url"`) {
		t.Fatal("grant", grant.Code, grant.Body.String())
	}
	provider.parts = []s3store.Part{{Number: 1, Size: int64(len(ciphertext)), SHA256: checksum, ETag: `"part"`}}
	confirm := request("POST", base+"/parts/1/confirm", gin.H{})
	if confirm.Code != 200 || !strings.Contains(confirm.Body.String(), `"confirmed":true`) {
		t.Fatal("confirm", confirm.Code, confirm.Body.String())
	}
	composite := sha256.Sum256(digest[:])
	provider.proof = s3store.Proof{Size: int64(len(ciphertext)), ETag: `"object"`, VersionID: "v1", ChecksumType: "COMPOSITE", ChecksumSHA256: base64.StdEncoding.EncodeToString(composite[:]) + "-1", Metadata: map[string]string{"fc-format": store.S3OpaqueMetadata, "fc-owner": provider.owner}}
	finished := request("POST", base+"/finalize", gin.H{})
	if finished.Code != 200 || !strings.Contains(finished.Body.String(), `"state":"published"`) {
		t.Fatal("finalize", finished.Code, finished.Body.String())
	}
	finished = request("POST", base+"/finalize", gin.H{})
	if finished.Code != 200 || provider.completes != 1 {
		t.Fatal("finalize replay", finished.Code, finished.Body.String())
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	parent, err := tree.ResolveDirectoryWithLease(ctx, lease, "music/category", false)
	if err != nil {
		t.Fatal(err)
	}
	items, _, err := tree.ListCatalogPageWithLease(ctx, lease, parent, "", 10, false)
	if err != nil || len(items) != 1 || items[0].S3Placement == nil {
		t.Fatal("finalized S3 listing", err)
	}
	item := items[0]
	admitted, admission := network.WithPublicAdmission(ctx)
	defer admission.Abort()
	admitted = store.WithIngressPrerequisite(admitted, lease)
	object, placement, err := public.media.OpaquePublicS3Media(admitted, tree, "music/category/song.mp3", item.Entry.ObjectID, item.S3Placement.Proof.ObjectID)
	if err != nil || object.ID != item.Entry.ObjectID || placement.Proof != item.S3Placement.Proof || object.Encryption == nil || *object.Encryption != generated.Encryption {
		t.Fatal("authenticated S3 tree lookup", err)
	}
	if _, _, err = public.media.OpaquePublicS3Media(admitted, tree, "music/category/other.mp3", item.Entry.ObjectID, item.S3Placement.Proof.ObjectID); err == nil {
		t.Fatal("accepted a different path")
	}
	if _, _, err = public.media.OpaquePublicS3Media(admitted, tree, "music/category/song.mp3", item.Entry.ObjectID, strings.Repeat("f", 64)); err == nil {
		t.Fatal("accepted a different provider object")
	}
	response := httptest.NewRecorder()
	requestContext, _ := gin.CreateTestContext(response)
	requestContext.Request = httptest.NewRequest(http.MethodPost, "https://master.test/api/v1/media/crypto/key", nil).WithContext(admitted)
	public.opaqueEncryptedMediaKey(requestContext, "admin:"+login.Hash, cryptoKeyBody{SessionID: sessionValue.SessionID, FilePath: "music/category/song.mp3", ResourceID: item.Entry.ObjectID, ObjectID: item.S3Placement.Proof.ObjectID})
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "source_url") || strings.Contains(response.Body.String(), "key_envelope") {
		t.Fatal("unavailable S3 read signer returned a source", response.Code)
	}
	admission.Abort()
	if _, _, err = public.media.OpaquePublicS3Media(admitted, tree, "music/category/song.mp3", item.Entry.ObjectID, item.S3Placement.Proof.ObjectID); err == nil {
		t.Fatal("accepted an ended public admission")
	}
}
