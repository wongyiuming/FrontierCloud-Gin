package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type selectedPickerTestGate struct{}

func (selectedPickerTestGate) AcquireSelectedUpload(context.Context, *sealedtree.SQLStore) (business.SelectedUploadRuntimeLease, error) {
	return nil, store.ErrNodeState
}

func TestLocalUploadRejectsAnotherExplicitOwnerBeforePublication(t *testing.T) {
	router, db, _, public := publicFixture(t, false)
	a := &Admin{public: public, settings: public.settings}
	router.POST("/selected-local-upload", func(c *gin.Context) { a.upload(c, false) })
	for _, field := range []string{"storage_member_id", "member_id"} {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		for key, value := range map[string]string{field: strings.Repeat("f", 32), "storage_mode": "plain", "target_dir": "music/SelectedLocal"} {
			if err := writer.WriteField(key, value); err != nil {
				t.Fatal(err)
			}
		}
		file, err := writer.CreateFormFile("file", "song.mp3")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("ID3payload")); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("POST", "/selected-local-upload", &body)
		request.Header.Set("Content-Type", writer.FormDataContentType())
		w := httptest.NewRecorder()
		router.ServeHTTP(w, request)
		if w.Code != 409 {
			t.Fatal("explicit owner ignored", field, w.Code, w.Body.String())
		}
	}
	var count int
	if err := db.Database().QueryRow("SELECT COUNT(*) FROM media_objects WHERE media_path=?", "music/SelectedLocal/song.mp3").Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected target was published", count, err)
	}
}

func TestSelectedDestinationHTTPChoosesExactPeerAndNeverFallsBack(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, db, _, public, master := clusterFixture(t, "https://master.test", transport, false)
	if _, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	relations := []store.Relationship{}
	for _, origin := range []string{"https://first.test", "https://chosen.test"} {
		_, _, _, _, follower := clusterFixture(t, origin, transport, true)
		if _, err := follower.Promote(ctx, "Follower", origin, 0, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		pair, err := follower.CreatePair(ctx, store.NodeAudit{})
		if err != nil {
			t.Fatal(err)
		}
		id, err := master.ImportPair(ctx, pair, store.NodeAudit{})
		if err != nil {
			t.Fatal(err)
		}
		relation, err := db.Nodes().Relationship(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		cfg := store.ResourceConfiguration{}
		cfg.Storage.Enabled, cfg.Storage.Allocation = true, 5*store.GiB
		if err := db.Pool().ConfigureMember(ctx, relation.PeerID, cfg, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		if err := master.Tick(ctx, relation); err != nil {
			t.Fatal(err)
		}
		if err := db.Nodes().SetRelationshipMode(ctx, id, "Direct", false, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		relations = append(relations, relation)
	}
	resolver, _ := network.New(nil)
	a := &Admin{public: public, settings: public.settings, network: resolver}
	sessionHash := strings.Repeat("1", 64)
	g := router.Group("/api/v1/media/admin", func(c *gin.Context) { c.Set("admin_session", admin.Session{Hash: sessionHash}); c.Next() })
	g.POST("/upload/session", a.reserveUpload)
	g.GET("/storage-pool", a.storagePool)
	request := func(method, route string, body any) *httptest.ResponseRecorder {
		encoded, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "https://master.test"+route, strings.NewReader(string(encoded)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/api/v1/media/admin/storage-pool", nil)
	var pool struct {
		Destinations []media.UploadDestination `json:"upload_destinations"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &pool) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, rel := range relations {
		found := false
		for _, d := range pool.Destinations {
			if d.MemberID == rel.PeerID {
				found = d.Address != nil && *d.Address == rel.Endpoint && d.Site == "direct" && d.Writable
			}
		}
		if !found {
			t.Fatal("paired address and stable member ID absent", rel.PeerID, pool.Destinations)
		}
	}
	if strings.Contains(w.Body.String(), "credential") || strings.Contains(w.Body.String(), "public_key") {
		t.Fatal("destination list leaked private relationship fields")
	}
	upload := func(member, folder, filename string) *httptest.ResponseRecorder {
		body, _ := encryptedAdminUploadFixture(t, public, sessionHash, []byte("ID3payload"), gin.H{"storage_member_id": member, "site_type": "primary", "target_dir": folder, "filename": filename})
		return request("POST", "/api/v1/media/admin/upload/session", body)
	}
	for _, bad := range []string{"", "auto", "https://chosen.test", strings.Repeat("f", 32)} {
		if w := upload(bad, "music/Rejected", "a.mp3"); w.Code != 409 {
			t.Fatal("invalid target admitted", bad, w.Code, w.Body.String())
		}
	}
	w = upload(relations[1].PeerID, "music/Chosen", "a.mp3")
	var ticket media.UploadTicket
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ticket) != nil || ticket.MemberID != relations[1].PeerID || !strings.HasPrefix(ticket.URL, "https://chosen.test/") || ticket.Site != "direct" {
		t.Fatal("requested owner not honored", w.Code, w.Body.String())
	}
	if w := upload(relations[0].PeerID, "music/Chosen", "b.mp3"); w.Code != 409 {
		t.Fatal("folder affinity ignored", w.Code, w.Body.String())
	}
	disabled := store.ResourceConfiguration{}
	disabled.Storage.Allocation = 5 * store.GiB
	if err := db.Pool().ConfigureMember(ctx, relations[1].PeerID, disabled, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if w := upload(relations[1].PeerID, "music/Unavailable", "a.mp3"); w.Code != 409 {
		t.Fatal("disabled destination fell back", w.Code, w.Body.String())
	}
	var count int
	if err := db.Database().QueryRow("SELECT COUNT(*) FROM cluster_upload_sessions").Scan(&count); err != nil || count != 1 {
		t.Fatal("rejected requests changed reservations", count, err)
	}
	var reserved int64
	if err := db.Database().QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", relations[0].PeerID).Scan(&reserved); err != nil || reserved != 0 {
		t.Fatal("another owner received reservation", reserved, err)
	}
	// Reproduce stale placement transport independently of the paired mode.
	if _, err := db.Database().Exec("UPDATE cluster_storage_members SET transport='Relay' WHERE member_id=?", relations[0].PeerID); err != nil {
		t.Fatal(err)
	}
	if w := upload(relations[0].PeerID, "music/StaleTransport", "a.mp3"); w.Code != 409 {
		t.Fatal("inconsistent member/relationship mode accepted", w.Code, w.Body.String())
	}
	if _, err := db.Database().Exec("UPDATE cluster_storage_members SET transport='Direct' WHERE member_id=?", relations[0].PeerID); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().RecordHeartbeat(ctx, relations[0].ID, true, 0, map[string]any{}, time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if w := upload(relations[0].PeerID, "music/FutureHeartbeat", "a.mp3"); w.Code != 409 {
		t.Fatal("future heartbeat admitted", w.Code, w.Body.String())
	}
	if err := db.Nodes().RecordHeartbeat(ctx, relations[0].ID, true, 0, map[string]any{}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().Exec("UPDATE node_relationships SET protocol=0 WHERE relationship_id=?", relations[0].ID); err != nil {
		t.Fatal(err)
	}
	if w := upload(relations[0].PeerID, "music/InvalidProtocol", "a.mp3"); w.Code != 409 {
		t.Fatal("unsupported protocol reserved capacity", w.Code, w.Body.String())
	}
	if _, err := db.Database().Exec("UPDATE node_relationships SET protocol=?,credential='broken-envelope' WHERE relationship_id=?", relations[0].Protocol, relations[0].ID); err != nil {
		t.Fatal(err)
	}
	if w := upload(relations[0].PeerID, "music/BrokenCredential", "a.mp3"); w.Code != 409 {
		t.Fatal("unusable credential reserved capacity", w.Code, w.Body.String())
	}
	if err := db.Database().QueryRow("SELECT COUNT(*) FROM cluster_upload_sessions").Scan(&count); err != nil || count != 1 {
		t.Fatal("preflight failure left a new reservation", count, err)
	}
	if _, err := db.Database().Exec("UPDATE node_relationships SET credential=? WHERE relationship_id=?", relations[0].Credential, relations[0].ID); err != nil {
		t.Fatal(err)
	}
	// A real independently applied Direct resource origin must not inherit the
	// old token/URL aimed at the node's control listener.
	routing := db.Nodes().(store.PublicRoutingRepository)
	if err := routing.ConfigurePublicOrigin("https://master.test"); err != nil {
		t.Fatal(err)
	}
	policy, err := routing.ConfirmNativeTransport(ctx, relations[0].PeerID, "Direct", 0, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	reportDirectOrigin := func(origin string) {
		t.Helper()
		summary := map[string]any{"native_resource_origin": origin, "storage": map[string]any{"physical_free_bytes": 10 * store.GiB}}
		if err := db.Nodes().RecordHeartbeat(ctx, relations[0].ID, true, 0, summary, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	reportDirectOrigin("https://resource-first.test")
	application := db.Nodes().(interface {
		RecordNativeDirectApplication(context.Context, string, int64, string) error
	})
	if err := application.RecordNativeDirectApplication(ctx, relations[0].ID, policy.Revision, "https://resource-first.test"); err != nil {
		t.Fatal(err)
	}
	if w := upload(relations[0].PeerID, "music/SeparateResourceOrigin", "a.mp3"); w.Code != 409 {
		t.Fatal("resource/control origin mismatch used legacy upload", w.Code, w.Body.String())
	}
	w = request("GET", "/api/v1/media/admin/storage-pool", nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &pool) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, d := range pool.Destinations {
		if d.MemberID == relations[0].PeerID && d.Writable {
			t.Fatal("incompatible legacy destination was shown ready")
		}
	}
	owner := relations[0]
	reportDirectOrigin(owner.Endpoint)
	if err := application.RecordNativeDirectApplication(ctx, owner.ID, policy.Revision, owner.Endpoint); err != nil {
		t.Fatal(err)
	}
	// Exercise Admin selection against a distinct ingress record without
	// claiming that this fixture ran the production ingress activation gate.
	if _, err := db.Database().Exec("UPDATE public_ingress_config SET node_id=?,public_origin=?,generation=generation+1 WHERE singleton=1", owner.PeerID, owner.Endpoint); err != nil {
		t.Fatal(err)
	}
	identity, err := db.Nodes().ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w = upload(identity.ID, "music/LocalWithPeerIngress", "a.mp3")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ticket) != nil || ticket.MemberID != identity.ID || ticket.Transport != "Local" {
		t.Fatal("ingress moved Admin's selected local owner", w.Code, w.Body.String())
	}
	repo := db.Nodes().(*business.Repository)
	repo.EnablePeerIngress()
	activePolicy, err := routing.NativeTransport(ctx, owner.PeerID)
	if err != nil || activePolicy.State != "retained" || activePolicy.EffectiveTransport != "Local" || activePolicy.AppliedTransport != "Direct" {
		t.Fatalf("invalid active Direct ingress fixture: %+v, %v", activePolicy, err)
	}
	checkPicker := func(selected, writable bool) {
		t.Helper()
		w := request("GET", "/api/v1/media/admin/storage-pool", nil)
		var result struct {
			Standalone   *bool                     `json:"standalone"`
			Selected     bool                      `json:"selected_upload"`
			Destinations []media.UploadDestination `json:"upload_destinations"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Standalone == nil || *result.Standalone || result.Selected != selected {
			t.Fatal("storage pool protocol differs", w.Code, w.Body.String())
		}
		for _, destination := range result.Destinations {
			if destination.MemberID == owner.PeerID {
				if destination.Site != "direct" || destination.Address == nil || *destination.Address != owner.Endpoint || destination.Writable != writable {
					t.Fatalf("unexpected Direct destination: %+v, writable expected %v", destination, writable)
				}
				return
			}
		}
		t.Fatal("Direct destination missing")
	}
	checkPicker(false, false)
	// Only destination observation is under test. The fixture cannot issue
	// selected upload grants or mutate the encrypted tree.
	nodeVault, err := vault.OpenExisting(public.settings.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	public.opaqueTree = &sealedtree.SQLStore{}
	a.settings.AdminOrigin = "https://master.test"
	runtime, err := business.NewSelectedUploadRuntime(repo, public.opaqueTree, bytes.Repeat([]byte{7}, 32), public.crypto, nodeVault, a.settings.AdminOrigin, selectedPickerTestGate{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ConfigureSelectedUploadRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	checkPicker(true, true)
	reportDirectOrigin("https://changed-resource.test")
	checkPicker(true, false)
}
