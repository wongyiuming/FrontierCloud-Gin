package business_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestOfflineStorageEndpointPreservesIdentityAndOwnership(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "native.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	before, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: id, Role: "Standalone", PrivateKey: "retained-secret"})
	if err != nil {
		t.Fatal(err)
	}
	before, err = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Follower", Endpoint: "https://disk.test", PhysicalFree: 10 * store.GiB}, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	objects, err := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: "music/retained.mp3", Kind: "audio"}})
	if err != nil {
		t.Fatal(err)
	}
	writer := db.Nodes().(interface {
		MoveStorageEndpoint(context.Context, string, string, string) error
	})
	for _, next := range []string{"https://disk.test", "https://disk.test:443", "http://disk.test:8443", "https://user:pass@disk.test:8443", "https://disk.test:8443/path", "https://disk.test:8443?q=1"} {
		if err := writer.MoveStorageEndpoint(ctx, id, before.Endpoint, next); err == nil {
			t.Fatal("unsafe endpoint accepted", next)
		}
	}
	next := "https://disk.test:8443"
	if err := writer.MoveStorageEndpoint(ctx, strings.Repeat("b", 32), before.Endpoint, next); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong identity accepted", err)
	}
	raw := db.Database()
	if _, err := raw.Exec("CREATE TRIGGER fail_endpoint_audit BEFORE INSERT ON node_audit WHEN NEW.action='storage-endpoint-moved' BEGIN SELECT RAISE(ABORT,'injected'); END"); err != nil {
		t.Fatal(err)
	}
	if err := writer.MoveStorageEndpoint(ctx, id, before.Endpoint, next); err == nil {
		t.Fatal("audit failure committed")
	}
	actual, err := db.Nodes().ReadIdentity(ctx)
	if err != nil || actual != before {
		t.Fatal("identity escaped transaction", err)
	}
	if _, err := raw.Exec("DROP TRIGGER fail_endpoint_audit"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := writer.MoveStorageEndpoint(ctx, id, before.Endpoint, next); err != nil {
			t.Fatal(err)
		}
	}
	actual, err = db.Nodes().ReadIdentity(ctx)
	before.Endpoint = next
	if err != nil || actual != before {
		t.Fatal("identity rotated", err)
	}
	object, err := db.Media().ObjectByID(ctx, objects["music/retained.mp3"])
	if err != nil || object.Path != "music/retained.mp3" {
		t.Fatal("owned object lost", err)
	}
}

func TestOfflineMasterStorageRebindGuardsAndPreservesRelationship(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	raw := db.(interface{ Database() *sql.DB }).Database()
	identity, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "rebind-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Role == "Standalone" {
		if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
	} else if identity.Role != "Master" {
		t.Fatal("fixture has non-Master identity")
	}
	rel := store.Relationship{ID: "de" + strings.Repeat("b", 30), PeerID: "de" + strings.Repeat("c", 30), Endpoint: "https://disk.test", PublicKey: strings.Repeat("A", 43), Credential: "retained-encrypted-secret", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: time.Now().Unix()}
	t.Cleanup(func() {
		raw.Exec("DELETE FROM node_relationships WHERE relationship_id=?", rel.ID)
		raw.Exec("DELETE FROM cluster_storage_members WHERE member_id=?", rel.PeerID)
	})
	if err := db.Nodes().PrepareRelationship(ctx, rel, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().ActivateRelationship(ctx, rel.ID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	rel, err = db.Nodes().Relationship(ctx, rel.ID)
	if err != nil {
		t.Fatal(err)
	}
	writer := db.Nodes().(interface {
		RebindStorageEndpoint(context.Context, string, store.Relationship, string) error
	})
	next := "https://disk.test:8443"
	wrong := rel
	wrong.PublicKey = strings.Repeat("B", 43)
	if err := writer.RebindStorageEndpoint(ctx, identity.ID, wrong, next); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("peer key race ignored", err)
	}
	if _, err := raw.Exec("UPDATE cluster_storage_members SET reserved_bytes=1 WHERE member_id=?", rel.PeerID); err != nil {
		t.Fatal(err)
	}
	if err := writer.RebindStorageEndpoint(ctx, identity.ID, rel, next); !errors.Is(err, store.ErrBackupBusy) {
		t.Fatal("reserved upload ignored", err)
	}
	if _, err := raw.Exec("UPDATE cluster_storage_members SET reserved_bytes=0 WHERE member_id=?", rel.PeerID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := writer.RebindStorageEndpoint(ctx, identity.ID, rel, next); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := db.Nodes().Relationship(ctx, rel.ID)
	if err != nil || actual.Endpoint != next || actual.PeerID != rel.PeerID || actual.PublicKey != rel.PublicKey || actual.Credential != rel.Credential || actual.Mode != rel.Mode || actual.State != rel.State {
		t.Fatal("relationship ownership changed", err)
	}
}
