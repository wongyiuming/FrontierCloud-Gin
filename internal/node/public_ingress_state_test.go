package node

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestTypedNilIngressLeaseIsInvalid(t *testing.T) {
	var lease *testIngressLease
	if validIngressLease(lease) {
		t.Fatal("typed nil ingress lease accepted")
	}
}

func TestServiceUsesConfiguredPublicOriginForMasterLease(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: id, Role: "Standalone", PrivateKey: "sealed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://control.example", Allocation: store.GiB, PhysicalFree: 2 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	svc := NewService(db.Nodes(), nil, nil)
	if _, release, err := svc.AcquireCurrentIngress(ctx); err == nil || release != nil {
		t.Fatal("unconfigured origin admitted", err)
	}
	if err := svc.ConfigurePublicOrigin("https://public.example:443"); err != nil {
		t.Fatal(err)
	}
	current, release, err := svc.AcquireCurrentIngress(ctx)
	if err != nil || release == nil {
		t.Fatal(err)
	}
	defer release.Release()
	if current.NodeID != id || current.PublicOrigin != "https://public.example" || current.Generation != 1 {
		t.Fatal(current)
	}
}
