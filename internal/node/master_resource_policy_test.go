package node

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestMasterPolicyApplicationBoundToRevisionIngressAndRuntime(t *testing.T) {
	ctx := context.Background()
	service, db := testNode(t, "Master", "https://master.test", nil)
	identity, err := service.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := &masterDirectFixtureRepo{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), current: store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 3}, policy: store.NativeTransportPolicy{MemberID: identity.ID, ConfiguredTransport: "Direct", Revision: 4, State: "blocked"}}
	service.repo = r
	if err := service.PrepareMasterResourcePolicy(ctx); err == nil {
		t.Fatal("missing runtime verifier applied")
	}
	if p, err := service.MasterNativePolicy(ctx); err != nil || p.State != "blocked" || p.AppliedTransport != "" {
		t.Fatal("unverified policy", p, err)
	}
	if err := service.ConfigureMasterResourceReadiness("https://resource.test", func(_ context.Context, ingress store.PublicIngress, mode, origin string) error {
		if ingress != r.current || mode != "Direct" || origin != "https://resource.test" {
			return errors.New("wrong readiness context")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.PrepareMasterResourcePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if p, err := service.MasterNativePolicy(ctx); err != nil || p.State != "applied" || p.AppliedTransport != "Direct" || p.AppliedOrigin != "https://resource.test" || p.EffectiveTransport != "Direct" {
		t.Fatal("verified policy", p, err)
	}
	r.commitFail = true
	if err := service.PrepareMasterResourcePolicy(ctx); err == nil {
		t.Fatal("failed ingress lease accepted")
	}
	if p, err := service.MasterNativePolicy(ctx); err != nil || p.State != "blocked" || p.AppliedTransport != "" {
		t.Fatal("failed lease retained proof", p, err)
	}
	r.commitFail = false
	if err := service.PrepareMasterResourcePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	r.policy.Revision++
	if p, err := service.MasterNativePolicy(ctx); err != nil || p.State != "blocked" || p.AppliedTransport != "" {
		t.Fatal("stale revision applied", p, err)
	}
	if err := service.PrepareMasterResourcePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	r.current.Generation++
	if p, err := service.MasterNativePolicy(ctx); err != nil || p.State != "blocked" {
		t.Fatal("stale ingress applied", p, err)
	}
	if err := service.PrepareMasterResourcePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	service.masterPolicyMu.Lock()
	service.masterPolicy.verifiedAt = time.Now().Add(-masterResourceApplicationTTL)
	service.masterPolicyMu.Unlock()
	if p, err := service.MasterNativePolicy(ctx); err != nil || p.State != "blocked" {
		t.Fatal("expired readiness applied", p, err)
	}
	if err := service.ConfigureMasterResourceReadiness("https://resource.test", func(context.Context, store.PublicIngress, string, string) error { return errors.New("unavailable") }); err != nil {
		t.Fatal(err)
	}
	if err := service.PrepareMasterResourcePolicy(ctx); err == nil {
		t.Fatal("failed readiness applied")
	}
}
