package httpapi

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type testCertificateAgent struct{ calls int }

func (a *testCertificateAgent) Control(context.Context, certificate.Request) (certificate.View, error) {
	a.calls++
	return certificate.View{Hostname: "storage.fixture.test", Managed: true, Job: certificate.Job{State: "running"}}, nil
}
func TestStorageCertificateHTTPUsesSignedOwnerAndStrictBody(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, md, _, _, master := clusterFixture(t, "https://master.fixture.test", transport, false)
	router, _, _, public, follower := clusterFixture(t, "https://storage.fixture.test", transport, true)
	if _, e := master.Promote(ctx, "Master", "https://master.fixture.test", 10*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := follower.Promote(ctx, "Follower", "https://storage.fixture.test", 0, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	pair, e := follower.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	id, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	r, _ := md.Nodes().Relationship(ctx, id)
	agent := &testCertificateAgent{}
	follower.ConfigureNetwork(3478, agent, func() certificate.View {
		return certificate.View{Hostname: "storage.fixture.test", State: "valid", Fingerprint: "public-fingerprint"}
	}, nil)
	master.ConfigureNetwork(0, nil, nil, md.Admin())
	cfg := public.settings
	cfg.DeploymentMode = config.DeploymentStorage
	resolver, _ := network.New(nil)
	RegisterNodeCertificate(router, cfg, resolver, follower)
	if w := request(router, "POST", "https://storage.fixture.test/internal/v1/certificate", `{"action":"renew"}`); w.Code != 401 {
		t.Fatal("anonymous reached certificate control", w.Code)
	}
	result, e := master.Certificate(ctx, id, certificate.Request{Action: "renew"}, store.NodeAudit{Actor: "admin"})
	if e != nil || result["fingerprint"] != "public-fingerprint" || agent.calls != 1 {
		t.Fatal(result, e, agent.calls)
	}
	for _, value := range []map[string]any{{"action": "renew", "hostname": "other.fixture.test"}, {"action": "renew", "http01_directory": "/private"}, {"action": "renew", "command": "stop-business"}, {"action": "reset"}} {
		if _, e = master.Call(ctx, r, "/internal/v1/certificate", value); e == nil {
			t.Fatal("unsafe certificate operation admitted", value)
		}
	}
	if _, e = master.Call(ctx, r, "/internal/v1/certificate?other=1", map[string]any{"action": "renew"}); e == nil {
		t.Fatal("unsigned query accepted")
	}
	if agent.calls != 1 {
		t.Fatal("rejected request reached agent", agent.calls)
	}
	if e = master.Revoke(ctx, id, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = master.Call(ctx, r, "/internal/v1/certificate", map[string]any{"action": "renew"}); e == nil {
		t.Fatal("revoked signed owner admitted")
	}
}
