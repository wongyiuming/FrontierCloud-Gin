package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type candidateHTTPTransport struct {
	*clusterHTTP
	master *node.Service
	fail   bool
}

type candidateMasterHTTPTransport struct {
	*clusterHTTP
	follower *node.Service
}

func (t *candidateMasterHTTPTransport) CandidatePublic(ctx context.Context, origin string, body []byte, headers http.Header) (map[string]any, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	signed, err := t.follower.VerifyCandidatePublicProbe(ctx, u.Host, headers, body)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := controlJSON(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (t *candidateHTTPTransport) CandidateEdge(ctx context.Context, origin string, body []byte, headers http.Header) (map[string]any, error) {
	if t.fail || origin != "https://master.test" {
		return nil, errors.New("unavailable")
	}
	signed, err := t.master.VerifyCandidateEdge(ctx, headers, body)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := controlJSON(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func TestCandidateControlHTTPRequiresPairAndDoesNotSelect(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, masterDB, masterDir, _, master := clusterFixture(t, "https://master.test", transport, false)
	followerRouter, followerDB, followerDir, followerPublic, follower := clusterFixture(t, "https://follower.test", transport, true)
	if _, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := follower.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := follower.ConfigureFollowerIngressCandidate("https://candidate.test"); err != nil {
		t.Fatal(err)
	}
	transport.routers["https://candidate.test"] = followerRouter
	pkg, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pkg, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := masterDB.Nodes().Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := master.Tick(ctx, relation); err != nil {
		t.Fatal(err)
	}
	routing := masterDB.Nodes().(store.PublicRoutingRepository)
	before, err := routing.PublicIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := node.Initialize(ctx, followerDB.Nodes(), filepath.Join(followerDir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	edge := &candidateHTTPTransport{clusterHTTP: transport, master: master}
	candidate := node.NewService(followerDB.Nodes(), identity, edge)
	if err := candidate.ConfigureFollowerIngressCandidate("https://candidate.test"); err != nil {
		t.Fatal(err)
	}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	RegisterNodeIngressCandidateProbe(followerRouter, followerPublic.settings, resolver, candidate)
	masterIdentity, err := node.Initialize(ctx, masterDB.Nodes(), filepath.Join(masterDir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	probeMaster := node.NewService(masterDB.Nodes(), masterIdentity, &candidateMasterHTTPTransport{clusterHTTP: transport, follower: follower})
	if origin, err := probeMaster.VerifyFollowerIngressProxy(ctx, id); err != nil || origin != "https://candidate.test" {
		t.Fatal("authenticated control probe", origin, err)
	}
	if origin, err := probeMaster.CheckPublicIngressCandidate(ctx, relation.PeerID); err != nil || origin != "https://candidate.test" {
		t.Fatal("administrator candidate check", origin, err)
	}
	if after, err := routing.PublicIngress(ctx); err != nil || after != before {
		t.Fatal("probe selected ingress", after, err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://follower.test/internal/v1/public-ingress-probe", nil)
	response := httptest.NewRecorder()
	followerRouter.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("anonymous probe accepted", response.Code)
	}
	edge.fail = true
	if _, err := probeMaster.VerifyFollowerIngressProxy(ctx, id); err == nil {
		t.Fatal("unreachable Master edge accepted")
	}
}
