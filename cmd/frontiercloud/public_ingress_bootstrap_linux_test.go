//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// The relationship and heartbeat are synthetic; the repository, nonce store,
// node HMAC and signed Master identity are real. This does not enable ingress.
func TestMasterProbeOnlyAuthenticatesPairedNodeAndRejectsReplay(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(dir, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	identity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().ExecContext(ctx, "UPDATE node_identity SET role='Master', endpoint='https://master.test' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	master := node.NewService(db.Nodes(), identity, nil)
	nodeVault, err := vault.OpenExisting(filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	credential := protocol.Encode(bytes.Repeat([]byte{7}, 48))
	sealed, err := nodeVault.Seal(credential)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer, relationship := strings.Repeat("a", 32), strings.Repeat("b", 32)
	relation := store.Relationship{ID: relationship, PeerID: peer, Endpoint: "https://follower.test", PublicKey: protocol.Encode(pub), Credential: sealed, Direction: "downstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: time.Now().Unix()}
	if err = db.Nodes().PrepareRelationship(ctx, relation, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = db.Nodes().ActivateRelationship(ctx, relationship, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	summary := map[string]any{"capabilities": []string{protocol.PublicIngressProxyCapability}, "public_ingress_candidate_origin": "https://candidate.test"}
	if err = db.Nodes().RecordHeartbeat(ctx, relationship, true, 1, summary, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(masterIngressProbeOnly(master, resolver))
	defer server.Close()
	body, err := json.Marshal(struct {
		PeerID    string `json:"peer_id"`
		Origin    string `json:"origin"`
		Challenge string `json:"challenge"`
	}{peer, "https://candidate.test", strings.Repeat("c", 32)})
	if err != nil {
		t.Fatal(err)
	}
	makeRequest := func(signed bool) *http.Request {
		req, e := http.NewRequest(http.MethodPost, server.URL+node.IngressCandidateEdgePath, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		if signed {
			headers, e := protocol.AuthHeaders(credential, relationship, http.MethodPost, "/internal/v1/public-ingress-candidate-proof", body, time.Now().Unix())
			if e != nil {
				t.Fatal(e)
			}
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
		return req
	}
	req := makeRequest(true)
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var proof node.Envelope
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	err = decoder.Decode(&proof)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || proof.Payload["challenge"] != strings.Repeat("c", 32) {
		t.Fatal("paired challenge", response.StatusCode, err)
	}
	masterPublic, ok := proof.Payload["public_key"].(string)
	masterPrivate, err := nodeVault.Unseal(identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	pinnedPublic, err := protocol.PublicKey(masterPrivate)
	if !ok || err != nil || masterPublic != pinnedPublic || protocol.Verify(pinnedPublic, proof.Payload, proof.Signature) != nil {
		t.Fatal("invalid signed Master identity")
	}
	replay := req.Clone(ctx)
	replay.Body = io.NopCloser(bytes.NewReader(body))
	response, err = server.Client().Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("replayed probe accepted", response.StatusCode)
	}
	response, err = server.Client().Do(makeRequest(false))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("unsigned probe accepted", response.StatusCode)
	}
	if err = db.Nodes().RecordHeartbeat(ctx, relationship, true, 1, summary, time.Now().Unix()-121); err != nil {
		t.Fatal(err)
	}
	response, err = server.Client().Do(makeRequest(true))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("stale heartbeat accepted", response.StatusCode)
	}
}

func TestMasterBootstrapListenerKeepsBusinessClosedUntilPublish(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gate, err := maintenance.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	runtime, err := gate.Runtime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	control := &candidateEdgeFixture{edgeFixture: &edgeFixture{master: "https://master.test", nonces: map[string]bool{}}}
	resolver, err := network.New([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := startMasterIngressBootstrap(ctx, "127.0.0.1:0", runtime, control, resolver)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { runtime.Stop(); bootstrap.server.Close(); bootstrap.listener.Close(); runtime.WaitHTTP() }()
	base := "http://" + bootstrap.listener.Addr().String()
	request := func(method, path, body string) *http.Response {
		r, e := http.NewRequestWithContext(ctx, method, base+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Real-IP", "192.0.2.1")
		r.Header.Set("X-Node-Signature", "fixture")
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		response.Body.Close()
		return response
	}
	if response := request(http.MethodGet, "/api/v1/media/catalog/media", ""); response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("business visible before publish", response.StatusCode)
	}
	if response := request(http.MethodPost, node.IngressCandidateEdgePath, "{}"); response.StatusCode != http.StatusOK {
		t.Fatal("bootstrap probe unavailable", response.StatusCode)
	}
	bootstrap.publish(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	if response := request(http.MethodGet, "/api/v1/media/catalog/media", ""); response.StatusCode != http.StatusNoContent {
		t.Fatal("published route unavailable", response.StatusCode)
	}
}
