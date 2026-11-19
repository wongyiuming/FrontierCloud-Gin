package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestLogReplicaAuthenticatedCanonicalTransferAndBrowserRead(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, mdb, _, mpub, master := clusterFixture(t, "https://master.test", transport, true)
	router, _, dir, pub, peer := clusterFixture(t, "https://logs.test", transport, true)
	if _, e := master.Promote(ctx, "Master", "https://master.test", store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := peer.Promote(ctx, "Follower", "https://logs.test", 0, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	pair, e := peer.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	id, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	rel, e := mdb.Nodes().Relationship(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	settings := pub.settings
	settings.DataRoot = dir
	resolver, _ := network.New(nil)
	closeReplica := RegisterLogReplica(router, settings, resolver, peer)
	t.Cleanup(func() { closeReplica() })
	private, e := vault.OpenExisting(mpub.settings.SecretsDirectory)
	if e != nil {
		t.Fatal(e)
	}
	identity, e := master.IdentityState(ctx)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	record, ciphertext, e := logarchive.Seal(private, identity.ID, logarchive.Audit, now, now.Add(time.Millisecond), bytes.Repeat([]byte("x"), logarchive.MaxPlainBytes))
	if e != nil {
		t.Fatal(e)
	}
	target := logarchive.Target{MemberID: rel.PeerID, RelationshipID: id, Origin: "https://logs.test"}
	remote := &logRemote{node: master}
	if e = remote.Store(ctx, target, record.Reference(), ciphertext, now.Add(logarchive.Retention).Unix()); e != nil {
		t.Fatal("signed ciphertext upload failed", e)
	}
	if e = remote.Verify(ctx, target, record.Reference()); e != nil {
		t.Fatal("remote verification failed", e)
	}
	grant, e := master.LogReadGrant(ctx, target, record.Reference(), "https://admin.test")
	if e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(grant)
	request := httptest.NewRequest("POST", "https://logs.test"+logBlobPath, bytes.NewReader(body))
	request.Header.Set("Origin", "https://admin.test")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), ciphertext) || response.Header().Get("Access-Control-Allow-Origin") != "https://admin.test" {
		t.Fatal("browser ciphertext read failed", response.Code, response.Body.String())
	}
}
