package httpapi

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	storeSQLite "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func retirementApplyFixture(t *testing.T) (*node.Service, *storeSQLite.Store, *storeSQLite.Store, string, store.Relationship, *noderetirement.Service) {
	t.Helper()
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, masterDB, _, _, master := clusterFixtureRoots(t, "https://master.test", transport, true, []bool{true}, map[string]string{"retirement-provenance": "true"})
	_, peerDB, directory, _, peer := clusterFixtureRoots(t, "https://peer.test", transport, true, []bool{true}, map[string]string{"retirement-provenance": "true"})
	if _, e := master.Promote(ctx, "Master", "https://master.test", store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := peer.Promote(ctx, "Follower", "https://peer.test", 0, store.NodeAudit{}); e != nil {
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
	rel, e := masterDB.Nodes().Relationship(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	if e = master.Tick(ctx, rel); e != nil {
		t.Fatal(e)
	}
	rel, e = masterDB.Nodes().Relationship(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	service := &noderetirement.Service{Repository: masterDB.Pool().(store.RetirementRepository), Nodes: masterDB.Nodes(), Client: master}
	return master, masterDB, peerDB, directory, rel, service
}

type retirementLostAck struct {
	noderetirement.Caller
	lost bool
}

func (c *retirementLostAck) Call(ctx context.Context, rel store.Relationship, route string, request any) (map[string]any, error) {
	value, e := c.Caller.Call(ctx, rel, route, request)
	if e == nil && route == "/internal/v1/retirement" && request.(map[string]any)["action"] == "complete" && !c.lost {
		c.lost = true
		return nil, errors.New("lost peer commit acknowledgement")
	}
	return value, e
}

func TestSafeRetirementPreservesNativeStateAndRecoversLostPeerCommit(t *testing.T) {
	master, mdb, pdb, dir, rel, service := retirementApplyFixture(t)
	ctx := context.Background()
	report, e := service.Check(ctx, rel.PeerID, rel.ID)
	if e != nil || !report.ObservationComplete || !report.Master.DatabaseClear || !report.Peer.DatabaseClear || len(report.Concerns) != 0 {
		t.Fatal("empty native node not reconciled", report, e)
	}
	orphan := filepath.Join(dir, "unmanaged.bin")
	if e = os.WriteFile(orphan, []byte("must stay"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = service.Apply(ctx, rel.PeerID, rel.ID, store.NodeAudit{}); e == nil {
		t.Fatal("orphan ignored")
	}
	before, e := mdb.Nodes().Relationship(ctx, rel.ID)
	if e != nil || before.State != "active" {
		t.Fatal("failed precheck closed relationship", before.State, e)
	}
	if e = os.Remove(orphan); e != nil {
		t.Fatal(e)
	}
	lost := &retirementLostAck{Caller: master}
	service.Client = lost
	if _, e = service.Apply(ctx, rel.PeerID, rel.ID, store.NodeAudit{}); e == nil || !lost.lost {
		t.Fatal("lost peer commit was reported complete", e)
	}
	peer, e := pdb.Nodes().Relationship(ctx, rel.ID)
	if e != nil || peer.State != "revoked" {
		t.Fatal(peer.State, e)
	}
	pending, e := mdb.Nodes().Relationship(ctx, rel.ID)
	if e != nil || pending.State != "retiring" {
		t.Fatal("Master discarded durable fence", pending.State, e)
	}
	if _, e = master.Call(ctx, rel, "/internal/v1/heartbeat", map[string]any{}); e == nil {
		t.Fatal("old ordinary control credential accepted")
	}
	done, e := service.Apply(ctx, rel.PeerID, rel.ID, store.NodeAudit{})
	if e != nil || done.CompletedAt < done.FencedAt || done.CompletedAt == 0 {
		t.Fatal(done, e)
	}
	again, e := service.Apply(ctx, rel.PeerID, rel.ID, store.NodeAudit{})
	if e != nil || again != done {
		t.Fatal("repeat changed retirement", again, e)
	}
	for _, name := range []string{"data.db", "secrets/node-vault.key", "media-keys/media-premaster.key", "media/lyrics/default.lrc"} {
		if _, e = os.Stat(filepath.Join(dir, name)); e != nil {
			t.Fatal("retirement removed retained state", name, e)
		}
	}
	var count int
	if e = pdb.Database().QueryRow("SELECT COUNT(*) FROM node_audit WHERE action='retirement-completed'").Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	status, e := master.Status(ctx)
	if e != nil {
		t.Fatal(e)
	}
	history, ok := status["relationships"].([]store.Relationship)
	if !ok || len(history) != 1 || history[0].ID != rel.ID || history[0].State != "revoked" {
		t.Fatal("completed retirement disappeared from operator history", status)
	}
}

func TestSafeRetirementNativeKeysRequireOriginalRuntimeIdentity(t *testing.T) {
	_, _, _, dir, rel, service := retirementApplyFixture(t)
	ctx := context.Background()
	checkClear := func(want bool) {
		t.Helper()
		report, e := service.Check(ctx, rel.PeerID, rel.ID)
		clear := e == nil && report.ObservationComplete && len(report.Concerns) == 0 && report.Master.DatabaseClear && report.Peer.DatabaseClear
		if clear != want {
			t.Fatal("native key reconciliation", want, report, e)
		}
	}
	checkClear(true)
	for _, name := range []string{"media-keys/media-premaster.key", "secrets/node-vault.key", ".native-runtime", ".native-store"} {
		path := filepath.Join(dir, name)
		original, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		bad := append([]byte(nil), original...)
		bad[0] ^= 0xff
		if e = os.WriteFile(path, bad, 0600); e != nil {
			t.Fatal(e)
		}
		checkClear(false)
		if e = os.WriteFile(path, original, 0600); e != nil {
			t.Fatal(e)
		}
		checkClear(true)
		// Missing files are rejected without recreating key material.
		if e = os.Rename(path, path+".test-held"); e != nil {
			t.Fatal(e)
		}
		checkClear(false)
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("missing key recreated", e)
		}
		// A byte-identical replacement inode is still not the selected runtime file.
		if e = os.WriteFile(path, original, 0600); e != nil {
			t.Fatal(e)
		}
		checkClear(false)
		if e = os.Remove(path); e != nil {
			t.Fatal(e)
		}
		if e = os.Rename(path+".test-held", path); e != nil {
			t.Fatal(e)
		}
		checkClear(true)
	}
	// A well-formed envelope sealed by the correct vault still has to bind this
	// node, not merely some valid NodeID and selected-store prefix.
	seal, e := vault.OpenExisting(filepath.Join(dir, "secrets"))
	if e != nil {
		t.Fatal(e)
	}
	binding, e := os.ReadFile(filepath.Join(dir, ".native-store"))
	if e != nil {
		t.Fatal(e)
	}
	receiptPath := filepath.Join(dir, ".native-runtime")
	original, e := os.ReadFile(receiptPath)
	if e != nil {
		t.Fatal(e)
	}
	foreign, e := seal.Seal("frontiercloud-native-runtime-v1\n" + string(binding) + strings.Repeat("f", 32))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(receiptPath, []byte(foreign), 0600); e != nil {
		t.Fatal(e)
	}
	checkClear(false)
	if e = os.WriteFile(receiptPath, original, 0600); e != nil {
		t.Fatal(e)
	}
	checkClear(true)
	for _, name := range []string{".native-admission.lock", ".native-store.lock"} {
		path := filepath.Join(dir, name)
		f, e := os.OpenFile(path, os.O_RDWR, 0600)
		if e != nil {
			t.Fatal(e)
		}
		release, e := filelease.Try(f, true)
		if e != nil {
			t.Fatal(e)
		}
		checkClear(false)
		release()
		checkClear(true)
		if e = os.WriteFile(path, []byte("unknown"), 0600); e != nil {
			t.Fatal(e)
		}
		checkClear(false)
		if e = os.Truncate(path, 0); e != nil {
			t.Fatal(e)
		}
		checkClear(true)
	}
	sibling := filepath.Join(dir, "media-keys", "unknown.key")
	if e := os.WriteFile(sibling, []byte("unrecognized secret must remain"), 0600); e != nil {
		t.Fatal(e)
	}
	checkClear(false)
	if _, e := service.Apply(ctx, rel.PeerID, rel.ID, store.NodeAudit{}); e == nil {
		t.Fatal("unknown sibling retired")
	}
	if data, e := os.ReadFile(sibling); e != nil || string(data) != "unrecognized secret must remain" {
		t.Fatal("unknown sibling changed", e)
	}
}

func TestSafeRetirementPeerBarrierWaitsForNativeReadersAndRetainsFence(t *testing.T) {
	master, _, pdb, dir, rel, _ := retirementApplyFixture(t)
	ctx := context.Background()
	begin := map[string]any{"action": "begin", "confirm_member_id": rel.PeerID}
	if _, e := master.Call(ctx, rel, "/internal/v1/retirement", begin); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(filepath.Join(dir, "media/.media-mutation.lock"))
	if e != nil {
		t.Fatal(e)
	}
	release, e := filelease.Try(f, false)
	if e != nil {
		t.Fatal(e)
	}
	deadline, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	_, e = master.Call(deadline, rel, "/internal/v1/retirement", map[string]any{"action": "complete", "confirm_member_id": rel.PeerID})
	stop()
	release()
	if e == nil {
		t.Fatal("held native read allowed retirement")
	}
	pending, e := pdb.Nodes().Relationship(ctx, rel.ID)
	if e != nil || pending.State != "retiring" {
		t.Fatal(pending.State, e)
	}
	if _, e = master.Call(ctx, rel, "/internal/v1/retirement", map[string]any{"action": "complete", "confirm_member_id": strings.Repeat("f", 32)}); e == nil {
		t.Fatal("wrong identity confirmation accepted")
	}
	if _, e = master.Call(ctx, rel, "/internal/v1/retirement", map[string]any{"action": "complete", "confirm_member_id": rel.PeerID}); e != nil {
		t.Fatal("idle fenced node failed retry", e)
	}
}
