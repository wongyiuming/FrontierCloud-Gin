package business_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

const routingMaster = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const routingFollower = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const routingRelation = "cccccccccccccccccccccccccccccccc"

func TestPeerIngressSelectionRequiresEnabledGateAndFreshEvidence(t *testing.T) {
	db := database(t)
	routing, raw := routingFixture(t, db)
	ctx := context.Background()
	initial, err := routing.PublicIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := db.Nodes().RecordHeartbeat(ctx, routingRelation, true, 1, map[string]any{"public_ingress_candidate_origin": "https://candidate.test", "capabilities": []string{"public-ingress-proxy-v1"}}, now); err != nil {
		t.Fatal(err)
	}
	relation, err := db.Nodes().Relationship(ctx, routingRelation)
	if err != nil {
		t.Fatal(err)
	}
	evidence := store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, PublicOrigin: "https://candidate.test", CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt, LastHeartbeat: relation.LastHeartbeat}
	peer := db.Nodes().(store.PeerIngressRepository)
	if _, err := peer.CommitPeerPublicIngress(ctx, evidence, initial.Generation, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("closed gate selected peer", err)
	}
	peer.EnablePeerIngress()
	bad := evidence
	bad.PublicOrigin = "https://other.test"
	if _, err := peer.CommitPeerPublicIngress(ctx, bad, initial.Generation, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong candidate origin selected", err)
	}
	bad = evidence
	bad.CredentialDigest = store.PeerCredentialDigest("replacement-fixture")
	if _, err := peer.CommitPeerPublicIngress(ctx, bad, initial.Generation, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("replaced relationship credential accepted", err)
	}
	bad = evidence
	bad.CreatedAt++
	if _, err := peer.CommitPeerPublicIngress(ctx, bad, initial.Generation, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("recreated relationship accepted", err)
	}
	if _, err := peer.CommitPeerPublicIngress(ctx, evidence, initial.Generation+1, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("stale selection revision accepted", err)
	}
	selected, err := peer.CommitPeerPublicIngress(ctx, evidence, initial.Generation, store.NodeAudit{Actor: "admin"})
	if err != nil || selected.NodeID != routingFollower || selected.PublicOrigin != evidence.PublicOrigin || selected.Generation != initial.Generation+1 {
		t.Fatal("candidate selection", selected, err)
	}
	current, lease, err := routing.AcquireCurrentIngress(ctx)
	if err != nil || current != selected {
		t.Fatal("selected admission", current, err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	// A fresh relationship with the same peer and origin must not inherit the
	// previous selection. Only another explicit, verified selection may bind it.
	if _, err := raw.Exec("UPDATE node_relationships SET credential=?,created_at=created_at+1 WHERE relationship_id=?", "replacement-fixture", relation.ID); err != nil {
		t.Fatal(err)
	}
	if _, lease, err := routing.AcquireCurrentIngress(ctx); !errors.Is(err, store.ErrNodeState) || lease != nil {
		t.Fatal("replacement relationship inherited ingress admission", err)
	}
	relation, err = db.Nodes().Relationship(ctx, routingRelation)
	if err != nil {
		t.Fatal(err)
	}
	evidence.CredentialDigest = store.PeerCredentialDigest(relation.Credential)
	evidence.CreatedAt = relation.CreatedAt
	renewed, err := peer.CommitPeerPublicIngress(ctx, evidence, selected.Generation, store.NodeAudit{Actor: "admin"})
	if err != nil || renewed.Generation != selected.Generation+1 || renewed.NodeID != selected.NodeID {
		t.Fatal("explicit relationship re-selection", renewed, err)
	}
	selected = renewed
	if _, lease, err := routing.AcquireCurrentIngress(ctx); err != nil {
		t.Fatal("re-selected relationship denied", err)
	} else if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().RecordHeartbeat(ctx, routingRelation, true, 1, map[string]any{"public_ingress_candidate_origin": "https://changed.test", "capabilities": []string{"public-ingress-proxy-v1"}}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if persisted, err := routing.PublicIngress(ctx); err != nil || persisted != selected {
		t.Fatal("unavailable ingress selection changed implicitly", persisted, err)
	}
	if _, lease, err := routing.AcquireCurrentIngress(ctx); !errors.Is(err, store.ErrNodeState) || lease != nil {
		t.Fatal("changed candidate address retained admission", err)
	}
	back, err := routing.CommitMasterPublicIngress(ctx, "https://public.test", selected.Generation, store.NodeAudit{Actor: "admin"})
	if err != nil || back.NodeID != routingMaster || back.Generation != selected.Generation+1 {
		t.Fatal("explicit public ingress selection for Master", back, err)
	}
	if err := db.Nodes().RecordHeartbeat(ctx, routingRelation, true, 1, map[string]any{"public_ingress_candidate_origin": "https://changed.test", "capabilities": []string{"public-ingress-proxy-v1"}}, now+1); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.CommitPeerPublicIngress(ctx, evidence, back.Generation, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("changed candidate evidence accepted", err)
	}
}

func TestPeerIngressEffectiveTransportUsesAppliedPolicy(t *testing.T) {
	db := database(t)
	routing, _ := routingFixture(t, db)
	ctx := context.Background()
	initial, err := routing.PublicIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	otherID, otherRelation := strings.Repeat("d", 32), strings.Repeat("e", 32)
	other := store.Relationship{ID: otherRelation, PeerID: otherID, Endpoint: "https://other.test", PublicKey: strings.Repeat("A", 43), Credential: "sealed-fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: time.Now().Unix()}
	if err := db.Nodes().PrepareRelationship(ctx, other, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().ActivateRelationship(ctx, otherRelation, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().SetRelationshipMode(ctx, otherRelation, "Direct", false, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := routing.ConfirmNativeTransport(ctx, otherID, "Relay", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	apply := db.Nodes().(interface {
		RecordNativeTransportApplication(context.Context, string, int64, string) error
	})
	if err := apply.RecordNativeTransportApplication(ctx, otherRelation, 1, "Relay"); err != nil {
		t.Fatal(err)
	}
	if p, err := routing.NativeTransport(ctx, otherID); err != nil || p.EffectiveTransport != "Direct" {
		t.Fatal("Master ingress legacy route", p, err)
	}
	now := time.Now().Unix()
	if err := db.Nodes().RecordHeartbeat(ctx, routingRelation, true, 1, map[string]any{"public_ingress_candidate_origin": "https://candidate.test", "capabilities": []string{"public-ingress-proxy-v1"}}, now); err != nil {
		t.Fatal(err)
	}
	relation, err := db.Nodes().Relationship(ctx, routingRelation)
	if err != nil {
		t.Fatal(err)
	}
	evidence := store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, PublicOrigin: "https://candidate.test", CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt, LastHeartbeat: relation.LastHeartbeat}
	peer := db.Nodes().(store.PeerIngressRepository)
	peer.EnablePeerIngress()
	if _, err := peer.CommitPeerPublicIngress(ctx, evidence, initial.Generation, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if p, err := routing.NativeTransport(ctx, routingFollower); err != nil || p.EffectiveTransport != "Local" {
		t.Fatal("ingress owner not Local", p, err)
	}
	if p, err := routing.NativeTransport(ctx, otherID); err != nil || p.EffectiveTransport != "Relay" {
		t.Fatal("other owner did not use applied Relay", p, err)
	}
	if _, err := routing.ConfirmNativeTransport(ctx, otherID, "Direct", 1, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if p, err := routing.NativeTransport(ctx, otherID); err != nil || p.State != "blocked" || p.EffectiveTransport != "" {
		t.Fatal("pending Direct silently inherited a route", p, err)
	}
}

func TestNativeTransportApplicationFencedAndHeartbeatCannotForge(t *testing.T) {
	db := database(t)
	repo, raw := routingFixture(t, db)
	ctx := context.Background()
	apply := db.Nodes().(interface {
		RecordNativeTransportApplication(context.Context, string, int64, string) error
	})
	if _, err := repo.ConfirmNativeTransport(ctx, routingFollower, "Relay", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().RecordHeartbeat(ctx, routingRelation, true, 1, map[string]any{"_local_native_transport_receipt": map[string]any{"transport": "Relay", "revision": 1}}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	p, err := repo.NativeTransport(ctx, routingFollower)
	if err != nil || p.AppliedTransport != "" {
		t.Fatal("peer forged receipt", p, err)
	}
	if err := apply.RecordNativeTransportApplication(ctx, routingRelation, 1, "Relay"); err != nil {
		t.Fatal(err)
	}
	p, err = repo.NativeTransport(ctx, routingFollower)
	if err != nil || p.State != "applied" || p.AppliedTransport != "Relay" {
		t.Fatal(p, err)
	}
	if err := db.Nodes().RecordHeartbeat(ctx, routingRelation, true, 1, nil, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	p, err = repo.NativeTransport(ctx, routingFollower)
	if err != nil || p.State != "applied" {
		t.Fatal("heartbeat removed receipt", p, err)
	}
	if _, err = repo.ConfirmNativeTransport(ctx, routingFollower, "Direct", 1, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = apply.RecordNativeTransportApplication(ctx, routingRelation, 1, "Relay"); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("stale acknowledgment accepted", err)
	}
	if err = apply.RecordNativeTransportApplication(ctx, routingRelation, 2, "Direct"); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("unverified Direct accepted", err)
	}
	p, err = repo.NativeTransport(ctx, routingFollower)
	if err != nil || p.State != "blocked" || p.AppliedTransport != "Relay" {
		t.Fatal(p, err)
	}
	var mode, transport string
	if err = raw.QueryRow("SELECT n.mode,m.transport FROM node_relationships n JOIN cluster_storage_members m ON n.relationship_id=m.relationship_id WHERE n.relationship_id=?", routingRelation).Scan(&mode, &transport); err != nil || mode != "Relay" || transport != "Relay" {
		t.Fatal("legacy mode changed", mode, transport, err)
	}
}

func routingFixture(t *testing.T, db store.Store) (store.PublicRoutingRepository, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: routingMaster, Role: "Standalone", PrivateKey: "sealed-fixture"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	relation := store.Relationship{ID: routingRelation, PeerID: routingFollower, Endpoint: "https://follower.test", PublicKey: strings.Repeat("A", 43), Credential: "sealed-fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: time.Now().Unix()}
	if err := db.Nodes().PrepareRelationship(ctx, relation, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().ActivateRelationship(ctx, relation.ID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	repository, ok := db.Nodes().(store.PublicRoutingRepository)
	if !ok {
		t.Fatal("public routing repository unavailable")
	}
	if err := repository.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	return repository, raw
}

func TestPublicRoutingPreservesLegacyAndConfirmsWithoutApplyingDifferentMode(t *testing.T) {
	db := database(t)
	repo, raw := routingFixture(t, db)
	ctx := context.Background()
	ingress, err := repo.PublicIngress(ctx)
	if err != nil || ingress.NodeID != routingMaster || ingress.PublicOrigin != "https://public.test" || ingress.Generation != 1 {
		t.Fatal("default ingress", ingress, err)
	}
	master, err := repo.NativeTransport(ctx, routingMaster)
	if err != nil || master.ConfiguredTransport != "" || master.AppliedTransport != "" || master.EffectiveTransport != "Local" || master.State != "confirmation_required" || master.Revision != 0 {
		t.Fatal("Master policy was inferred", master, err)
	}
	peer, err := repo.NativeTransport(ctx, routingFollower)
	if err != nil || peer.ConfiguredTransport != "Relay" || peer.AppliedTransport != "" || peer.LegacyTransport != "Relay" || peer.EffectiveTransport != "Relay" || peer.State != "confirmation_required" || peer.Revision != 0 {
		t.Fatal("legacy follower mode", peer, err)
	}
	peer, err = repo.ConfirmNativeTransport(ctx, routingFollower, "Direct", 0, store.NodeAudit{Actor: "admin"})
	if err != nil || peer.Revision != 1 || peer.ConfiguredTransport != "Direct" || peer.State != "blocked" || peer.AppliedTransport != "" || peer.EffectiveTransport != "Relay" {
		t.Fatal("desired mode not blocked without peer application", peer, err)
	}
	if _, err = repo.ConfirmNativeTransport(ctx, routingFollower, "Relay", 0, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("stale revision overwrote desired mode", err)
	}
	peer, err = repo.ConfirmNativeTransport(ctx, routingFollower, "Relay", 1, store.NodeAudit{Actor: "admin"})
	if err != nil || peer.Revision != 2 || peer.State != "legacy_confirmed" || peer.AppliedTransport != "" || peer.EffectiveTransport != "Relay" {
		t.Fatal("confirm legacy follower", peer, err)
	}
	peer, err = repo.ConfirmNativeTransport(ctx, routingFollower, "Relay", 2, store.NodeAudit{Actor: "admin"})
	if err != nil || peer.Revision != 2 {
		t.Fatal("idempotent confirmation", peer, err)
	}
	if _, err = repo.ConfirmNativeTransport(ctx, routingFollower, "Relay", 0, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("stale revision accepted", err)
	}
	master, err = repo.ConfirmNativeTransport(ctx, routingMaster, "Direct", 0, store.NodeAudit{Actor: "admin"})
	if err != nil || master.ConfiguredTransport != "Direct" || master.EffectiveTransport != "Local" || master.State != "retained" || master.Revision != 1 {
		t.Fatal("retain Master policy while ingress", master, err)
	}
	master, err = repo.ConfirmNativeTransport(ctx, routingMaster, "Relay", 1, store.NodeAudit{Actor: "admin"})
	if err != nil || master.ConfiguredTransport != "Relay" || master.EffectiveTransport != "Local" || master.Revision != 2 {
		t.Fatal("change retained policy", master, err)
	}
	var mode, ownerTransport, kind string
	if err = raw.QueryRow("SELECT mode FROM node_relationships WHERE relationship_id=?", routingRelation).Scan(&mode); err != nil || mode != "Relay" {
		t.Fatal("relationship changed", mode, err)
	}
	if err = raw.QueryRow("SELECT member_kind,transport FROM cluster_storage_members WHERE member_id=?", routingMaster).Scan(&kind, &ownerTransport); err != nil || kind != "MasterLocal" || ownerTransport != "Local" {
		t.Fatal("Master placement changed", kind, ownerTransport, err)
	}
	// Control-origin changes cannot implicitly rewrite the public origin.
	if _, err = raw.Exec("UPDATE node_identity SET endpoint='https://control-changed.test' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	again, err := repo.PublicIngress(ctx)
	if err != nil || again != ingress {
		t.Fatal("control endpoint changed ingress", again, err)
	}
}

func TestPublicRoutingRevisionRaceAndAuditRollback(t *testing.T) {
	db := database(t)
	repo, raw := routingFixture(t, db)
	ctx := context.Background()
	if _, err := repo.ConfirmNativeTransport(ctx, routingMaster, "Direct", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.ConfirmNativeTransport(ctx, routingMaster, "Relay", 1, store.NodeAudit{})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		}
	}
	value, err := repo.NativeTransport(ctx, routingMaster)
	if err != nil || wins != 1 || value.Revision != 2 || value.ConfiguredTransport != "Relay" {
		t.Fatal("CAS failed", wins, value, err)
	}
	trigger := "CREATE TRIGGER public_routing_audit_fault BEFORE INSERT ON node_audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"
	if db.Backend() == "mysql" {
		trigger = "CREATE TRIGGER public_routing_audit_fault BEFORE INSERT ON node_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit unavailable'"
	} else if db.Backend() != "sqlite" {
		t.Fatal("unsupported database fixture", db.Backend())
	}
	if _, err := raw.Exec(trigger); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConfirmNativeTransport(ctx, routingMaster, "Direct", 2, store.NodeAudit{}); err == nil {
		t.Fatal("unaudited policy change accepted")
	}
	after, err := repo.NativeTransport(ctx, routingMaster)
	if err != nil || after != value {
		t.Fatal("audit failure changed policy", value, after, err)
	}
}

func TestPublicRoutingRejectsRevisionOverflow(t *testing.T) {
	db := database(t)
	repo, raw := routingFixture(t, db)
	ctx := context.Background()
	if _, err := repo.ConfirmNativeTransport(ctx, routingFollower, "Relay", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("UPDATE native_transport_policy SET revision=? WHERE member_id=?", int64(math.MaxInt64), routingFollower); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConfirmNativeTransport(ctx, routingFollower, "Direct", math.MaxInt64, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("overflowing revision accepted", err)
	}
	policy, err := repo.NativeTransport(ctx, routingFollower)
	if err != nil || policy.Revision != math.MaxInt64 || policy.ConfiguredTransport != "Relay" || policy.EffectiveTransport != "Relay" {
		t.Fatal("overflow changed policy", policy, err)
	}
}

func TestPublicRoutingRejectsInvalidOwnersAndNonMaster(t *testing.T) {
	db := database(t)
	repo, raw := routingFixture(t, db)
	ctx := context.Background()
	s3ID := strings.Repeat("d", 32)
	if _, err := raw.Exec("INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES (?,NULL,'S3','S3',0,0,0,0,0,'offline',0,1)", s3ID); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{s3ID, strings.Repeat("e", 32), "invalid"} {
		if _, err := repo.NativeTransport(ctx, owner); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("invalid native owner accepted", owner, err)
		}
		if _, err := repo.ConfirmNativeTransport(ctx, owner, "Direct", 0, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("invalid owner policy accepted", owner, err)
		}
	}
	for _, mode := range []string{"", "Local", "direct", "S3"} {
		if _, err := repo.ConfirmNativeTransport(ctx, routingMaster, mode, 0, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("invalid configured transport accepted", mode, err)
		}
	}
	if _, err := raw.Exec("UPDATE node_identity SET `role`='Follower' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.PublicIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("non-Master ingress admitted", err)
	}
	if _, err := repo.ConfirmNativeTransport(ctx, routingMaster, "Direct", 0, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("non-Master changed policy", err)
	}
	if _, err := raw.Exec("UPDATE node_identity SET `role`='Master' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("UPDATE public_ingress_config SET node_id=? WHERE singleton=1", routingFollower); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.PublicIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("unimplemented follower ingress accepted", err)
	}
}

func TestEffectiveNativeTransportMatrix(t *testing.T) {
	for _, c := range []struct {
		ingress, owner, policy, want string
		valid                        bool
	}{
		{"a", "a", "Direct", "Local", true}, {"a", "a", "Relay", "Local", true}, {"a", "a", "", "Local", true},
		{"a", "b", "Direct", "Direct", true}, {"a", "b", "Relay", "Relay", true},
		{"a", "b", "Local", "", false}, {"a", "b", "", "", false}, {"", "a", "Direct", "", false}, {"a", "", "Relay", "", false},
	} {
		got, err := store.EffectiveNativeTransport(c.ingress, c.owner, c.policy)
		if (err == nil) != c.valid || got != c.want {
			t.Fatal(c, got, err)
		}
	}
}

func TestPublicRoutingRestartAndBusinessSnapshot(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "routing.db")
	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	repo, _ := routingFixture(t, db)
	if _, err = repo.ConfirmNativeTransport(ctx, routingMaster, "Direct", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ConfirmNativeTransport(ctx, routingFollower, "Direct", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	repo = db.Nodes().(store.PublicRoutingRepository)
	ingress, err := repo.PublicIngress(ctx)
	if err != nil || ingress.NodeID != routingMaster || ingress.Generation != 1 {
		t.Fatal("ingress lost on restart", ingress, err)
	}
	for _, entry := range []struct{ id, mode string }{{routingMaster, "Direct"}, {routingFollower, "Direct"}} {
		value, err := repo.NativeTransport(ctx, entry.id)
		if err != nil || value.ConfiguredTransport != entry.mode || value.Revision != 1 {
			t.Fatal("policy lost on restart", value, err)
		}
	}
	blocked, err := repo.NativeTransport(ctx, routingFollower)
	if err != nil || blocked.State != "blocked" || blocked.EffectiveTransport != "Relay" || blocked.AppliedTransport != "" {
		t.Fatal("restart incorrectly applied desired policy", blocked, err)
	}
	var rows []map[string]any
	if err = db.Backups().ExportBusinessSnapshot(ctx, func(table string, row map[string]any) error {
		rows = append(rows, map[string]any{"kind": "row", "table": table, "value": row})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"current", "legacy", "foreign_ingress", "foreign_policy", "unsafe_origin"} {
		var data bytes.Buffer
		enc := json.NewEncoder(&data)
		const generation int64 = 1790000000000000123
		if err = enc.Encode(map[string]any{"kind": "header", "version": 2, "generation": generation}); err != nil {
			t.Fatal(err)
		}
		seen := map[string]int{}
		for _, row := range rows {
			table := row["table"].(string)
			if variant == "legacy" && (table == "public_ingress_config" || table == "native_transport_policy") {
				continue
			}
			seen[table]++
			value := make(map[string]any)
			for key, item := range row["value"].(map[string]any) {
				value[key] = item
			}
			if table == "public_ingress_config" && variant == "foreign_ingress" {
				value["node_id"] = routingFollower
			} else if table == "public_ingress_config" && variant == "unsafe_origin" {
				value["public_origin"] = "http://untrusted.test"
			} else if table == "native_transport_policy" && variant == "foreign_policy" && value["member_id"] == routingMaster {
				value["member_id"] = strings.Repeat("e", 32)
			}
			if err = enc.Encode(map[string]any{"kind": "row", "table": table, "value": value}); err != nil {
				t.Fatal(err)
			}
		}
		if err = enc.Encode(map[string]any{"kind": "end"}); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data.Bytes())
		report, err := backup.Preflight(ctx, bytes.NewReader(data.Bytes()), backup.Expectation{Generation: generation, Checksum: hex.EncodeToString(hash[:]), Bytes: int64(data.Len())}, t.TempDir())
		valid := variant == "current" || variant == "legacy"
		if valid && (err != nil || !report.LogicalValid || report.RestoreReady || (variant == "current" && (seen["public_ingress_config"] != 1 || seen["native_transport_policy"] != 2))) {
			t.Fatal("backup compatibility", variant, seen, report, err)
		}
		if !valid && !errors.Is(err, store.ErrBackupState) {
			t.Fatal("unsafe backup accepted", variant, report, err)
		}
	}
}
