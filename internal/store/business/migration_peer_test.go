package business_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func peerMigrationFixture(t *testing.T, source bool) (store.Store, *sql.DB, store.MigrationPeerRepository, string, store.MigrationPeerHeader, store.MigrationLease, store.MigrationPeerObject) {
	t.Helper()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	ctx := context.Background()
	n, e := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "private-fixture"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = raw.Exec("UPDATE node_identity SET `role`='Follower',endpoint='https://peer.test' WHERE singleton=1"); e != nil {
		t.Fatal(e)
	}
	master := strings.Repeat("9", 32)
	rel := hashPath(t.Name() + "rel")[:32]
	nonce := hashPath(t.Name() + "nonce")[:32]
	task := hashPath(t.Name() + "task")[:32]
	other := strings.Repeat("b", 32)
	h := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: task, MasterID: master, SourceID: other, TargetID: n.ID, SourceRelationship: strings.Repeat("c", 32), TargetRelationship: rel, PlanSHA: strings.Repeat("e", 64), ObjectCount: 1, Bytes: 7}
	if source {
		h.SourceID = n.ID
		h.TargetID = other
		h.SourceRelationship = rel
		h.TargetRelationship = strings.Repeat("c", 32)
	}
	l := store.MigrationLease{TaskID: task, RunnerID: strings.Repeat("d", 32), Epoch: 1, ExpiresAt: time.Now().Unix() + 60}
	o := store.MigrationObject{ID: hashPath(t.Name() + "object"), ObjectID: hashPath(t.Name() + "object"), Resource: "media", Path: "music/" + t.Name() + "/track.mp3", TargetPath: "music/" + t.Name() + "/track.mp3", Parent: "music/" + t.Name(), Kind: "audio", Bytes: 7, Version: strings.Repeat("1", 64), ETag: `"` + strings.Repeat("2", 64) + `"`}
	v := store.MigrationPeerObject{Object: o, Proof: store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: strings.Repeat("2", 64)}}
	t.Cleanup(func() {
		for _, table := range []string{"migration_units", "migration_peer_bindings", "migration_storage_journal", "migration_capacity", "migration_scopes", "migration_runners", "migration_tasks"} {
			raw.Exec("DELETE FROM "+table+" WHERE task_id=?", task)
		}
		raw.Exec("DELETE FROM migration_drains WHERE owner_id=?", task)
		raw.Exec("DELETE FROM media_objects WHERE media_id=?", o.ObjectID)
		raw.Exec("DELETE FROM cluster_upload_sessions WHERE storage_member_id=?", n.ID)
		for _, table := range []string{"cluster_storage_members", "cluster_compute_members", "cluster_backup_members"} {
			raw.Exec("DELETE FROM "+table+" WHERE member_id=?", n.ID)
		}
		raw.Exec("DELETE FROM node_relationships WHERE relationship_id=?", rel)
		raw.Exec("DELETE FROM node_pair_packages WHERE nonce=?", nonce)
		raw.Exec("UPDATE node_identity SET `role`=?,endpoint=? WHERE singleton=1", n.Role, n.Endpoint)
	})
	now := time.Now().Unix()
	pair := store.PairPackage{Nonce: nonce, TokenHash: strings.Repeat("f", 64), ExpiresAt: now + 300}
	if _, e = db.Nodes().IssuePair(ctx, pair, now, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = db.Nodes().ConsumePair(ctx, pair, store.Relationship{ID: rel, PeerID: master, Endpoint: "https://master.test", PublicKey: strings.Repeat("A", 43), Credential: "private-fixture-credential", Direction: "upstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: now}, now, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = db.Nodes().ActivateRelationship(ctx, rel, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	cfg := store.ResourceConfiguration{}
	cfg.Storage.Enabled = true
	cfg.Storage.Allocation = 10 * store.GiB
	if e = db.Pool().AcceptFollowerConfiguration(ctx, rel, cfg, 20*store.GiB); e != nil {
		t.Fatal(e)
	}
	if source {
		operation := hashPath(t.Name() + "upload")[:32]
		m := store.MediaObject{ID: o.ObjectID, Path: o.Path, Kind: o.Kind}
		if e = db.Pool().ReserveOwnedUpload(ctx, operation, rel, m, 7, 20*store.GiB, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if e = db.Pool().CompleteOwnedUpload(ctx, operation, m, 7, o.ETag, 20*store.GiB, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	return db, raw, db.Pool().(store.MigrationPeerRepository), rel, h, l, v
}

func TestPeerMigrationTargetIdentityRosterQuotaAndEpochFences(t *testing.T) {
	db, raw, repo, rel, h, l, v := peerMigrationFixture(t, false)
	ctx := context.Background()
	wrong := h
	wrong.MasterID = strings.Repeat("8", 32)
	if e := repo.RegisterPeerMigration(ctx, rel, wrong, l, "queued", 20*store.GiB, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("foreign Master", e)
	}
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", store.PhysicalReserve, store.NodeAudit{}); !errors.Is(e, store.ErrStorageCapacity) {
		t.Fatal("insufficient physical space", e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}) })
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var reserved int64
	raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.TargetID).Scan(&reserved)
	if reserved != 7 {
		t.Fatal("duplicate capacity charge", reserved)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "append"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("incomplete roster authorized", e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal("lost-response retry", e)
	}
	changed := v
	changed.Object.ETag = "changed"
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, changed, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("changed immutable object binding accepted", e)
	}
	if _, e := raw.Exec("DELETE FROM migration_peer_bindings WHERE task_id=? AND logical_id=?", l.TaskID, v.Object.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "append"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("missing historical binding inferred as safe", e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal("canonical re-registration did not restore binding", e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "append"); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "read"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("target used source read operation", e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "publish"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("unverified publication authorized", e)
	}
	if e := repo.VerifyPeerMigrationObject(ctx, rel, l, v.Object.ID, v.Object.Bytes, strings.Repeat("0", 64)); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("wrong verification proof", e)
	}
	if e := repo.VerifyPeerMigrationObject(ctx, rel, l, v.Object.ID, v.Object.Bytes, v.Proof.SHA256); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "publish"); e != nil {
		t.Fatal("verified publication gate", e)
	}
	if e := db.Pool().ReserveOwnedUpload(ctx, hashPath(t.Name() + "bad")[:32], rel, store.MediaObject{ID: strings.Repeat("3", 64), Path: v.Object.Parent + "/new.mp3", Kind: "audio"}, 7, 20*store.GiB, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("ordinary upload bypassed target scope", e)
	}
	if e := repo.FencePeerMigration(ctx, rel, h.TaskID, l.Epoch, "paused", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "append"); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal("paused command authorized", e)
	}
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal("old epoch resumed task", e)
	}
	newLease := l
	newLease.Epoch++
	if e := repo.RegisterPeerMigration(ctx, rel, h, newLease, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, newLease, v.Object.ID, "append"); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "append"); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal("old runner retained authority", e)
	}
	if e := repo.FencePeerMigration(ctx, rel, h.TaskID, newLease.Epoch, "cancelling", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	newLease.Epoch++
	if e := repo.RegisterPeerMigration(ctx, rel, h, newLease, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, newLease, v.Object.ID, "abort"); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, newLease, v.Object.ID, "append"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("cancel continued copy", e)
	}
	raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.TargetID).Scan(&reserved)
	if reserved != 7 {
		t.Fatal("cancel refunded before disk cleanup", reserved)
	}
}

func TestPeerMigrationSourceDrainBlocksLegacyWritesButPreservesRead(t *testing.T) {
	db, raw, repo, rel, h, l, v := peerMigrationFixture(t, true)
	ctx := context.Background()
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "read"); e != nil {
		t.Fatal(e)
	}
	if e := db.Pool().ReserveOwnedUpload(ctx, hashPath(t.Name() + "bad")[:32], rel, store.MediaObject{ID: strings.Repeat("3", 64), Path: "music/unrelated/new.mp3", Kind: "audio"}, 7, 20*store.GiB, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("source allocation bypassed drain", e)
	}
	if e := db.Pool().CheckOwnedRename(ctx, rel, v.Object.Parent, v.Object.Parent+"-new"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("rename bypassed source scope", e)
	}
	if e := db.Nodes().RevokeRelationship(ctx, rel, false, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("revoke bypassed source journal", e)
	}
	var reserved int64
	raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.SourceID).Scan(&reserved)
	if reserved != 0 {
		t.Fatal("source was charged target capacity", reserved)
	}
	if e := db.Pool().AcceptFollowerConfiguration(ctx, rel, store.ResourceConfiguration{Storage: struct {
		Enabled    bool  `json:"enabled"`
		Allocation int64 `json:"allocated_bytes"`
	}{true, 10 * store.GiB}}, 20*store.GiB); e != nil {
		t.Fatal(e)
	}
	if e := db.Pool().ReserveOwnedUpload(ctx, hashPath(t.Name() + "after")[:32], rel, store.MediaObject{ID: strings.Repeat("4", 64), Path: "music/unrelated/after.mp3", Kind: "audio"}, 7, 20*store.GiB, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("configuration heartbeat erased drain", e)
	}
}

func TestPeerMigrationAbortReceiptIsFencedIdempotentAndKeepsReservations(t *testing.T) {
	_, raw, repo, rel, h, l, v := peerMigrationFixture(t, false)
	ctx := context.Background()
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.CompletePeerMigrationAbort(ctx, rel, l, v.Object.ID, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("abort before cancellation", e)
	}
	l.Epoch++
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "abort"); e != nil {
			t.Fatal(e)
		}
		if e := repo.CompletePeerMigrationAbort(ctx, rel, l, v.Object.ID, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	var phase string
	var capacity, scopes int64
	if e := raw.QueryRow("SELECT state FROM migration_storage_journal WHERE task_id=? AND logical_id=?", h.TaskID, v.Object.ID).Scan(&phase); e != nil {
		t.Fatal(e)
	}
	if e := raw.QueryRow("SELECT reserved_bytes FROM migration_capacity WHERE task_id=?", h.TaskID).Scan(&capacity); e != nil {
		t.Fatal(e)
	}
	if e := raw.QueryRow("SELECT COUNT(*) FROM migration_scopes WHERE task_id=?", h.TaskID).Scan(&scopes); e != nil {
		t.Fatal(e)
	}
	if phase != "aborted" || capacity != h.Bytes || scopes != 1 {
		t.Fatal(phase, capacity, scopes)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "append"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("aborted object writable", e)
	}
	if _, e := raw.Exec("UPDATE migration_storage_journal SET state='published' WHERE task_id=?", h.TaskID); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "abort"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("published shadow blindly aborted", e)
	}
	if e := repo.CompletePeerMigrationAbort(ctx, rel, l, v.Object.ID, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("published journal blindly aborted", e)
	}
}

func TestPeerMigrationUnitCancellationRefundsOnlyUnpublishedTarget(t *testing.T) {
	for _, sourcePeer := range []bool{false, true} {
		t.Run(map[bool]string{false: "target", true: "source"}[sourcePeer], func(t *testing.T) {
			_, raw, repo, rel, h, l, v := peerMigrationFixture(t, sourcePeer)
			ctx := context.Background()
			if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			// Cancellation may interrupt registration before the last object arrives.
			l.Epoch++
			if e := repo.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			var unit string
			if e := raw.QueryRow("SELECT unit_id FROM migration_storage_journal WHERE task_id=?", h.TaskID).Scan(&unit); e != nil {
				t.Fatal(e)
			}
			sha, e := store.MigrationUnitObjectsSHA([]store.MigrationPeerObject{v})
			if e != nil {
				t.Fatal(e)
			}
			g := store.MigrationUnitFinishGrant{Header: h, Unit: store.MigrationUnit{ID: unit, Resource: v.Object.Resource, Parent: v.Object.Parent, State: "cancelled", ObjectCount: 1, Bytes: v.Object.Bytes}, UnitVersion: strings.Repeat("1", 64), ObjectsSHA: sha}
			if !sourcePeer {
				if _, e = repo.CompletePeerMigrationUnitCancellation(ctx, rel, l, g, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
					t.Fatal("live stage refunded", e)
				}
				if e = repo.CompletePeerMigrationAbort(ctx, rel, l, v.Object.ID, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
			}
			for range 2 {
				receipt, e := repo.CompletePeerMigrationUnitCancellation(ctx, rel, l, g, store.NodeAudit{})
				if e != nil || !receipt.Complete {
					t.Fatal(receipt, e)
				}
			}
			var scopes int
			if e = raw.QueryRow("SELECT COUNT(*) FROM migration_scopes WHERE task_id=?", h.TaskID).Scan(&scopes); e != nil || scopes != 0 {
				t.Fatal(scopes, e)
			}
			if sourcePeer {
				var objects, drains int
				if e = raw.QueryRow("SELECT COUNT(*) FROM media_objects WHERE media_id=?", v.Object.ObjectID).Scan(&objects); e != nil {
					t.Fatal(e)
				}
				if e = raw.QueryRow("SELECT COUNT(*) FROM migration_drains WHERE owner_id=?", h.TaskID).Scan(&drains); e != nil || drains != 1 || objects != 1 {
					t.Fatal(objects, drains, e)
				}
			} else {
				var reserved int64
				if e = raw.QueryRow("SELECT reserved_bytes FROM migration_capacity WHERE task_id=?", h.TaskID).Scan(&reserved); e != nil || reserved != 0 {
					t.Fatal(reserved, e)
				}
			}
			if _, e = repo.CompletePeerMigrationUnit(ctx, rel, l, g, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
				t.Fatal("cancel receipt reused as clean", e)
			}
			unitsSHA, e := store.MigrationTaskUnitsSHA([]store.MigrationUnitFinishGrant{g})
			if e != nil {
				t.Fatal(e)
			}
			final := store.MigrationTaskFinishGrant{Outcome: "cancelled", Header: h, UnitsSHA: unitsSHA, UnitCount: 1}
			if _, e = repo.CompletePeerMigrationTask(ctx, rel, l, final, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
				t.Fatal("cancel final receipt reused as completed", e)
			}
			if receipt, e := repo.CompletePeerMigrationTaskCancellation(ctx, rel, l, final, store.NodeAudit{}); e != nil || !receipt.Complete {
				t.Fatal(receipt, e)
			}
			l.Epoch++
			if e = repo.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal("terminal registration retry", e)
			}
			if receipt, e := repo.CompletePeerMigrationTaskCancellation(ctx, rel, l, final, store.NodeAudit{}); e != nil || !receipt.Complete {
				t.Fatal("final receipt under fresh epoch", receipt, e)
			}
			if _, e = repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "abort"); !errors.Is(e, store.ErrMigrationLease) {
				t.Fatal("terminal task regained data permissions", e)
			}

		})
	}
}

func TestPeerMigrationEmptyCancellationReceiptReplay(t *testing.T) {
	_, _, repo, rel, h, l, _ := peerMigrationFixture(t, false)
	ctx := context.Background()
	h.ObjectCount = 0
	h.Bytes = 0
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	sha, e := store.MigrationTaskUnitsSHA([]store.MigrationUnitFinishGrant{})
	if e != nil {
		t.Fatal(e)
	}
	g := store.MigrationTaskFinishGrant{Outcome: "cancelled", Header: h, UnitsSHA: sha, UnitCount: 0}
	if receipt, e := repo.CompletePeerMigrationTaskCancellation(ctx, rel, l, g, store.NodeAudit{}); e != nil || !receipt.Complete {
		t.Fatal(receipt, e)
	}
	l.Epoch++
	if e = repo.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if receipt, e := repo.CompletePeerMigrationTaskCancellation(ctx, rel, l, g, store.NodeAudit{}); e != nil || !receipt.Complete {
		t.Fatal(receipt, e)
	}
	if e = repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("cancelled empty task reopened", e)
	}
}

func TestPeerMigrationCancellationSourceProofReadIsTaskStateBound(t *testing.T) {
	_, raw, repo, rel, h, l, v := peerMigrationFixture(t, true)
	ctx := context.Background()
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "cancel-read"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("proof read outside cancellation", e)
	}
	l.Epoch++
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "read"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("ordinary copy read restored", e)
	}
	if bound, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "cancel-read"); e != nil || bound.Object.Version != v.Object.Version || bound.Proof.SHA256 != v.Proof.SHA256 {
		t.Fatal(bound, e)
	}
	if _, e := raw.Exec("UPDATE migration_storage_journal SET state='deleting' WHERE task_id=?", h.TaskID); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "cancel-read"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("deleting source accepted as authority proof", e)
	}
}
