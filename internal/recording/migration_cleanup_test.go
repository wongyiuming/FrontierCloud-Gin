package recording

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestRecordingMigrationIntentRecoveryBeforeAndAfterCommit(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := "prepared"
		if committed {
			name = "committed"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			db, e := sqlite.Open(filepath.Join(dir, "db.sqlite"))
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			if e = db.Initialize(ctx); e != nil {
				t.Fatal(e)
			}
			n, e := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "fixture"})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Follower", Endpoint: "https://source.test"}, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			now := time.Now().Unix()
			pair := store.PairPackage{Nonce: strings.Repeat("b", 32), TokenHash: strings.Repeat("c", 64), ExpiresAt: now + 300}
			if _, e = db.Nodes().IssuePair(ctx, pair, now, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			rel := store.Relationship{ID: strings.Repeat("d", 32), PeerID: strings.Repeat("e", 32), Endpoint: "https://master.test", PublicKey: strings.Repeat("A", 43), Credential: "fixture", Direction: "upstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: now}
			if e = db.Nodes().ConsumePair(ctx, pair, rel, now, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if e = db.Nodes().ActivateRelationship(ctx, rel.ID, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			cfg := store.ResourceConfiguration{}
			cfg.Storage.Enabled = true
			cfg.Storage.Allocation = store.GiB
			if e = db.Pool().AcceptFollowerConfiguration(ctx, rel.ID, cfg, 10*store.GiB); e != nil {
				t.Fatal(e)
			}
			root, e := os.OpenRoot(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			s, e := New(root, db.Recordings(), db.Nodes())
			if e != nil {
				t.Fatal(e)
			}
			id, user := strings.Repeat("1", 32), strings.Repeat("2", 32)
			payload := trailer(`{"version":1,"title":"original","lyrics":[{"time":1,"text":"line"}]}`)
			v := store.Recording{ID: id, UserID: user, Filename: "voice.webm", ContentType: "audio/webm", Bytes: int64(len(payload))}
			if _, e = s.Upload(ctx, rel.ID, v, strings.NewReader(string(payload)), store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			peer := db.Pool().(store.MigrationPeerRepository)
			h := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: strings.Repeat("3", 32), MasterID: rel.PeerID, SourceID: n.ID, TargetID: strings.Repeat("4", 32), SourceRelationship: rel.ID, TargetRelationship: strings.Repeat("5", 32), PlanSHA: strings.Repeat("6", 64), ObjectCount: 1, Bytes: v.Bytes}
			l := store.MigrationLease{TaskID: h.TaskID, RunnerID: strings.Repeat("7", 32), Epoch: 1, ExpiresAt: now + 60}
			sum := sha256.Sum256(payload)
			sha := hex.EncodeToString(sum[:])
			o := store.MigrationObject{ID: id, ObjectID: id, Resource: "recording", Kind: "recording", Parent: user, Path: rel.ID + "/" + user + "/" + id + ".bin", TargetPath: h.TargetRelationship + "/" + user + "/" + id + ".bin", Bytes: v.Bytes, Version: strings.Repeat("8", 64), ETag: sha, Recording: &store.RecordingProof{ID: id, UserID: user, Filename: v.Filename, ContentType: v.ContentType, Bytes: v.Bytes, SHA256: sha, CreatedAt: now}}
			if e = peer.RegisterPeerMigration(ctx, rel.ID, h, l, "queued", 10*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if e = peer.RegisterPeerMigrationObject(ctx, rel.ID, l, store.MigrationPeerObject{Object: o, Proof: store.MigrationDiskProof{ID: id, Version: o.Version, Bytes: v.Bytes, SHA256: sha}}, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			unit := sha256.Sum256([]byte("recording:" + user))
			g := store.MigrationCleanupGrant{TaskID: h.TaskID, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, PlanSHA: h.PlanSHA, UnitID: hex.EncodeToString(unit[:]), UnitVersion: strings.Repeat("9", 64), Object: o, SHA256: sha, CommittedAt: now - 3601, CleanupAfter: now - 1, TargetVerifiedAt: now}
			if e = peer.PreparePeerMigrationCleanup(ctx, rel.ID, l, g, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			row, e := peer.StagePeerRecordingDeletion(ctx, rel.ID, l, id)
			if e != nil {
				t.Fatal(e)
			}
			j := journal{Version: 1, Operation: "delete", Relationship: rel.ID, Recording: *row, UserID: user, MemberID: n.ID, MigrationTask: l.TaskID}
			if e = s.writeJournal(j); e != nil {
				t.Fatal(e)
			}
			if e = s.root.Rename(o.Path, ".recording-"+id+".deleted"); e != nil {
				t.Fatal(e)
			}
			if committed {
				if e = peer.CompletePeerRecordingDeletion(ctx, rel.ID, l.TaskID, id, 10*store.GiB, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
			}
			// Simulate restart with expired runner: the prepared durable file intent
			// still finishes forward, and must update both recording and source ledger.
			if _, e = db.Database().Exec("UPDATE migration_runners SET expires_at=0 WHERE task_id=?", l.TaskID); e != nil {
				t.Fatal(e)
			}
			recovered, e := New(root, db.Recordings(), db.Nodes())
			if e != nil {
				t.Fatal(e)
			}
			if complete, e := recovered.MigrationCleanupFinished(ctx, l.TaskID, id); e != nil || !complete {
				t.Fatal(complete, e)
			}
			if _, e = os.Stat(filepath.Join(dir, o.Path)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("source resurrected", e)
			}
			var phase string
			var used int64
			var audits int
			if e = db.Database().QueryRow("SELECT state FROM migration_storage_journal WHERE task_id=? AND logical_id=?", l.TaskID, id).Scan(&phase); e != nil || phase != "deleted" {
				t.Fatal(phase, e)
			}
			if e = db.Database().QueryRow("SELECT used_bytes FROM cluster_storage_members WHERE member_id=?", n.ID).Scan(&used); e != nil || used != 0 {
				t.Fatal(used, e)
			}
			if e = db.Database().QueryRow("SELECT COUNT(*) FROM node_audit WHERE action='recording-deleted'").Scan(&audits); e != nil || audits != 1 {
				t.Fatal("recovery duplicate refund", audits, e)
			}
		})
	}
}
