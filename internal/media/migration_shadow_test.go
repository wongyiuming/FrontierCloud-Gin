package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPublishedMigrationShadowUsesManagedFilesAndRetiresPrivateAnchor(t *testing.T) {
	for _, fault := range []string{"none", "corrupt", "audit", "replaced_inode", "lost_ack", "crash_pending", "crash_committed"} {
		t.Run(fault, func(t *testing.T) {
			root, db, svc, rel := ownedFixture(t)
			svc.nodes = db.Nodes()
			ctx := context.Background()
			payload := "ID3" + strings.Repeat("x", 128<<10)
			n, e := db.Nodes().ReadIdentity(ctx)
			if e != nil {
				t.Fatal(e)
			}
			h := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: strings.Repeat("1", 32), MasterID: strings.Repeat("e", 32), SourceID: strings.Repeat("2", 32), TargetID: n.ID, SourceRelationship: strings.Repeat("3", 32), TargetRelationship: rel, PlanSHA: strings.Repeat("4", 64), ObjectCount: 1, Bytes: int64(len(payload))}
			l := store.MigrationLease{TaskID: h.TaskID, RunnerID: strings.Repeat("6", 32), Epoch: 1, ExpiresAt: time.Now().Unix() + 60}
			o := store.MigrationObject{ID: strings.Repeat("5", 64), ObjectID: strings.Repeat("5", 64), Resource: "media", Path: "music/ShadowCleanup/song.mp3", TargetPath: "music/ShadowCleanup/song.mp3", Parent: "music/ShadowCleanup", Kind: "audio", Bytes: h.Bytes, Version: strings.Repeat("7", 64)}
			sum := sha256.Sum256([]byte(payload))
			hash := hex.EncodeToString(sum[:])
			v := store.MigrationPeerObject{Object: o, Proof: store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: hash}}
			repo := db.Pool().(store.MigrationPeerRepository)
			if e = repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 10*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if e = repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			spec := migrationdata.Spec{TaskID: h.TaskID, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: hash}
			receiver, e := svc.MigrationReceiver(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = receiver.Begin(ctx, spec); e != nil {
				t.Fatal(e)
			}
			if _, e = receiver.Append(ctx, spec, 0, []byte(payload), hash); e != nil {
				t.Fatal(e)
			}
			if _, e = receiver.Verify(ctx, spec, nil); e != nil {
				t.Fatal(e)
			}
			if e = repo.VerifyPeerMigrationObject(ctx, rel, l, o.ID, o.Bytes, hash); e != nil {
				t.Fatal(e)
			}
			admission := func() error { _, e := repo.AuthorizePeerMigration(ctx, rel, l, o.ID, "publish"); return e }
			if _, e = svc.MigrationPublish(ctx, spec, admission, func(object store.MediaObject, free int64) error {
				return repo.CompletePeerMediaPublication(ctx, rel, l, o.ID, object, o.Bytes, hash, free, store.NodeAudit{})
			}); e != nil {
				t.Fatal(e)
			}
			ownedFunds(t, db, o.Bytes, 0)
			l.Epoch++
			if e = repo.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 10*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			unit := sha256.Sum256([]byte("media:" + o.Parent))
			roster, e := store.MigrationUnitObjectsSHA([]store.MigrationPeerObject{v})
			if e != nil {
				t.Fatal(e)
			}
			g := store.MigrationShadowGrant{Unit: store.MigrationUnitFinishGrant{Header: h, Unit: store.MigrationUnit{ID: hex.EncodeToString(unit[:]), Resource: o.Resource, Parent: o.Parent, State: "cancelled", ObjectCount: 1, Bytes: o.Bytes}, UnitVersion: strings.Repeat("8", 64), ObjectsSHA: roster}, Object: o, SourceProof: store.MigrationCleanupProof{MigrationDiskProof: v.Proof, VerifiedAt: time.Now().Unix()}}
			if fault == "corrupt" {
				if e = os.WriteFile(filepath.Join(root, o.Path), []byte("!"+payload[1:]), 0644); e != nil {
					t.Fatal(e)
				}
				if e = svc.MigrationShadowCleanup(ctx, rel, l, g, repo, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
					t.Fatal("corrupt shadow deleted", e)
				}
				ownedFunds(t, db, o.Bytes, 0)
				if e = os.WriteFile(filepath.Join(root, o.Path), []byte(payload), 0644); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "audit" {
				if _, e = db.Database().Exec("CREATE TRIGGER shadow_delete_audit BEFORE INSERT ON node_audit WHEN NEW.action='storage-delete-committed' BEGIN SELECT RAISE(FAIL,'shadow audit unavailable'); END"); e != nil {
					t.Fatal(e)
				}
				if e = svc.MigrationShadowCleanup(ctx, rel, l, g, repo, store.NodeAudit{}); e == nil {
					t.Fatal("audit fault ignored")
				}
				ownedFunds(t, db, o.Bytes, 0)
				if data, e := os.ReadFile(filepath.Join(root, o.Path)); e != nil || string(data) != payload {
					t.Fatal("shadow not restored after failed commit", e)
				}
				if _, e = db.Database().Exec("DROP TRIGGER shadow_delete_audit"); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "replaced_inode" {
				wrapped := &replacedMigrationSource{MigrationPeerRepository: repo, root: svc.root, name: o.Path, payload: payload}
				if e = svc.MigrationShadowCleanup(ctx, rel, l, g, wrapped, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
					t.Fatal("replacement inode deleted", e)
				}
				ownedFunds(t, db, o.Bytes, 0)
				if e = svc.root.Rename(".original-source-inode", o.Path); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "lost_ack" {
				svc.Close()
				svc, e = New(root, &ambiguousOwnedDeleteRepo{db.Media(), db.Pool()}, svc.identity)
				if e != nil {
					t.Fatal(e)
				}
				defer svc.Close()
			}
			if strings.HasPrefix(fault, "crash_") {
				if e = repo.PreparePeerMigrationShadowDeletion(ctx, rel, l, g, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				op := store.DeleteOperation{ID: strings.Repeat("9", 32), State: "pending", Items: []store.DeleteItem{{Path: o.Path, Slot: "0", OwnedID: o.ObjectID, Bytes: o.Bytes, MigrationTask: l.TaskID, MigrationLogical: o.ID}}}
				if e = repo.PreparePeerMediaDelete(ctx, rel, l, op, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				quarantine := ".delete-" + op.ID
				if e = svc.root.Mkdir(quarantine, 0700); e != nil {
					t.Fatal(e)
				}
				if e = svc.root.Rename(o.Path, quarantine+"/0"); e != nil {
					t.Fatal(e)
				}
				if e = svc.syncDirectory(o.Parent); e != nil {
					t.Fatal(e)
				}
				if e = svc.syncDirectory(quarantine); e != nil {
					t.Fatal(e)
				}
				if fault == "crash_committed" {
					if e = db.Pool().CommitOwnedDelete(ctx, op.ID, 10*store.GiB, store.NodeAudit{}); e != nil {
						t.Fatal(e)
					}
				}
				svc.Close()
				svc, e = New(root, db.Media(), svc.identity)
				if e != nil {
					t.Fatal(e)
				}
				defer svc.Close()
				if _, e = os.Stat(filepath.Join(root, quarantine)); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("restart retained quarantine", e)
				}
				if fault == "crash_pending" {
					if data, e := os.ReadFile(filepath.Join(root, o.Path)); e != nil || string(data) != payload {
						t.Fatal("pending target not restored", e)
					}
					ownedFunds(t, db, o.Bytes, 0)
				} else {
					ownedFunds(t, db, 0, 0)
				}
			}
			for range 2 {
				if e = svc.MigrationShadowCleanup(ctx, rel, l, g, repo, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
			}
			ownedFunds(t, db, 0, 0)
			if _, e = os.Stat(filepath.Join(root, o.Path)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("business shadow remains", e)
			}
			svc.nodes = db.Nodes()
			receiver, e = svc.MigrationReceiver(ctx)
			if e != nil {
				t.Fatal(e)
			}
			cp, e := receiver.Status(ctx, spec)
			if e != nil || !cp.AnchorRetired || cp.AnchorRetiring {
				t.Fatal("private anchor not retired", cp, e)
			}
			entries, e := os.ReadDir(root)
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".part") || strings.HasPrefix(entry.Name(), ".delete-") {
					t.Fatal("retained byte/quarantine material", entry.Name())
				}
			}
			var audits int
			if e = db.Database().QueryRow("SELECT COUNT(*) FROM node_audit WHERE action='storage-delete-committed'").Scan(&audits); e != nil || audits != 1 {
				t.Fatal("duplicate refund audit", audits, e)
			}
		})
	}
}
