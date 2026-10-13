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

func TestInterruptedMigrationPublicationUnlinksOnlyOwnUnaccountedFiles(t *testing.T) {
	for _, fault := range []string{"none", "foreign", "corrupt", "missing"} {
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
				return errors.New("crash before SQL publication")
			}); e == nil {
				t.Fatal("missing publication failure")
			}
			ownedFunds(t, db, 0, o.Bytes)
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
			target := filepath.Join(root, o.TargetPath)
			if fault == "foreign" || fault == "missing" {
				if e = os.Remove(target); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "foreign" {
				if e = os.WriteFile(target, []byte(payload), 0644); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "corrupt" {
				if e = os.WriteFile(target, []byte("!"+payload[1:]), 0644); e != nil {
					t.Fatal(e)
				}
			}
			e = svc.MigrationCancelPublication(ctx, rel, l, g, repo, store.NodeAudit{})
			if fault == "foreign" || fault == "corrupt" {
				if e == nil {
					t.Fatal("unsafe unlink accepted")
				}
				if _, e = os.Stat(target); e != nil {
					t.Fatal("conflicting bytes removed", e)
				}
				ownedFunds(t, db, 0, o.Bytes)
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = os.Stat(target); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("business link survived", e)
			}
			cp, e := receiver.Status(ctx, spec)
			if e != nil || cp.State != "aborted" || !cp.PublicationUnlinked {
				t.Fatal(cp, e)
			}
			if e = svc.MigrationCancelPublication(ctx, rel, l, g, repo, store.NodeAudit{}); e != nil {
				t.Fatal("lost acknowledgment replay", e)
			}
			ownedFunds(t, db, 0, o.Bytes)
		})
	}
}
