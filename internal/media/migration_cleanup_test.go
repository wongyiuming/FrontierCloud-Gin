package media

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
)

type replacedMigrationSource struct {
	store.MigrationPeerRepository
	root          *os.Root
	name, payload string
	calls         int
}

type deferredMigrationCleanup struct {
	store.MediaRepository
	store.OwnedStorageRepository
	fail bool
}

func (r *deferredMigrationCleanup) ForgetDelete(ctx context.Context, id string) error {
	if r.fail {
		r.fail = false
		return errors.New("lost private cleanup receipt")
	}
	return r.MediaRepository.ForgetDelete(ctx, id)
}

func (r *replacedMigrationSource) AuthorizePeerMigration(ctx context.Context, rel string, l store.MigrationLease, id, op string) (store.MigrationPeerObject, error) {
	v, e := r.MigrationPeerRepository.AuthorizePeerMigration(ctx, rel, l, id, op)
	if e != nil || op != "cleanup" {
		return v, e
	}
	r.calls++
	if r.calls == 2 {
		// Swap equal bytes after hashing but before the short deletion transaction.
		if e = r.root.Rename(r.name, ".original-source-inode"); e != nil {
			return v, e
		}
		f, err := r.root.OpenFile(r.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			return v, err
		}
		_, e = f.WriteString(r.payload)
		f.Close()
	}
	return v, e
}

func TestMigrationSourceMediaCleanupBytesAuditRollbackAndReplay(t *testing.T) {
	for _, fault := range []string{"none", "corrupt", "replaced_inode", "audit", "lost_ack", "cleanup_receipt", "crash_pending", "crash_committed"} {
		t.Run(fault, func(t *testing.T) {
			root, db, svc, rel := ownedFixture(t)
			ctx := context.Background()
			payload := "ID3" + strings.Repeat("a", 128<<10)
			o := store.MediaObject{ID: strings.Repeat("5", 64), Path: "music/MigrationCleanup/song.mp3", Kind: "audio"}
			if _, e := svc.OwnedUpload(ctx, rel, o, int64(len(payload)), strings.NewReader(payload), store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			n, e := db.Nodes().ReadIdentity(ctx)
			if e != nil {
				t.Fatal(e)
			}
			h := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: strings.Repeat("1", 32), MasterID: strings.Repeat("e", 32), SourceID: n.ID, TargetID: strings.Repeat("2", 32), SourceRelationship: rel, TargetRelationship: strings.Repeat("3", 32), PlanSHA: strings.Repeat("4", 64), ObjectCount: 1, Bytes: int64(len(payload))}
			l := store.MigrationLease{TaskID: h.TaskID, RunnerID: strings.Repeat("6", 32), Epoch: 1, ExpiresAt: time.Now().Unix() + 60}
			bound := store.MigrationObject{ID: o.ID, ObjectID: o.ID, Resource: "media", Path: o.Path, TargetPath: o.Path, Parent: "music/MigrationCleanup", Kind: o.Kind, Bytes: h.Bytes, Version: strings.Repeat("7", 64)}
			sum := sha256.Sum256([]byte(payload))
			hash := hex.EncodeToString(sum[:])
			repo := db.Pool().(store.MigrationPeerRepository)
			if e = repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 10*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if e = repo.RegisterPeerMigrationObject(ctx, rel, l, store.MigrationPeerObject{Object: bound, Proof: store.MigrationDiskProof{ID: bound.ID, Version: bound.Version, Bytes: bound.Bytes, SHA256: hash}}, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			unit := sha256.Sum256([]byte("media:" + bound.Parent))
			now := time.Now().Unix()
			g := store.MigrationCleanupGrant{TaskID: h.TaskID, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, PlanSHA: h.PlanSHA, UnitID: hex.EncodeToString(unit[:]), UnitVersion: strings.Repeat("8", 64), Object: bound, SHA256: hash, CommittedAt: now - 3601, CleanupAfter: now - 1, TargetVerifiedAt: now}
			if fault == "corrupt" {
				if e = os.WriteFile(filepath.Join(root, o.Path), []byte("!"+payload[1:]), 0644); e != nil {
					t.Fatal(e)
				}
				if e = svc.MigrationCleanup(ctx, rel, l, g, repo, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
					t.Fatal("corrupt source deleted", e)
				}
				ownedFunds(t, db, bound.Bytes, 0)
				if e = os.WriteFile(filepath.Join(root, o.Path), []byte(payload), 0644); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "audit" {
				if _, e = db.Database().Exec("CREATE TRIGGER migration_cleanup_audit BEFORE INSERT ON node_audit WHEN NEW.action='storage-delete-committed' BEGIN SELECT RAISE(FAIL,'cleanup audit unavailable'); END"); e != nil {
					t.Fatal(e)
				}
				if e = svc.MigrationCleanup(ctx, rel, l, g, repo, store.NodeAudit{}); e == nil {
					t.Fatal("audit failure accepted")
				}
				ownedFunds(t, db, bound.Bytes, 0)
				got, e := os.ReadFile(filepath.Join(root, o.Path))
				if e != nil || string(got) != payload {
					t.Fatal("quarantine not restored", e)
				}
				if _, e = db.Database().Exec("DROP TRIGGER migration_cleanup_audit"); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "replaced_inode" {
				r := &replacedMigrationSource{MigrationPeerRepository: repo, root: svc.root, name: bound.Path, payload: payload}
				if e = svc.MigrationCleanup(ctx, rel, l, g, r, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
					t.Fatal("equal-byte replacement inode deleted", e)
				}
				ownedFunds(t, db, bound.Bytes, 0)
				got, e := os.ReadFile(filepath.Join(root, bound.Path))
				if e != nil || string(got) != payload {
					t.Fatal("replacement touched", e)
				}
				if e = svc.root.Rename(".original-source-inode", bound.Path); e != nil {
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
			if fault == "cleanup_receipt" {
				svc.Close()
				svc, e = New(root, &deferredMigrationCleanup{MediaRepository: db.Media(), OwnedStorageRepository: db.Pool(), fail: true}, svc.identity)
				if e != nil {
					t.Fatal(e)
				}
				defer svc.Close()
				if e = svc.MigrationCleanup(ctx, rel, l, g, repo, store.NodeAudit{}); !errors.Is(e, ErrRecovery) {
					t.Fatal("retained cleanup journal reported complete", e)
				}
				ownedFunds(t, db, 0, 0)
			}
			if strings.HasPrefix(fault, "crash_") {
				if e = repo.PreparePeerMigrationCleanup(ctx, rel, l, g, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				op := store.DeleteOperation{ID: strings.Repeat("9", 32), State: "pending", Items: []store.DeleteItem{{Path: bound.Path, Slot: "0", OwnedID: bound.ObjectID, Bytes: bound.Bytes, MigrationTask: l.TaskID, MigrationLogical: bound.ID}}}
				if e = repo.PreparePeerMediaDelete(ctx, rel, l, op, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				q := ".delete-" + op.ID
				if e = svc.root.Mkdir(q, 0700); e != nil {
					t.Fatal(e)
				}
				if e = svc.root.Rename(bound.Path, q+"/0"); e != nil {
					t.Fatal(e)
				}
				if e = svc.syncDirectory(bound.Parent); e != nil {
					t.Fatal(e)
				}
				if e = svc.syncDirectory(q); e != nil {
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
				if _, e = os.Stat(filepath.Join(root, q)); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("restart left private quarantine", e)
				}
				if fault == "crash_pending" {
					ownedFunds(t, db, bound.Bytes, 0)
					got, e := os.ReadFile(filepath.Join(root, bound.Path))
					if e != nil || string(got) != payload {
						t.Fatal("pending source not restored", e)
					}
				} else {
					ownedFunds(t, db, 0, 0)
					if _, e = os.Stat(filepath.Join(root, bound.Path)); !errors.Is(e, os.ErrNotExist) {
						t.Fatal("committed source resurrected", e)
					}
				}
			}
			for range 2 {
				if e = svc.MigrationCleanup(ctx, rel, l, g, repo, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
			}
			ownedFunds(t, db, 0, 0)
			if _, e = os.Stat(filepath.Join(root, o.Path)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("source bytes remain", e)
			}
			var phase string
			if e = db.Database().QueryRow("SELECT state FROM migration_storage_journal WHERE task_id=? AND logical_id=?", h.TaskID, bound.ID).Scan(&phase); e != nil || phase != "deleted" {
				t.Fatal(phase, e)
			}
			var audits int
			if e = db.Database().QueryRow("SELECT COUNT(*) FROM node_audit WHERE action='storage-delete-committed'").Scan(&audits); e != nil || audits != 1 {
				t.Fatal("duplicate deletion refund/audit", audits, e)
			}
		})
	}
}
