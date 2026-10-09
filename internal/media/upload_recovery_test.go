package media

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestExpiredUploadRecoveryReleasesAbandonedButPreservesLiveUnknownAndComplete(t *testing.T) {
	for _, scenario := range []string{"abandoned", "live", "unknown", "complete", "unexpired", "audit-failure"} {
		t.Run(scenario, func(t *testing.T) {
			root, db, svc := masterFixture(t)
			ctx := context.Background()
			v, err := svc.ReserveMasterUpload(ctx, "song.mp3", "music/Refresh", "", "primary", 10, 255, store.AdminAudit{})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "complete" {
				if _, err := svc.UploadMasterBytes(ctx, v.ID, strings.NewReader("ID3payload"), store.AdminAudit{}); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "unknown" {
				if err := os.MkdirAll(filepath.Join(root, "music/Refresh"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, v.Path), []byte("unknown"), 0644); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "live" {
				release, err := svc.uploadSessionLease(v.ID)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			} else if scenario == "audit-failure" {
				if _, err := db.Database().Exec("CREATE TRIGGER expiry_audit_fault BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(FAIL,'audit unavailable'); END"); err != nil {
					t.Fatal(err)
				}
			}
			if scenario != "unexpired" {
				if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=? WHERE upload_id=?", time.Now().Unix()-1, v.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := svc.RetryExpiredUploads(ctx); err != nil {
				t.Fatal(err)
			}
			current, err := db.Pool().Upload(ctx, v.ID)
			if scenario == "abandoned" {
				if !errors.Is(err, store.ErrNodeState) {
					t.Fatal("abandoned reservation remains", current, err)
				}
				masterFunds(t, db, 0, 0)
				if _, err := svc.ReserveMasterUpload(ctx, "song.mp3", "music/Refresh", "", "primary", 10, 255, store.AdminAudit{}); err != nil {
					t.Fatal("refresh retry blocked", err)
				}
			} else if scenario == "complete" {
				if err != nil || current.State != "complete" {
					t.Fatal(current, err)
				}
				masterFunds(t, db, 10, 0)
			} else {
				if err != nil || current.State != "reserved" {
					t.Fatal("unsafe release", current, err)
				}
				masterFunds(t, db, 0, 10)
				if scenario == "unknown" {
					data, err := os.ReadFile(filepath.Join(root, v.Path))
					if err != nil || string(data) != "unknown" {
						t.Fatal("unknown bytes changed", err)
					}
				}
			}
		})
	}
}

func TestPeriodicStorageRecoveryReleasesDeadStageWithoutRestart(t *testing.T) {
	root, db, svc, rel := ownedFixture(t)
	svc.ConfigureCluster(db.Nodes(), db.Pool(), nil)
	ctx := context.Background()
	stage, err := svc.Stage(ctx, strings.NewReader("ID3payload"), 10)
	if err != nil {
		t.Fatal(err)
	}
	object := store.MediaObject{ID: strings.Repeat("5", 64), Path: "music/Refresh/song.mp3", Kind: "audio"}
	if err := db.Pool().ReserveOwnedUpload(ctx, stage.id, rel, object, 10, 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	// A held stage lease fences the sweep even after the browser disconnects.
	if err := svc.RetryExpiredUploads(ctx); err != nil {
		t.Fatal(err)
	}
	ownedFunds(t, db, 0, 10)
	stage.retain = true
	stage.Close()
	if err := svc.RetryExpiredUploads(ctx); err != nil {
		t.Fatal(err)
	}
	ownedFunds(t, db, 0, 0)
	if _, err := os.Stat(filepath.Join(root, ".upload-"+stage.id+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dead partial stage retained", err)
	}
	if err := svc.RetryExpiredUploads(ctx); err != nil {
		t.Fatal("recovery replay", err)
	}
	ownedFunds(t, db, 0, 0)
}

func TestVideoDestinationRejectsMP3BeforeCapacityReservation(t *testing.T) {
	_, db, svc := masterFixture(t)
	_, err := svc.ReserveMasterUpload(context.Background(), "concert.mp3", "vido/Concerts", "", "primary", 10, 255, store.AdminAudit{})
	if !errors.Is(err, ErrPath) {
		t.Fatal("audio routed into video category", err)
	}
	masterFunds(t, db, 0, 0)
}
