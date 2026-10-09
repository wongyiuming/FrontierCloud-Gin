package httpapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestUploadRecoveryRemoteRefreshLostFinalizeOfflineAndWrongReceipt(t *testing.T) {
	for _, mode := range []string{"Direct", "Relay"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
			_, db, _, public, master := clusterFixture(t, "https://master.test", transport, false)
			fr, fdb, _, _, follower := clusterFixture(t, "https://follower.test", transport, true)
			if _, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
			if _, err := follower.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
			pair, err := follower.CreatePair(ctx, store.NodeAudit{})
			if err != nil {
				t.Fatal(err)
			}
			relID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
			if err != nil {
				t.Fatal(err)
			}
			rel, err := db.Nodes().Relationship(ctx, relID)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Nodes().SetRelationshipMode(ctx, relID, mode, false, store.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
			cfg := store.ResourceConfiguration{}
			cfg.Storage.Enabled, cfg.Storage.Allocation = true, 5*store.GiB
			if err := db.Pool().ConfigureMember(ctx, rel.PeerID, cfg, store.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
			if err := master.Tick(ctx, rel); err != nil {
				t.Fatal(err)
			}
			site := strings.ToLower(mode)
			for _, scenario := range []string{"absent", "lost-finalize", "wrong-receipt"} {
				t.Run(scenario, func(t *testing.T) {
					v, err := public.media.ReserveMasterUpload(ctx, "song.mp3", "music/Refresh-"+scenario, "", site, 10, 255, store.AdminAudit{})
					if err != nil {
						t.Fatal(err)
					}
					upload, err := db.Pool().Upload(ctx, v.ID)
					if err != nil {
						t.Fatal(err)
					}
					if scenario != "absent" {
						if _, err := master.UploadStorage(ctx, upload, strings.NewReader("ID3payload")); err != nil {
							t.Fatal(err)
						}
						if scenario == "wrong-receipt" {
							if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expected_bytes=11 WHERE upload_id=?", v.ID); err != nil {
								t.Fatal(err)
							}
						}
					}
					if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=? WHERE upload_id=?", time.Now().Unix()-1, v.ID); err != nil {
						t.Fatal(err)
					}
					delete(transport.routers, "https://follower.test")
					if err := public.media.RetryExpiredUploads(ctx); err != nil {
						t.Fatal(err)
					}
					current, err := db.Pool().Upload(ctx, v.ID)
					if err != nil || current.State != "reserved" {
						t.Fatal("offline reservation discarded", current, err)
					}
					transport.routers["https://follower.test"] = fr
					if err := public.media.RetryExpiredUploads(ctx); err != nil {
						t.Fatal(err)
					}
					current, err = db.Pool().Upload(ctx, v.ID)
					switch scenario {
					case "absent":
						if !errors.Is(err, store.ErrNodeState) {
							t.Fatal("absent path not released", current, err)
						}
						if _, err := public.media.ReserveMasterUpload(ctx, "song.mp3", "music/Refresh-"+scenario, "", site, 10, 255, store.AdminAudit{}); err != nil {
							t.Fatal("refresh retry remains blocked", err)
						}
					case "lost-finalize":
						if err != nil || current.State != "complete" {
							t.Fatal("complete ciphertext/media deleted instead of recovered", current, err)
						}
						resource, err := db.Pool().Resource(ctx, v.MediaID)
						if err != nil || resource.Bytes != 10 {
							t.Fatal(resource, err)
						}
						object, err := fdb.Media().ObjectByID(ctx, v.MediaID)
						if err != nil || object == nil {
							t.Fatal("storage object lost", object, err)
						}
					case "wrong-receipt":
						if err != nil || current.State != "reserved" {
							t.Fatal("invalid receipt published/refunded", current, err)
						}
					}
				})
			}
		})
	}
}
