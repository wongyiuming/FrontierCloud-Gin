package httpapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type absenceRaceHTTP struct {
	*clusterHTTP
	publish func()
	legacy  bool
	deletes int
}

func (c *absenceRaceHTTP) Request(ctx context.Context, origin, route, method string, value any, relationship, credential string) (map[string]any, error) {
	if strings.Contains(route, "/delete") {
		c.deletes++
	}
	if strings.HasSuffix(route, "/stat") && c.publish != nil {
		// Stat saw absence, then PUT publishes before the absence request begins.
		callback := c.publish
		c.publish = nil
		callback()
		return nil, node.ErrRemoteNotFound
	}
	if route == "/internal/v1/storage-control/upload-absence" && c.legacy {
		return nil, node.ErrRemoteNotFound
	}
	return c.clusterHTTP.Request(ctx, origin, route, method, value, relationship, credential)
}

func TestRemoteUploadAbsenceRaceLegacyAndExplicitCancelPreserveCommit(t *testing.T) {
	for _, mode := range []string{"Direct", "Relay"} {
		for _, scenario := range []string{"stat-publish-race", "absent", "legacy-unsupported", "explicit-cancel-committed"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				ctx := context.Background()
				transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
				_, db, masterDir, public, master := clusterFixture(t, "https://master.test", transport, false)
				_, fdb, followerDir, _, follower := clusterFixture(t, "https://follower.test", transport, true)
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
				identity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(masterDir, "secrets"))
				if err != nil {
					t.Fatal(err)
				}
				racing := &absenceRaceHTTP{clusterHTTP: transport, legacy: scenario == "legacy-unsupported"}
				control := node.NewService(db.Nodes(), identity, racing)
				public.media.ConfigureCluster(db.Nodes(), db.Pool(), control)
				ticket, err := public.media.ReserveMasterUpload(ctx, "song.mp3", "music/Absence", "", strings.ToLower(mode), 10, 255, store.AdminAudit{})
				if err != nil {
					t.Fatal(err)
				}
				upload, err := db.Pool().Upload(ctx, ticket.ID)
				if err != nil {
					t.Fatal(err)
				}
				publish := func() {
					if _, err := control.UploadStorage(ctx, upload, strings.NewReader("ID3payload")); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "explicit-cancel-committed" {
					publish()
					if err := public.media.CancelMasterUpload(ctx, ticket.ID, store.AdminAudit{}); err == nil {
						t.Fatal("cancel deleted a storage commit")
					}
				} else {
					if scenario == "stat-publish-race" {
						racing.publish = publish
					}
					if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=? WHERE upload_id=?", time.Now().Unix()-1, ticket.ID); err != nil {
						t.Fatal(err)
					}
					if err := public.media.RetryExpiredUploads(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if racing.deletes != 0 {
					t.Fatal("unsafe delete fallback", racing.deletes)
				}
				current, err := db.Pool().Upload(ctx, ticket.ID)
				if scenario == "absent" {
					if !errors.Is(err, store.ErrNodeState) {
						t.Fatal("absent not refunded", current, err)
					}
					var reserved int64
					if err := db.Database().QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", rel.PeerID).Scan(&reserved); err != nil || reserved != 0 {
						t.Fatal("quota not refunded", reserved, err)
					}
					fresh, err := public.media.ReserveMasterUpload(ctx, "song.mp3", "music/Absence", "", strings.ToLower(mode), 10, 255, store.AdminAudit{})
					if err != nil {
						t.Fatal(err)
					}
					freshUpload, err := db.Pool().Upload(ctx, fresh.ID)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := control.UploadStorage(ctx, freshUpload, strings.NewReader("ID3payload")); err != nil {
						t.Fatal("new generation blocked", err)
					}
					return
				}
				if err != nil || current.State != "reserved" {
					t.Fatal("unsafe reservation release", current, err)
				}
				var used, reserved int64
				if err := db.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", rel.PeerID).Scan(&used, &reserved); err != nil || used != 0 || reserved != 10 {
					t.Fatal("master quota changed", used, reserved, err)
				}
				if scenario != "legacy-unsupported" {
					object, err := fdb.Media().ObjectByID(ctx, ticket.MediaID)
					if err != nil || object == nil {
						t.Fatal("storage catalog destroyed", object, err)
					}
					bytes, err := os.ReadFile(filepath.Join(followerDir, "media", ticket.Path))
					if err != nil || string(bytes) != "ID3payload" {
						t.Fatal("storage bytes destroyed", err)
					}
					if err := public.media.RetryExpiredUploads(ctx); err != nil {
						t.Fatal(err)
					}
					if scenario == "stat-publish-race" {
						current, err = db.Pool().Upload(ctx, ticket.ID)
						if err != nil || current.State != "complete" {
							t.Fatal("next sweep did not repair finalize", current, err)
						}
					}
				}
			})
		}
	}
}
