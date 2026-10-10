package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type pausedRemoteRecoveryReader struct {
	ctx     context.Context
	reader  io.Reader
	started chan struct{}
	resume  chan struct{}
	paused  bool
}

func (r *pausedRemoteRecoveryReader) Read(bytes []byte) (int, error) {
	if !r.paused {
		r.paused = true
		close(r.started)
		select {
		case <-r.resume:
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		}
	}
	return r.reader.Read(bytes)
}

func TestRemoteExpiredUploadSweepPreservesLiveBodyAndRepairsCompletion(t *testing.T) {
	for _, mode := range []string{"Direct", "Relay"} {
		for _, encrypted := range []bool{false, true} {
			label := "/plain"
			if encrypted {
				label = "/encrypted"
			}
			t.Run(mode+label, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
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
				payload := "ID3payload"
				var metadata *mediacrypto.Metadata
				if encrypted {
					value, err := mediacrypto.NewMetadata(int64(len(payload)))
					if err != nil {
						t.Fatal(err)
					}
					metadata = &value
					payload = strings.Repeat("x", int(value.CiphertextSize))
				}
				size := int64(len(payload))
				v, err := public.media.ReserveMasterEncryptedUpload(ctx, "song.mp3", "music/LiveRecovery", "", strings.ToLower(mode), size, 255, store.AdminAudit{}, metadata)
				if err != nil {
					t.Fatal(err)
				}
				reader := &pausedRemoteRecoveryReader{ctx: ctx, reader: strings.NewReader(payload), started: make(chan struct{}), resume: make(chan struct{})}
				done := make(chan error, 1)
				finished := make(chan struct{})
				go func() {
					defer close(finished)
					if mode == "Relay" {
						_, err := public.media.UploadMasterBytes(ctx, v.ID, reader, store.AdminAudit{})
						done <- err
						return
					}
					// Use the browser's original signed direct PUT capability, not a
					// freshly generated capability after expiry.
					request := httptest.NewRequest("PUT", v.URL, reader).WithContext(ctx)
					request.Header.Set("Origin", "https://master.test")
					response := httptest.NewRecorder()
					fr.ServeHTTP(response, request)
					if response.Code != 200 {
						done <- fmt.Errorf("direct upload HTTP %d: %s", response.Code, response.Body.String())
						return
					}
					done <- nil
				}()
				t.Cleanup(func() {
					cancel()
					<-finished
				})
				select {
				case <-reader.started:
				case <-ctx.Done():
					t.Fatal("upload did not enter the live body transfer", ctx.Err())
				}
				if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=? WHERE upload_id=?", time.Now().Unix()-1, v.ID); err != nil {
					t.Fatal(err)
				}
				if err := public.media.RetryExpiredUploads(ctx); err != nil {
					t.Fatal(err)
				}
				current, err := db.Pool().Upload(ctx, v.ID)
				if err != nil || current.State != "reserved" {
					t.Fatal("expiry discarded a live storage transfer", current, err)
				}
				var used, reserved int64
				if err := db.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", rel.PeerID).Scan(&used, &reserved); err != nil || used != 0 || reserved != size {
					t.Fatal("Master refunded live capacity", used, reserved, err)
				}
				if err := fdb.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members").Scan(&used, &reserved); err != nil || used != 0 || reserved != size {
					t.Fatal("storage discarded its live stage", used, reserved, err)
				}
				close(reader.resume)
				select {
				case err := <-done:
					// Relay's ordinary finalize retains the reservation expiry fence;
					// only the following verified receipt recovery may publish it.
					if mode == "Direct" && err != nil || mode == "Relay" && !errors.Is(err, store.ErrNodeState) {
						t.Fatal("unexpected transfer completion", err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if err := public.media.RetryExpiredUploads(ctx); err != nil {
					t.Fatal(err)
				}
				current, err = db.Pool().Upload(ctx, v.ID)
				if err != nil || current.State != "complete" {
					t.Fatal("live transfer was not recovered after completion", current, err)
				}
				object, err := fdb.Media().ObjectByID(ctx, v.MediaID)
				if err != nil || object == nil {
					t.Fatal("completed storage object lost", object, err)
				}
				if err := db.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", rel.PeerID).Scan(&used, &reserved); err != nil || used != size || reserved != 0 {
					t.Fatal("recovered Master quota", used, reserved, err)
				}
				actual, err := public.media.Encryption(ctx, v.MediaID)
				if err != nil || (actual == nil) != (metadata == nil) || actual != nil && *actual != *metadata {
					t.Fatal("recovery lost or changed the Master encryption descriptor", actual, err)
				}
			})
		}
	}
}

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
