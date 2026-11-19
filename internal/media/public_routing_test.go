package media

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// listTransportMismatch models a catalog list read whose placement transport is
// stale. Resource resolution must supply the classification used by a plan.
type listTransportMismatch struct{ store.PoolRepository }

func (p listTransportMismatch) Resources(ctx context.Context, path string, exact bool) ([]store.GlobalMedia, error) {
	rows, err := p.PoolRepository.Resources(ctx, path, exact)
	for i := range rows {
		if rows[i].Transport != "S3" {
			rows[i].Transport = "Relay"
		}
	}
	return rows, err
}

func TestDownloadPlansUseResolvedIngressTransport(t *testing.T) {
	_, db, svc := masterFixture(t)
	ctx := context.Background()
	name := "music/artist/song.mp3"
	svc.pool = listTransportMismatch{db.Pool()}
	d, err := svc.Download(ctx, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, plan := range []func(int) ([]DownloadEntry, error){d.Plan, d.BrowserPlan} {
		entries, err := plan(1)
		if err != nil || len(entries) != 1 || entries[0].Transport != "Local" || entries[0].MediaID == "" || entries[0].ObjectID == "" {
			t.Fatal("plan did not preserve resolved local identity and transport", entries, err)
		}
	}
}

func TestDownloadPlanRejectsChangedGlobalObjectRevision(t *testing.T) {
	for _, change := range []struct {
		name, column, value string
	}{
		{"object", "object_id", strings.Repeat("e", 64)},
		{"etag", "etag", `"replacement"`},
	} {
		t.Run(change.name, func(t *testing.T) {
			_, db, svc := masterFixture(t)
			ctx := context.Background()
			d, err := svc.Download(ctx, []string{"music/artist/song.mp3"})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			entries, err := d.Plan(1)
			if err != nil || len(entries) != 1 {
				t.Fatal(entries, err)
			}
			// Simulate a revision changing between plan creation and the final
			// lookup, including changes outside the managed mutation protocol.
			if _, err = db.Database().Exec("UPDATE global_media_objects SET "+change.column+"=? WHERE media_id=?", change.value, entries[0].MediaID); err != nil {
				t.Fatal(err)
			}
			if _, err = d.PlanDelivery(entries[0].MediaID, entries[0].Snapshot, "", "", true); !errors.Is(err, store.ErrNodeState) {
				t.Fatal("stale plan authorized a different object revision", err)
			}
		})
	}
}

func TestNativeDeliveryFollowsAppliedRelationWithoutFallback(t *testing.T) {
	_, db, svc := deleteFixture(t)
	ctx := context.Background()
	secrets := filepath.Join(t.TempDir(), "secrets")
	identity, err := node.Initialize(ctx, db.Nodes(), secrets)
	if err != nil {
		t.Fatal(err)
	}
	svc.identity = identity
	if err = svc.WithPromotion(ctx, "Master", func(p store.NodePromotion) error {
		p.Endpoint, p.Allocation = "https://master.test", 10*store.GiB
		_, err := db.Nodes().PromoteIdentity(ctx, p, store.NodeAudit{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = db.Nodes().(store.PublicRoutingRepository).ConfigurePublicOrigin("https://master.test"); err != nil {
		t.Fatal(err)
	}
	privateVault, err := vault.OpenExisting(secrets)
	if err != nil {
		t.Fatal(err)
	}
	credential := protocol.Encode(bytes.Repeat([]byte{3}, 48))
	sealed, err := privateVault.Seal(credential)
	if err != nil {
		t.Fatal(err)
	}
	relation := store.Relationship{ID: strings.Repeat("a", 32), PeerID: strings.Repeat("b", 32), Endpoint: "https://owner.test:8443", PublicKey: strings.Repeat("c", 43), Credential: sealed, Direction: "downstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: time.Now().Unix()}
	if err = db.Nodes().PrepareRelationship(ctx, relation, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = db.Nodes().ActivateRelationship(ctx, relation.ID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().Exec("UPDATE node_relationships SET status='online',last_heartbeat=? WHERE relationship_id=?", time.Now().Unix(), relation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().Exec("UPDATE cluster_storage_members SET health='online' WHERE member_id=?", relation.PeerID); err != nil {
		t.Fatal(err)
	}
	name := "music/artist/song.mp3"
	rows, err := db.Pool().Resources(ctx, name, true)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	resourceID := rows[0].ID
	objectID := strings.Repeat("d", 64)
	if _, err = db.Database().Exec("UPDATE global_media_objects SET storage_member_id=?,object_id=? WHERE media_id=?", relation.PeerID, objectID, resourceID); err != nil {
		t.Fatal(err)
	}
	svc.ConfigureCluster(db.Nodes(), db.Pool(), node.NewService(db.Nodes(), identity, nil))
	policy, err := db.Nodes().(store.PublicRoutingRepository).ConfirmNativeTransport(ctx, relation.PeerID, "Direct", 0, store.NodeAudit{})
	if err != nil || policy.State != "blocked" || policy.ConfiguredTransport != "Direct" || policy.EffectiveTransport != "Relay" {
		t.Fatal("desired policy was treated as applied", policy, err)
	}
	blockedDelivery, err := svc.Delivery(ctx, name, resourceID, "", "", true)
	if err != nil || blockedDelivery.Relay == "" || blockedDelivery.Redirect != "" {
		t.Fatal("blocked policy changed the actual resource path", blockedDelivery, err)
	}
	for _, mode := range []string{"Direct", "Relay"} {
		// Deliberately leave the placement field contradictory. The active
		// relationship is the current legacy applied route in this stage.
		if _, err = db.Database().Exec("UPDATE node_relationships SET mode=? WHERE relationship_id=?", mode, relation.ID); err != nil {
			t.Fatal(err)
		}
		storageMode := "Direct"
		if mode == "Direct" {
			storageMode = "Relay"
		}
		if _, err = db.Database().Exec("UPDATE cluster_storage_members SET transport=? WHERE member_id=?", storageMode, relation.PeerID); err != nil {
			t.Fatal(err)
		}
		delivery, err := svc.Delivery(ctx, name, resourceID, "", "", true)
		if err != nil || delivery.Stream != nil || delivery.ResourceID != resourceID || delivery.OwnerID != relation.PeerID || delivery.ObjectID != objectID {
			t.Fatal("delivery identity changed", mode, delivery, err)
		}
		var token string
		if mode == "Direct" {
			u, parseErr := url.Parse(delivery.Redirect)
			if parseErr != nil || u.Host != "owner.test:8443" || u.Path != "/internal/v1/media/"+objectID || delivery.Relay != "" {
				t.Fatal("Direct did not retain the owner route", delivery, parseErr)
			}
			token = u.Query().Get("token")
			withoutRelay, err := svc.Delivery(ctx, name, resourceID, "", "", false)
			if err != nil || withoutRelay.Redirect == "" || withoutRelay.Relay != "" {
				t.Fatal("Direct depended on or fell back to Relay", withoutRelay, err)
			}
		} else {
			parts := strings.Split(delivery.Relay, "/")
			if delivery.Redirect != "" || len(parts) != 6 || parts[1] != "_relay_media" || parts[2] != "owner.test" || parts[3] != "8443" || parts[4] != objectID {
				t.Fatal("Relay did not use the owner-bound path", delivery)
			}
			token = parts[5]
			if _, err := svc.Delivery(ctx, name, resourceID, "", "", false); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unavailable Relay silently chose another path", err)
			}
		}
		claims, err := protocol.VerifyMediaToken(credential, token, time.Now().Unix())
		if err != nil || claims["g"] != resourceID || claims["i"] != objectID || claims["o"] != relation.PeerID {
			t.Fatal("resource capability lost its identity", claims, err)
		}
		download, err := svc.Download(ctx, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		entries, err := download.BrowserPlan(1)
		if err != nil || len(entries) != 1 || entries[0].Transport != mode || entries[0].MediaID != resourceID || entries[0].ObjectID != objectID {
			download.Close()
			t.Fatal("download plan differs from applied route", mode, entries, err)
		}
		if mode == "Direct" {
			// Model a subsequent, explicit application of Relay. A newly
			// authorized read may use it while retaining the same snapshot.
			if _, err = db.Database().Exec("UPDATE node_relationships SET mode='Relay' WHERE relationship_id=?", relation.ID); err != nil {
				t.Fatal(err)
			}
			renewed, err := download.PlanDelivery(resourceID, entries[0].Snapshot, "", "", true)
			if err != nil || renewed.Relay == "" || renewed.Redirect != "" || renewed.ResourceID != resourceID || renewed.OwnerID != relation.PeerID || renewed.ObjectID != objectID {
				t.Fatal("explicitly changed route did not retain the same object", renewed, err)
			}
		}
		download.Close()
	}
}
