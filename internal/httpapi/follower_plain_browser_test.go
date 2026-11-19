package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// The browser, TLS sockets, source API and owner reader are real. The selected
// ingress and readiness callback are controlled fixtures: this is not a
// substitute for the gated, deployed multi-node acceptance.
func TestFollowerPlainRealBrowserFixture(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_FOLLOWER_PLAIN_BROWSER") != "1" {
		t.Skip("isolated real-browser fixture is opt-in")
	}
	if os.Getenv("FC_CHROME_EXECUTABLE") == "" || os.Getenv("FC_PLAYWRIGHT_MODULE") == "" {
		t.Fatal("explicit isolated browser paths required")
	}
	for _, mode := range []string{"Local", "Direct", "Relay"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
			masterRouter, db, dir, public, master := clusterFixture(t, "https://master.test", transport, false)
			ownerRouter, ownerDB, _, _, owner := clusterFixture(t, "https://follower.test", transport, true)
			if _, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
			if err := owner.ConfigureFollowerResourceOrigin("https://resource.test"); err != nil {
				t.Fatal(err)
			}
			transport.routers["https://resource.test"] = ownerRouter
			if mode == "Local" {
				transport.routers["https://entry.test"] = ownerRouter
			}
			pair, err := owner.CreatePair(ctx, store.NodeAudit{})
			if err != nil {
				t.Fatal(err)
			}
			relationID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
			if err != nil {
				t.Fatal(err)
			}
			relation, err := db.Nodes().Relationship(ctx, relationID)
			if err != nil {
				t.Fatal(err)
			}
			configuration := store.ResourceConfiguration{}
			configuration.Storage.Enabled, configuration.Storage.Allocation = true, 5*store.GiB
			if err = db.Pool().ConfigureMember(ctx, relation.PeerID, configuration, store.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
			if err = master.Tick(ctx, relation); err != nil {
				t.Fatal(err)
			}
			if err = db.Nodes().SetRelationshipMode(ctx, relationID, "Direct", false, store.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
			payload := []byte("ID3follower browser content")
			ticket, err := public.media.ReserveMasterEncryptedUpload(ctx, "browser.mp3", "music/Browser", "", "direct", int64(len(payload)), 255, store.AdminAudit{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			reservation, err := db.Pool().Upload(ctx, ticket.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = master.UploadStorage(ctx, reservation, bytes.NewReader(payload)); err != nil {
				t.Fatal(err)
			}
			if _, err = public.media.FinalizeMasterUpload(ctx, ticket.ID, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			ingressID := strings.Repeat("a", 32)
			if mode == "Local" {
				ingressID = relation.PeerID
			}
			ingress := store.PublicIngress{NodeID: ingressID, PublicOrigin: "https://entry.test", Generation: 5}
			routing := &masterDirectHTTPRouting{selectedIngressRepository: selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: ingress}, policy: store.NativeTransportPolicy{MemberID: relation.PeerID, ConfiguredTransport: mode, AppliedTransport: mode, AppliedOrigin: "https://resource.test", State: "applied", Revision: 2}}
			identity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
			if err != nil {
				t.Fatal(err)
			}
			control := node.NewService(routing, identity, followerRelayFixtureTransport{transport})
			control.ConfigureNativeTransportReadiness(func(context.Context, store.Relationship, string) error { return nil })
			public.media.ConfigureCluster(routing, db.Pool(), control)
			ownerRelation, err := ownerDB.Nodes().Relationship(ctx, relationID)
			if err != nil {
				t.Fatal(err)
			}
			_, err = owner.ReceiveHeartbeat(ctx, ownerRelation, map[string]any{"capabilities": protocol.AdvertisedCapabilities(), "public_ingress": map[string]any{"node_id": ingress.NodeID, "public_origin": ingress.PublicOrigin, "generation": ingress.Generation}})
			if err != nil {
				t.Fatal(err)
			}
			verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.PublicOrigin, Generation: ingress.Generation, ClientIP: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			relayRouter := gin.New()
			public.followerRelay, err = registerFollowerRelay(relayRouter, public.media, control, public.crypto)
			if err != nil {
				t.Fatal(err)
			}
			resourceServer := httptest.NewTLSServer(ownerRouter)
			defer resourceServer.Close()
			publicServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/fixture":
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = io.WriteString(w, `<script src="/static/js/compiled/media-crypto-common.js"></script><script src="/static/js/compiled/media-crypto.js"></script>`)
				case r.URL.Path == "/fixture/item":
					_ = json.NewEncoder(w).Encode(map[string]any{"path": ticket.Path, "resource_id": ticket.MediaID, "object_id": ticket.MediaID, "size_bytes": len(payload), "expected": string(payload)})
				case strings.HasPrefix(r.URL.Path, "/api/v1/media/crypto/"):
					admitted, lease := network.WithPublicAdmission(verified)
					defer lease.Abort()
					recorder := httptest.NewRecorder()
					masterRouter.ServeHTTP(recorder, r.WithContext(admitted))
					if !lease.Commit() {
						http.Error(w, "fixture admission failed", 503)
						return
					}
					for key, values := range recorder.Header() {
						for _, value := range values {
							w.Header().Add(key, value)
						}
					}
					w.WriteHeader(recorder.Code)
					_, _ = w.Write(recorder.Body.Bytes())
				case strings.HasPrefix(r.URL.Path, "/api/v1/media/follower-relay/"):
					relayRouter.ServeHTTP(w, r.WithContext(verified))
				case strings.HasPrefix(r.URL.Path, "/internal/v1/media/"):
					ownerRouter.ServeHTTP(w, r)
				default:
					masterRouter.ServeHTTP(w, r)
				}
			}))
			defer publicServer.Close()
			_, publicPort, _ := net.SplitHostPort(publicServer.Listener.Addr().String())
			_, resourcePort, _ := net.SplitHostPort(resourceServer.Listener.Addr().String())
			run, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			command := exec.CommandContext(run, "node", filepath.Join("..", "..", "tests", "follower_plain_browser.mjs"), publicPort, resourcePort, mode)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("isolated browser: %v\n%s", err, output)
			}
			t.Logf("%s", bytes.TrimSpace(output))
		})
	}
}
