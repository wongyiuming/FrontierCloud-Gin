package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type browserCipherProof struct {
	Ticket       media.UploadTicket   `json:"ticket"`
	Encryption   mediacrypto.Metadata `json:"encryption"`
	CipherSHA256 string               `json:"cipher_sha256"`
	PlainSHA256  string               `json:"plaintext_sha256"`
	Phase        string               `json:"phase"`
	Path         string               `json:"path"`
}

// The compiled page and service-worker modules use Node's real WebCrypto, real
// verified TLS requests and existing Gin handlers. Browser DOM/OPFS adapters,
// Nginx's X-Accel relay and the signed clusterHTTP transport are fixtures; this is not a real
// browser, deployment, private-CA transport or production acceptance test.
func TestBrowserEncryptedHTTPClusterPrimaryDirectRelayLifecycle(t *testing.T) {
	nodeBinary := os.Getenv("FRONTIERCLOUD_TEST_NODE_BINARY")
	if nodeBinary == "" {
		var err error
		nodeBinary, err = exec.LookPath("node")
		if err != nil {
			t.Skip("Node is required for real-WebCrypto HTTP interoperability")
		}
	}
	for _, site := range []string{"primary", "direct", "relay"} {
		t.Run(site, func(t *testing.T) { testBrowserEncryptedHTTPCluster(t, nodeBinary, site) })
	}
}

func testBrowserEncryptedHTTPCluster(t *testing.T, nodeBinary, site string) {
	t.Helper()
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	mr, db, masterDir, public, master := clusterFixture(t, "https://master.test", transport, false)
	fr, fdb, followerDir, _, follower := clusterFixture(t, "https://follower.test", transport, true)
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
	if site != "primary" {
		mode := "Direct"
		if site == "relay" {
			mode = "Relay"
		}
		if err = db.Nodes().SetRelationshipMode(ctx, relationID, mode, false, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
	}
	resolver, _ := network.New(nil)
	public.settings.NginxMedia = site == "relay"
	a := &Admin{public: public, settings: public.settings, network: resolver}
	g := mr.Group("/api/v1/media/admin", func(c *gin.Context) {
		c.Set("admin_session", admin.Session{Hash: "browser-cluster-encryption"})
		c.Next()
	})
	g.POST("/crypto/session", a.cryptoSession)
	g.POST("/crypto/prepare", a.cryptoPrepare)
	g.POST("/crypto/key", a.cryptoKey)
	g.GET("/crypto/bytes", a.cryptoBytes)
	g.POST("/upload/session", a.reserveUpload)
	g.PUT("/upload/session/:upload/bytes", a.uploadBytes)
	g.POST("/upload/session/:upload/finalize", a.finalizeUpload)
	g.POST("/directory/rename", a.renameDirectory)
	g.POST("/delete", a.delete)

	check := func(proof browserCipherProof) error {
		if proof.Ticket.Site != site || proof.Path == "" || proof.CipherSHA256 == proof.PlainSHA256 {
			return errors.New("invalid browser upload proof")
		}
		storedDir, storageDB := masterDir, db
		if site != "primary" {
			storedDir, storageDB = followerDir, fdb
		}
		object, err := storageDB.Media().ObjectByID(ctx, proof.Ticket.MediaID)
		if err != nil {
			return err
		}
		metadata, err := public.media.Encryption(ctx, proof.Ticket.MediaID)
		if err != nil {
			return err
		}
		physicalPath := filepath.Join(storedDir, "media", filepath.FromSlash(proof.Path))
		if proof.Phase == "deleted" {
			if _, err = os.Stat(physicalPath); !errors.Is(err, os.ErrNotExist) || object != nil || metadata != nil {
				return fmt.Errorf("deleted cipher/descriptor remains: disk=%v object=%v metadata=%v", err, object, metadata)
			}
			var rows int
			if err = db.Database().QueryRow("SELECT COUNT(*) FROM global_media_objects WHERE media_id=?", proof.Ticket.MediaID).Scan(&rows); err != nil || rows != 0 {
				return fmt.Errorf("deleted global placement remains: rows=%d %v", rows, err)
			}
		} else {
			ciphertext, err := os.ReadFile(physicalPath)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(ciphertext)
			if hex.EncodeToString(digest[:]) != proof.CipherSHA256 || int64(len(ciphertext)) != proof.Encryption.CiphertextSize {
				return errors.New("storage changed actual browser ciphertext")
			}
			if object == nil || object.Path != proof.Path || object.Encryption == nil || *object.Encryption != proof.Encryption || metadata == nil || *metadata != proof.Encryption {
				return errors.New("Master/storage lost descriptor, path or stable identity")
			}
			var state, path, etag string
			var size int64
			if err = db.Database().QueryRow("SELECT state,media_path,size_bytes,etag FROM global_media_objects WHERE media_id=?", proof.Ticket.MediaID).Scan(&state, &path, &size, &etag); err != nil {
				return err
			}
			expectedState := "active"
			if proof.Phase == "pending_delete" {
				expectedState = "pending_delete"
			}
			if state != expectedState || path != proof.Path || size != proof.Encryption.CiphertextSize || strings.Trim(etag, "\"") != proof.CipherSHA256 {
				return fmt.Errorf("ciphertext receipt does not match placement: %s %s %d %s", state, path, size, etag)
			}
		}
		usedNonce, err := db.Pool().(store.EncryptionRepository).EncryptionUsed(ctx, proof.Encryption.FileID)
		if err != nil || !usedNonce {
			return fmt.Errorf("nonce identity consumption lost: %v", err)
		}
		var used, reserved, catalogBytes int64
		if err = db.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", proof.Ticket.MemberID).Scan(&used, &reserved); err != nil {
			return err
		}
		if err = db.Database().QueryRow("SELECT COALESCE(SUM(size_bytes),0) FROM global_media_objects WHERE storage_member_id=?", proof.Ticket.MemberID).Scan(&catalogBytes); err != nil {
			return err
		}
		if used != catalogBytes || reserved != 0 {
			return fmt.Errorf("Master ciphertext quota inconsistent: used=%d reserved=%d catalog=%d", used, reserved, catalogBytes)
		}
		if site != "primary" {
			if err = fdb.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members").Scan(&used, &reserved); err != nil || used != catalogBytes || reserved != 0 {
				return fmt.Errorf("storage ciphertext quota inconsistent: %d %d %d %v", used, reserved, catalogBytes, err)
			}
		}
		return nil
	}
	control := func(c *gin.Context, operation func(browserCipherProof) error) {
		var proof browserCipherProof
		if err := json.NewDecoder(c.Request.Body).Decode(&proof); err != nil {
			c.JSON(400, gin.H{"detail": err.Error()})
			return
		}
		if err := operation(proof); err != nil {
			c.JSON(500, gin.H{"detail": err.Error()})
			return
		}
		c.JSON(200, gin.H{"ok": true})
	}
	// These four routes only control/assert this disposable test fixture. They
	// are never registered by runtime code and provide no production API.
	mr.POST("/__fixture/check", func(c *gin.Context) { control(c, check) })
	mr.POST("/__fixture/expire-and-recover", func(c *gin.Context) {
		control(c, func(proof browserCipherProof) error {
			if site != "direct" {
				return errors.New("lost-finalize fixture only admits browser Direct uploads")
			}
			reservation, err := db.Pool().Upload(ctx, proof.Ticket.ID)
			if err != nil || reservation.State != "reserved" || reservation.Encryption == nil || *reservation.Encryption != proof.Encryption {
				return fmt.Errorf("lost-finalize reservation changed: %+v %v", reservation, err)
			}
			if _, err = db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=? WHERE upload_id=?", time.Now().Unix()-1, proof.Ticket.ID); err != nil {
				return err
			}
			return public.media.RetryExpiredUploads(ctx)
		})
	})
	mr.POST("/__fixture/fail-delete", func(c *gin.Context) {
		control(c, func(browserCipherProof) error {
			if site == "primary" {
				_, err := db.Database().Exec("CREATE TRIGGER fail_browser_cipher_delete BEFORE INSERT ON admin_audit_log WHEN NEW.action='global-media-delete-completed' BEGIN SELECT RAISE(FAIL,'injected audit failure'); END")
				return err
			}
			delete(transport.routers, "https://follower.test")
			return nil
		})
	})
	mr.POST("/__fixture/recover-delete", func(c *gin.Context) {
		control(c, func(browserCipherProof) error {
			if site == "primary" {
				if _, err := db.Database().Exec("DROP TRIGGER fail_browser_cipher_delete"); err != nil {
					return err
				}
			} else {
				transport.routers["https://follower.test"] = fr
			}
			return public.media.RetryGlobalDeletes(ctx)
		})
	})
	masterEdge := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if site != "relay" {
			mr.ServeHTTP(w, request)
			return
		}
		response := httptest.NewRecorder()
		mr.ServeHTTP(response, request)
		if redirect := response.Header().Get("X-Accel-Redirect"); redirect != "" {
			// Mirror the existing Nginx internal relay's header-based signed
			// capability and Range forwarding; actual Nginx needs deployment QA.
			parts := strings.Split(redirect, "/")
			if len(parts) != 6 || parts[1] != "_relay_media" || parts[2] != "follower.test" || parts[3] != "443" {
				http.Error(w, "unexpected relay fixture target", 502)
				return
			}
			upstream := httptest.NewRequest(request.Method, "https://follower.test/internal/v1/media/"+parts[4], nil).WithContext(request.Context())
			upstream.Header.Set("X-Media-Capability", parts[5])
			upstream.Header.Set("Range", request.Header.Get("Range"))
			response = httptest.NewRecorder()
			fr.ServeHTTP(response, upstream)
		}
		for name, values := range response.Header() {
			if name != "X-Accel-Redirect" {
				w.Header()[name] = values
			}
		}
		w.WriteHeader(response.Code)
		_, _ = w.Write(response.Body.Bytes())
	})
	masterSocket, followerSocket := httptest.NewTLSServer(masterEdge), httptest.NewTLSServer(fr)
	defer masterSocket.Close()
	defer followerSocket.Close()
	caFile := filepath.Join(t.TempDir(), "fixture-ca.pem")
	certificates := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: masterSocket.Certificate().Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: followerSocket.Certificate().Raw})...)
	if err = os.WriteFile(caFile, certificates, 0600); err != nil {
		t.Fatal(err)
	}
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	testContext, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	command := exec.CommandContext(testContext, nodeBinary, "tests/media_crypto_http_fixture.mjs", masterSocket.URL, followerSocket.URL, site)
	command.Dir = repository
	command.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+caFile)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("compiled browser/HTTP %s lifecycle: %v\n%s", site, err, output)
	}
	var evidence struct {
		Site       string `json:"site"`
		Files      int    `json:"files"`
		Grants     int    `json:"http_key_grants"`
		Handshakes int    `json:"browser_handshakes"`
		Ranges     int    `json:"ciphertext_range_requests"`
	}
	if err = json.Unmarshal(output, &evidence); err != nil || evidence.Site != site || evidence.Files != 2 || evidence.Grants != 4 || evidence.Handshakes != 1 || evidence.Ranges < 8 {
		t.Fatalf("incomplete real-WebCrypto HTTP evidence: %s %v", output, err)
	}
	t.Log(strings.TrimSpace(string(output)))
}
