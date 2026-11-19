//go:build linux && ledger_fixture

package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/karaoke"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"golang.org/x/crypto/hkdf"
)

type selectedE2EGate struct{}
type selectedE2ELease struct{}

func (selectedE2EGate) AcquireSelectedUpload(ctx context.Context, _ *sealedtree.SQLStore) (business.SelectedUploadRuntimeLease, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return selectedE2ELease{}, nil
}
func (selectedE2ELease) Check(ctx context.Context) error { return ctx.Err() }
func (selectedE2ELease) Release()                        {}

// Real Admin cookie/CSRF, Master transactions, Owner HTTPS body and signed
// receipt are exercised. The readiness gate and offline initialization are
// explicitly test-only; this is not proof that runtime migration is ready.
func TestSelectedAdminToOwnerHTTPAndDurableCompletion(t *testing.T) {
	selectedAdminE2E(t, selectedFixtureOptions{})
}
func TestSelectedAdminRelayAndDurableCompletion(t *testing.T) {
	selectedAdminE2E(t, selectedFixtureOptions{relay: true})
}

func TestSelectedAdminLocalAndDurableCompletion(t *testing.T) {
	selectedAdminE2E(t, selectedFixtureOptions{local: true})
}

func TestSelectedAdminDirectDownloadUsesPinnedOwner(t *testing.T) {
	selectedAdminE2E(t, selectedFixtureOptions{downloadFollower: true})
}

func TestSelectedAdminRelayDownloadUsesPinnedOwner(t *testing.T) {
	selectedAdminE2E(t, selectedFixtureOptions{relay: true, downloadFollower: true})
}

func TestSelectedFollowerMediaDeleteResumesLostOwnerReply(t *testing.T) {
	t.Run("Direct", func(t *testing.T) { selectedAdminE2E(t, selectedFixtureOptions{deleteFollower: true}) })
	t.Run("Relay", func(t *testing.T) { selectedAdminE2E(t, selectedFixtureOptions{relay: true, deleteFollower: true}) })
}

func TestSelectedFolderDeleteResumesExactDescendant(t *testing.T) {
	selectedAdminE2E(t, selectedFixtureOptions{deleteFolder: true})
}

func TestSelectedRecordingDirectHTTPSRejectsMaster(t *testing.T) {
	selectedAdminE2E(t, selectedFixtureOptions{local: true, directRecording: true})
}

func TestSelectedRecordingHTTPSRealRedis(t *testing.T) {
	raw := os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL")
	if raw == "" {
		t.Skip("disposable Redis not configured")
	}
	opts, err := redis.ParseURL(raw)
	if err != nil || opts.Addr != "127.0.0.1:6379" || opts.DB != 0 || opts.Username != "" || opts.Password != "" || opts.TLSConfig != nil {
		t.Fatal("test requires a private loopback Redis fixture")
	}
	cache := redis.NewClient(opts)
	defer cache.Close()
	selectedAdminE2E(t, selectedFixtureOptions{local: true, realRecordingRedis: cache})
}

type selectedFixtureOptions struct {
	relay, local, directRecording, deleteFollower bool
	deleteFolder                                  bool
	realRecordingRedis                            *redis.Client
	downloadFollower                              bool
}

func selectedAdminE2E(t *testing.T, options selectedFixtureOptions) {
	relay, local, directRecording := options.relay, options.local, options.directRecording
	realRecordingRedis := options.realRecordingRedis
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	// This fixture tests a fresh encrypted deployment; legacy seed media
	// would be catalogued by Master promotion before the tree is installed.
	masterRouter, masterDB, masterDir, masterPublic, master := clusterFixture(t, "https://master.test", transport, true)
	ownerRouter, ownerDB, ownerDir, ownerPublic, owner := clusterFixture(t, "https://follower.test", transport, true)
	masterID, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := owner.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err = master.ConfigureSelectedAdminOrigin(ctx, "https://master.test"); err != nil {
		t.Fatal(err)
	}
	pair, err := owner.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	rid, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := masterDB.Nodes().Relationship(ctx, rid)
	if err != nil {
		t.Fatal(err)
	}
	allocation := store.ResourceConfiguration{}
	allocation.Storage.Enabled = true
	allocation.Storage.Allocation = 5 * store.GiB
	if err = masterDB.Pool().ConfigureMember(ctx, ownerID.ID, allocation, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = master.Tick(ctx, relation); err != nil {
		t.Fatal(err)
	}
	routing := masterDB.Nodes().(store.PublicRoutingRepository)
	transportMode := "Direct"
	if relay {
		transportMode = "Relay"
	}
	policy, err := routing.ConfirmNativeTransport(ctx, ownerID.ID, transportMode, 0, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := masterDB.Nodes().Relationship(ctx, rid)
	if err != nil || observed.Summary == nil {
		t.Fatalf("retrieve Owner heartbeat: %v", err)
	}
	observed.Summary["native_resource_origin"] = "https://follower.test"
	if err = masterDB.Nodes().RecordHeartbeat(ctx, rid, true, 0, observed.Summary, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if relay {
		if err = masterDB.Nodes().(interface {
			RecordNativeTransportApplication(context.Context, string, int64, string) error
		}).RecordNativeTransportApplication(ctx, rid, policy.Revision, "Relay"); err != nil {
			t.Fatal(err)
		}
	} else if err = masterDB.Nodes().(interface {
		RecordNativeDirectApplication(context.Context, string, int64, string) error
	}).RecordNativeDirectApplication(ctx, rid, policy.Revision, "https://follower.test"); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(ownerDir, "media")
	if err = os.Chmod(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(rootPath, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	ownerRoot, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerRoot.Close()
	ownerIdentity, err := node.Initialize(ctx, ownerDB.Nodes(), ownerPublic.settings.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	ownerFence, err := ownerfence.Create(ownerRoot, rootPath, ownerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	ownerRepo := ownerDB.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
		AcceptNativeDirectApplication(context.Context, string, int64, string) error
		AcceptNativeTransportApplication(context.Context, string, int64, string) error
	})
	if err = ownerRepo.ConfigureOwnerControlFence(func(c context.Context, x bool) (store.OwnerControlLease, error) { return ownerFence.Acquire(c, x) }); err != nil {
		t.Fatal(err)
	}
	if err = ownerRepo.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	if relay {
		if err = ownerRepo.AcceptNativeTransportApplication(ctx, rid, policy.Revision, "Relay"); err != nil {
			t.Fatal(err)
		}
	} else if err = ownerRepo.AcceptNativeDirectApplication(ctx, rid, policy.Revision, "https://follower.test"); err != nil {
		t.Fatal(err)
	}
	receiver, err := node.NewSelectedDirectReceiver(ctx, owner, ownerFence)
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := network.New(nil)
	if !registerSelectedOwnerHTTP(ownerRouter, ownerPublic.settings, resolver, owner, ownerPublic.media, receiver) {
		t.Fatal("Owner route not attached")
	}
	if !RegisterSelectedRelayOwnerHTTP(ownerRouter, ownerPublic.settings, resolver, owner, ownerPublic.media, receiver) {
		t.Fatal("Owner relay route not attached")
	}
	if options.downloadFollower {
		RegisterOpaqueNodeMedia(ownerRouter, ownerPublic.settings, resolver, owner, ownerPublic.media)
		// This fixture isolates actual Admin/Owner routes. Native readiness
		// has separate signed endpoint-proof tests.
		master.ConfigureNativeTransportReadiness(func(context.Context, store.Relationship, string) error { return nil })
	}
	if options.deleteFollower || options.deleteFolder {
		owner.ConfigureOpaqueOwnerRequestReadiness(func(c context.Context) (node.IngressPrerequisiteLease, error) {
			return ownerRepo.AcquireOwnerControlShared(c)
		})
		RegisterOpaqueRevocationControl(ownerRouter, ownerPublic.settings, resolver, owner, ownerPublic.media)
	}
	ownerServer := httptest.NewTLSServer(ownerRouter)
	defer ownerServer.Close()

	var seq int
	var dbName, dbPath string
	if err = masterDB.Database().QueryRowContext(ctx, "PRAGMA database_list").Scan(&seq, &dbName, &dbPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := masterPublic.settings
	cfg.DataRoot = masterDir
	cfg.SQLitePath = dbPath
	cfg.DatabaseType = config.DatabaseSQLite
	cfg.AdminOrigin = "https://master.test"
	cfg.PublicOrigin = "https://master.test"
	cfg.TLSEnabled = true
	masterPublic.settings.AdminOrigin = cfg.AdminOrigin
	masterPublic.settings.PublicOrigin = cfg.PublicOrigin
	treeDir := filepath.Join(masterDir, "tree")
	if err = os.Mkdir(treeDir, 0700); err != nil {
		t.Fatal(err)
	}
	maintenanceGate, err := maintenance.Open(masterDir)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenanceGate.Close()
	if err = maintenanceGate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = deployment.Bind(ctx, cfg, func(c context.Context) error { return master.ValidateRetainedIdentity(c, cfg.SecretsDirectory) }); err != nil {
		t.Fatal(err)
	}
	codec, err := sealedtree.New(bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	treeID := strings.Repeat("a", 64)
	if err = sealedtree.FixtureInitializeExisting(ctx, cfg, maintenanceGate, codec, treeID, treeDir); err != nil {
		t.Fatal("tree fixture", err)
	}
	tree, err := sealedtree.OpenSQLite(ctx, masterDB.Database(), codec, treeID)
	if err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(treeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	if _, err = sealedtree.OpenFence(ctx, tree, treeRoot, treeDir); err != nil {
		t.Fatal(err)
	}
	masterVault, err := vault.OpenExisting(cfg.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err = maintenanceGate.Resume(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	masterMediaPath := filepath.Join(masterDir, "media")
	if err = os.Chmod(masterMediaPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(masterMediaPath, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	masterRoot, err := os.OpenRoot(masterMediaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer masterRoot.Close()
	masterIdentity, err := node.Initialize(ctx, masterDB.Nodes(), cfg.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	masterFence, err := ownerfence.Create(masterRoot, masterMediaPath, masterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	repo := masterDB.Pool().(*business.Repository)
	if err = repo.ConfigureOwnerControlFence(func(c context.Context, x bool) (store.OwnerControlLease, error) { return masterFence.Acquire(c, x) }); err != nil {
		t.Fatal(err)
	}
	if err = repo.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	capKey := bytes.Repeat([]byte{7}, 32)
	if err = repo.InitializeOpaqueCapacityKey(ctx, capKey); err != nil {
		t.Fatal(err)
	}
	runtime, err := business.NewSelectedUploadRuntime(repo, tree, capKey, masterPublic.crypto, masterVault, cfg.AdminOrigin, selectedE2EGate{})
	if err != nil {
		t.Fatal(err)
	}
	if relay {
		relationNow, e := masterDB.Nodes().Relationship(ctx, rid)
		if e != nil {
			t.Fatal(e)
		}
		credential, e := masterVault.Unseal(relationNow.Credential)
		if e != nil {
			t.Fatal(e)
		}
		if e = runtime.ConfigureRelaySender(&selectedE2ERelaySender{server: ownerServer, relationship: rid, credential: credential}); e != nil {
			t.Fatal(e)
		}
	}
	var localReceiver *node.SelectedLocalReceiver
	if local {
		localReceiver, err = node.NewSelectedLocalReceiver(ctx, master, masterFence)
		if err != nil {
			t.Fatal("local receiver", err)
		}
		if err = runtime.ConfigureLocalOwner(localReceiver); err != nil {
			t.Fatal(err)
		}
	}
	key := "selected-e2e-admin-key"
	if err = os.WriteFile(filepath.Join(cfg.SecretsDirectory, "admin_key"), []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	auth, err := admin.New(cfg, &selectedAdminTestCache{sessions: map[string]map[string]string{}}, masterDB.Admin())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := RegisterAdmin(masterRouter, cfg, auth, masterPublic, masterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	masterPublic.opaqueTree = tree
	if err = handler.ConfigureSelectedUploadRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	var deletionWorker func(context.Context)
	if options.deleteFollower || options.deleteFolder {
		deletionWorker, err = handler.ConfigureSealedMediaDeletion()
		if err != nil {
			t.Fatal(err)
		}
	}
	const recordingPrepareRoute = "/api/v1/karaoke/account/recordings/crypto/audio-prepare"
	const recordingTicketRoute = "/api/v1/karaoke/account/recordings/ticket"
	const recordingLoginRoute = "/api/v1/karaoke/account/login"
	const recordingLogoutRoute = "/api/v1/karaoke/account/logout"
	const recordingPassword = "Fixture-Audio@2345"
	recordingUserID := strings.Repeat("d", 32)
	recordingLogin := karaoke.Session{Token: strings.Repeat("s", 43), CSRF: strings.Repeat("c", 32)}
	otherRecordingLogin := karaoke.Session{Token: strings.Repeat("r", 43), CSRF: strings.Repeat("f", 32)}
	if local {
		masterPublic.ConfigureNetwork(master)
		if err = master.ConfigureLocalIngressReadiness(ctx, func(c context.Context) (node.IngressPrerequisiteLease, error) {
			return node.AcquireCatalogPrerequisite(c, func(c context.Context) (store.OwnerControlLease, error) { return masterFence.Acquire(c, false) }, tree)
		}); err != nil {
			t.Fatal("ingress tree admission", err)
		}
		masterPublic.masterLocalMedia, err = RegisterOpaqueMasterLocalMedia(masterRouter, cfg, "https://master.test", masterPublic.media, master, masterPublic.crypto, tree)
		if err != nil {
			t.Fatal(err)
		}
		masterPublic.masterLocalLyric, err = RegisterOpaqueMasterLocalLyric(masterRouter, cfg, "https://master.test", masterPublic.media, master, masterPublic.crypto, tree)
		if err != nil {
			t.Fatal(err)
		}
		recordingRoot, e := os.OpenRoot(filepath.Join(masterDir, "recordings"))
		if e != nil {
			t.Fatal(e)
		}
		defer recordingRoot.Close()
		volume, e := recording.NewSealedContext(ctx, recordingRoot, masterDB.Recordings(), masterDB.Nodes(), tree)
		if e != nil {
			t.Fatal(e)
		}
		var cache karaoke.Cache = &recordingCryptoCache{sessions: map[string]map[string]string{}}
		passwordHash := "fixture"
		if realRecordingRedis != nil {
			cache = karaoke.NewRedisCache(realRecordingRedis)
			passwordHash, e = karaoke.HashPassword(ctx, recordingPassword)
			if e != nil {
				t.Fatal(e)
			}
		}
		accounts := RegisterKaraokeAccounts(masterRouter, karaoke.New(masterDB.Karaoke(), masterDB.Nodes(), cache), masterPublic, nil, resolver)
		manager := recording.NewManager(masterDB.Recordings(), masterDB.Karaoke(), masterDB.Nodes(), masterDB.Pool(), master, volume)
		RegisterKaraokeRecordings(masterRouter, accounts, manager, volume)
		if directRecording {
			if e = handler.ConfigureSealedRecordingDirect(accounts, repo); e != nil {
				t.Fatal(e)
			}
		} else {
			if e = accounts.ConfigureRecordingAudioPreparation(repo.ReserveRecordingAudioPreparation); e != nil {
				t.Fatal(e)
			}
			if e = accounts.ConfigureRecordingAudioReservation(runtime.AdmitRecordingAudioTicket); e != nil {
				t.Fatal(e)
			}
			if e = accounts.ConfigureRecordingAudioUpload(runtime.UploadRecordingAudioLocal); e != nil {
				t.Fatal(e)
			}
			if e = handler.ConfigureSealedRecordingRead(accounts); e != nil {
				t.Fatal(e)
			}
			if e = handler.ConfigureSealedRecordingDelete(accounts, localReceiver); e != nil {
				t.Fatal(e)
			}
		}
		user := store.KaraokeUser{ID: recordingUserID, Username: "selected-recording", NameKey: "selected-recording", PasswordHash: passwordHash, Quota: 2 * 1024 * 1024}
		if e = masterDB.Karaoke().RegisterUser(ctx, user, "192.0.2.51", "20261105", store.KaraokeAudit{}); e != nil {
			t.Fatal(e)
		}
		otherUser := store.KaraokeUser{ID: strings.Repeat("e", 32), Username: "other-recording", NameKey: "other-recording", PasswordHash: passwordHash, Quota: user.Quota}
		if e = masterDB.Karaoke().RegisterUser(ctx, otherUser, "192.0.2.52", "20261105", store.KaraokeAudit{}); e != nil {
			t.Fatal(e)
		}
		if realRecordingRedis == nil {
			if e = cache.SaveSession(ctx, "karaoke:session:"+karaokeSessionHash(recordingLogin.Token), user.ID, recordingLogin.CSRF, karaokeSessionHash(user.PasswordHash)); e != nil {
				t.Fatal(e)
			}
			if e = cache.SaveSession(ctx, "karaoke:session:"+karaokeSessionHash(otherRecordingLogin.Token), otherUser.ID, otherRecordingLogin.CSRF, karaokeSessionHash(otherUser.PasswordHash)); e != nil {
				t.Fatal(e)
			}
		}
	}
	masterServer := httptest.NewTLSServer(masterRouter)
	defer masterServer.Close()
	login, err := auth.Login(ctx, key, admin.RequestInfo{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	requestAdmin := func(method, route string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, "https://master.test"+route, bytes.NewReader(raw))
		r.Header.Set("Origin", "https://master.test")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", login.CSRF)
		r.AddCookie(&http.Cookie{Name: cfg.AdminCookieName(), Value: login.Cookie})
		r.AddCookie(&http.Cookie{Name: cfg.CSRFCookieName(), Value: login.CSRF})
		w := httptest.NewRecorder()
		masterRouter.ServeHTTP(w, r)
		return w
	}
	browser, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/media/admin"
	sessionResponse := requestAdmin("POST", base+"/crypto/session", map[string]any{"public_key": base64.StdEncoding.EncodeToString(browser.PublicKey().Bytes())})
	var cryptoSession mediacrypto.SessionGrant
	if sessionResponse.Code != 200 || json.Unmarshal(sessionResponse.Body.Bytes(), &cryptoSession) != nil {
		t.Fatal("browser session", sessionResponse.Code, sessionResponse.Body.String())
	}
	plain := []byte("ID3-real-selected-media")
	prep := requestAdmin("POST", base+"/crypto/prepare", map[string]any{"session_id": cryptoSession.SessionID, "plaintext_size": len(plain)})
	var prepared struct {
		Encryption mediacrypto.Metadata    `json:"encryption"`
		Envelope   mediacrypto.KeyEnvelope `json:"key_envelope"`
		Token      string                  `json:"preparation_token"`
	}
	if prep.Code != 200 || json.Unmarshal(prep.Body.Bytes(), &prepared) != nil || prepared.Token == "" {
		t.Fatal("crypto prepare", prep.Code, prep.Body.String())
	}
	serverPubRaw, err := base64.StdEncoding.DecodeString(cryptoSession.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := ecdh.P256().NewPublicKey(serverPubRaw)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := browser.ECDH(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := base64.StdEncoding.DecodeString(cryptoSession.Salt)
	if err != nil {
		t.Fatal(err)
	}
	wrapping := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte("frontiercloud:browser-wrap:v1:"+cryptoSession.SessionID)), wrapping); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(wrapping)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := base64.StdEncoding.DecodeString(prepared.Envelope.IV)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(prepared.Envelope.WrappedKey)
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := aead.Open(nil, iv, wrapped, []byte("frontiercloud:key-envelope:v1:"+cryptoSession.SessionID+":"+prepared.Encryption.FileID))
	if err != nil {
		t.Fatal(err)
	}
	block, err = aes.NewCipher(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err = cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := prepared.Encryption.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, plain, prepared.Encryption.ChunkAAD(0))
	digest := sha256.Sum256(ciphertext)
	idBytes := make([]byte, 16)
	if _, err = rand.Read(idBytes); err != nil {
		t.Fatal(err)
	}
	uploadID := hex.EncodeToString(idBytes)
	selectedMember := ownerID.ID
	if local {
		selectedMember, transportMode = masterID.ID, "Local"
	}
	request := business.SelectedPrepareRequest{UploadID: uploadID, ParentPath: "music/category", Filename: "private-song.mp3", MemberID: selectedMember, CipherSHA256: hex.EncodeToString(digest[:]), Encryption: prepared.Encryption, Preparation: prepared.Token}
	admission := requestAdmin("POST", base+"/upload/selected/prepare", request)
	var ticket business.SelectedDirectTicket
	if admission.Code != 200 || json.Unmarshal(admission.Body.Bytes(), &ticket) != nil || ticket.MemberID != selectedMember || ticket.Transport != transportMode || (!relay && !local && ticket.Capability == "") || ((relay || local) && ticket.Capability != "") {
		diagnosticCtx, diagnosticCancel := context.WithTimeout(ctx, 25*time.Second)
		defer diagnosticCancel()
		_, diagnostic := runtime.PrepareAndIssue(diagnosticCtx, login.Hash, request)
		t.Fatal("selected prepare", admission.Code, "retry diagnosis", diagnostic)
	}
	sendOwner := func(method, route, token string, body []byte) *http.Response {
		t.Helper()
		if relay || local {
			masterPath := base + "/upload/selected/" + uploadID
			switch route {
			case "/api/v1/node/selected-upload":
				masterPath += "/bytes"
			case "/api/v1/node/selected-upload/recover":
				masterPath += "/recover"
			case "/api/v1/node/selected-upload/cleanup":
				masterPath += "/cleanup"
			default:
				t.Fatal("unexpected relay route")
			}
			r := httptest.NewRequest(method, "https://master.test"+masterPath, bytes.NewReader(body))
			r.Header.Set("Origin", "https://master.test")
			r.Header.Set("X-CSRF-Token", login.CSRF)
			r.AddCookie(&http.Cookie{Name: cfg.AdminCookieName(), Value: login.Cookie})
			r.AddCookie(&http.Cookie{Name: cfg.CSRFCookieName(), Value: login.CSRF})
			if local {
				req, e := http.NewRequest(method, masterServer.URL+masterPath, bytes.NewReader(body))
				if e != nil {
					t.Fatal(e)
				}
				req.Host = "master.test"
				req.Header = r.Header.Clone()
				result, e := masterServer.Client().Do(req)
				if e != nil {
					t.Fatal(e)
				}
				return result
			}
			w := httptest.NewRecorder()
			masterRouter.ServeHTTP(w, r)
			return w.Result()
		}
		req, e := http.NewRequest(method, ownerServer.URL+route, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Origin", "https://master.test")
		if token != "" {
			req.Header.Set("X-Fc-Selected-Upload", token)
		}
		if method == "OPTIONS" {
			req.Header.Set("Access-Control-Request-Method", "PUT")
			req.Header.Set("Access-Control-Request-Headers", "content-type, x-fc-selected-upload")
		}
		result, e := ownerServer.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		return result
	}
	if !relay && !local {
		preflight := sendOwner("OPTIONS", "/api/v1/node/selected-upload", "", nil)
		preflight.Body.Close()
		if preflight.StatusCode != 204 {
			t.Fatal("preflight", preflight.StatusCode)
		}
	}
	// Lose the Owner response after publication; a newly issued Admin ticket and
	// the Owner recover endpoint must recover the same durable operation.
	upload := sendOwner("PUT", "/api/v1/node/selected-upload", ticket.Capability, ciphertext)
	io.Copy(io.Discard, upload.Body)
	upload.Body.Close()
	if upload.StatusCode != 200 {
		t.Fatal("Owner upload", upload.StatusCode)
	}
	resume := requestAdmin("POST", base+"/upload/selected/"+uploadID+"/resume", nil)
	var retried business.SelectedDirectTicket
	if resume.Code != 200 || json.Unmarshal(resume.Body.Bytes(), &retried) != nil || retried.MemberID != selectedMember {
		t.Fatal("resume", resume.Code, resume.Body.String())
	}
	recovery := sendOwner("POST", "/api/v1/node/selected-upload/recover", retried.Capability, nil)
	recoveryRaw, err := io.ReadAll(recovery.Body)
	recovery.Body.Close()
	if err != nil || recovery.StatusCode != 200 {
		t.Fatal("recover Owner", recovery.StatusCode, err)
	}
	var receipt selectedSignedReceipt
	if err = json.Unmarshal(recoveryRaw, &receipt); err != nil {
		t.Fatal(err)
	}
	// Simulate an interruption after the Owner receipt is durably recorded but before
	// the Master finalization transaction. An authenticated status request must
	// reconstruct the exact verified receipt so the browser can complete it.
	if err = repo.WithOwnerControlExclusive(ctx, func(c context.Context) error {
		_, e := repo.RecordOpaquePublishedReceipt(c, capKey, masterVault, receipt.Receipt, receipt.Signature)
		return e
	}); err != nil {
		t.Fatal("record receipt", err)
	}
	beforeComplete := requestAdmin("GET", base+"/upload/selected/"+uploadID+"/status", nil)
	var pendingStatus struct {
		State     string                          `json:"state"`
		Receipt   *protocol.OpaqueCapacityReceipt `json:"receipt"`
		Signature string                          `json:"signature"`
	}
	if beforeComplete.Code != 200 || json.Unmarshal(beforeComplete.Body.Bytes(), &pendingStatus) != nil || pendingStatus.State != "pending" || pendingStatus.Receipt == nil || *pendingStatus.Receipt != receipt.Receipt || pendingStatus.Signature != receipt.Signature {
		t.Fatal("pending receipt recovery", beforeComplete.Code, beforeComplete.Body.String())
	}
	complete := requestAdmin("POST", base+"/upload/selected/"+uploadID+"/complete", receipt)
	if complete.Code != 200 {
		t.Fatal("complete", complete.Code, complete.Body.String())
	}
	status := requestAdmin("GET", base+"/upload/selected/"+uploadID+"/status", nil)
	if status.Code != 200 || !strings.Contains(status.Body.String(), `"completed"`) {
		t.Fatal("status", status.Code, status.Body.String())
	}
	blobPath, err := sealedtree.BlobPath(receipt.Receipt.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	readRoot := ownerRoot
	if local {
		readRoot = masterRoot
	}
	stored, err := readRoot.ReadFile(blobPath)
	if err != nil || !bytes.Equal(stored, ciphertext) {
		t.Fatal("ciphertext mismatch", err)
	}
	if strings.Contains(blobPath, request.Filename) || strings.Contains(blobPath, request.ParentPath) {
		t.Fatal("business name exposed in Owner path")
	}
	if options.downloadFollower {
		read, err := tree.AcquireReadFence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		dirID, err := tree.ResolveDirectoryWithLease(ctx, read, request.ParentPath, true)
		var rows []sealedtree.CatalogItem
		if err == nil {
			rows, _, err = tree.ListCatalogPageWithLease(ctx, read, dirID, "", 10, true)
		}
		read.Release()
		if err != nil || len(rows) != 1 {
			t.Fatal("missing exact Follower download catalog", err)
		}
		target := media.OpaqueAdminDownloadTarget{Path: request.ParentPath + "/" + request.Filename, ResourceID: rows[0].Entry.ObjectID, Kind: "file"}
		response := requestAdmin("POST", base+"/download/plan", gin.H{"targets": []media.OpaqueAdminDownloadTarget{target}})
		var plan struct {
			Items []media.OpaqueAdminDownloadEntry `json:"items"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &plan) != nil || len(plan.Items) != 1 || plan.Items[0].Transport != transportMode {
			t.Fatalf("Follower download plan HTTP %d: %s", response.Code, response.Body.String())
		}
		item := plan.Items[0]
		response = requestAdmin("POST", base+"/crypto/key", cryptoKeyBody{SessionID: cryptoSession.SessionID, FilePath: item.Path, ResourceID: item.ResourceID, DownloadSnapshot: item.Snapshot})
		var grant struct {
			Transport string                  `json:"transport"`
			Source    string                  `json:"source_url"`
			Headers   map[string]string       `json:"source_headers"`
			Envelope  mediacrypto.KeyEnvelope `json:"key_envelope"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &grant) != nil || strings.Contains(grant.Source, request.Filename) {
			t.Fatalf("Follower download key HTTP %d: %s", response.Code, response.Body.String())
		}
		if actual := selectedRecordingCipher(t, browser, cryptoSession, item.Encryption, grant.Envelope, plain); !bytes.Equal(actual, ciphertext) {
			t.Fatal("Follower download envelope did not match uploaded ciphertext")
		}
		cipherRange := fmt.Sprintf("bytes=0-%d", len(ciphertext)-1)
		if relay {
			if grant.Transport != "" || len(grant.Headers) != 0 || !strings.HasPrefix(grant.Source, base+"/download/bytes?") {
				t.Fatal("Relay download leaked Owner bearer or bypassed Master")
			}
			r := httptest.NewRequest(http.MethodGet, "https://master.test"+grant.Source, nil)
			r.AddCookie(&http.Cookie{Name: cfg.AdminCookieName(), Value: login.Cookie})
			r.Header.Set("Range", cipherRange)
			r.Header.Set("X-Fc-Download-Session", cryptoSession.SessionID)
			w := httptest.NewRecorder()
			masterRouter.ServeHTTP(w, r)
			if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), ciphertext) || w.Header().Get("ETag") != `"`+item.Snapshot+`"` {
				t.Fatalf("Relay Admin download did not return exact Owner ciphertext: %d %s", w.Code, w.Body)
			}
		} else {
			if grant.Transport != "Native" || len(grant.Headers) != 1 || !strings.HasPrefix(grant.Source, "https://follower.test/internal/v1/opaque-media/") {
				t.Fatal("Direct download did not retain exact public Owner URL")
			}
			alias := strings.TrimPrefix(grant.Source, "https://follower.test")
			// The current public origin differs, so this preflight must use the
			// paired Master Admin proof and cannot inherit the public observation.
			otherIngress := "https://different-public-entry.test"
			if _, err = master.Call(ctx, relation, "/internal/v1/heartbeat", gin.H{"public_ingress": gin.H{
				"node_id": ownerID.ID, "public_origin": otherIngress, "generation": 99}}); err != nil {
				t.Fatal("isolated alternate public ingress observation", err)
			}
			if observed, _, err := owner.ObservedPublicIngress(ctx); err != nil || observed.PublicOrigin != otherIngress {
				t.Fatal("fixture did not distinguish Admin origin from public ingress", err)
			}
			preflight, err := http.NewRequestWithContext(ctx, http.MethodOptions, ownerServer.URL+alias, nil)
			if err != nil {
				t.Fatal(err)
			}
			preflight.Host = "follower.test"
			preflight.Header.Set("Origin", cfg.AdminOrigin)
			preflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
			preflight.Header.Set("Access-Control-Request-Headers", "range, x-media-capability")
			checked, err := ownerServer.Client().Do(preflight)
			if err != nil {
				t.Fatal(err)
			}
			checked.Body.Close()
			if checked.StatusCode != http.StatusNoContent || checked.Header.Get("Access-Control-Allow-Origin") != cfg.AdminOrigin {
				t.Fatalf("paired Admin preflight refused independent origin: %d", checked.StatusCode)
			}
			r, err := http.NewRequestWithContext(ctx, http.MethodGet, ownerServer.URL+alias, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "follower.test"
			r.Header.Set("Origin", cfg.AdminOrigin)
			r.Header.Set("Range", cipherRange)
			r.Header.Set("X-Media-Capability", grant.Headers["X-Media-Capability"])
			got, err := ownerServer.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(got.Body)
			got.Body.Close()
			if err != nil || got.StatusCode != http.StatusPartialContent || !bytes.Equal(data, ciphertext) {
				t.Fatalf("Direct Admin HTTPS read did not match: %d %s %v", got.StatusCode, data, err)
			}
			wrongOrigin := r.Clone(ctx)
			wrongOrigin.Header.Set("Origin", otherIngress)
			denied, err := ownerServer.Client().Do(wrongOrigin)
			if err != nil {
				t.Fatal(err)
			}
			denied.Body.Close()
			if denied.StatusCode != http.StatusForbidden {
				t.Fatalf("Direct Admin bearer accepted from public origin: %d", denied.StatusCode)
			}
		}
		return
	}
	if options.deleteFolder {
		readFolder := func() *media.TreeItem {
			t.Helper()
			response := requestAdmin(http.MethodGet, base+"/tree?path=music", nil)
			var view media.Tree
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &view) != nil {
				t.Fatalf("Admin folder list %d: %s", response.Code, response.Body.String())
			}
			for _, item := range view.Items {
				if item.Path == request.ParentPath {
					return &item
				}
			}
			return nil
		}
		folder := readFolder()
		if folder == nil || folder.Kind != "directory" || folder.MediaID == "" || folder.MutationState != "" {
			t.Fatal("missing exact uploaded folder", folder)
		}
		used := func() int64 {
			t.Helper()
			var n int64
			if err := masterDB.Database().QueryRowContext(ctx, `SELECT used_bytes FROM cluster_storage_members WHERE member_id=?`, ownerID.ID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := used()
		target := store.SelectedMediaDeleteTarget{Path: folder.Path, ResourceID: folder.MediaID, Directory: true}
		call := func(status int) store.SelectedMediaDeleteItem {
			t.Helper()
			response := requestAdmin(http.MethodPost, base+"/delete", gin.H{"targets": []store.SelectedMediaDeleteTarget{target}})
			var result store.SelectedMediaDeleteResult
			if response.Code != status || json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.Items) != 1 ||
				result.Items[0].ResourceID != target.ResourceID || result.Items[0].Path != target.Path || !result.Items[0].Directory {
				t.Fatalf("Admin folder delete %d want %d: %s", response.Code, status, response.Body.String())
			}
			return result.Items[0]
		}
		pending := call(http.StatusAccepted)
		target.OperationID = pending.OperationID
		folder = readFolder()
		if pending.State != store.SelectedMediaDeletePending || pending.OperationID == "" || folder == nil ||
			folder.MutationState != "pending_delete" || folder.MutationID != pending.OperationID || folder.MediaID != target.ResourceID || used() != before {
			t.Fatal("folder pending response did not match durable state", pending, folder)
		}
		stage := "staging/" + receipt.Receipt.OperationID + ".part"
		for _, locator := range []string{blobPath, stage} {
			if _, err := ownerRoot.Stat(locator); err != nil {
				t.Fatal("queue prematurely removed owner bytes", err)
			}
		}
		if response := requestAdmin(http.MethodGet, base+"/tree/search?path=music&q=private", nil); response.Code != http.StatusOK {
			t.Fatal("pending folder broke sibling search", response.Code)
		}
		workerCtx, stopWorker := context.WithCancel(ctx)
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			deletionWorker(workerCtx)
		}()
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			if _, _, err := tree.GetFacts(ctx, target.ResourceID); errors.Is(err, sql.ErrNoRows) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		stopWorker()
		<-stopped
		if folder = readFolder(); folder != nil || used() != before-receipt.Receipt.Bytes {
			t.Fatal("supervised workers did not settle both folder and child exactly once", folder, used())
		}
		for _, locator := range []string{blobPath, stage} {
			if _, err := ownerRoot.Stat(locator); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("owner ciphertext or recovery link remains after folder completion", err)
			}
		}
		completed := call(http.StatusOK)
		if completed.State != store.SelectedMediaDeleteDeleted || completed.OperationID != pending.OperationID {
			t.Fatal("terminal folder replay changed operation", completed)
		}
		return
	}
	if options.deleteFollower {
		stagePath := "staging/" + receipt.Receipt.OperationID + ".part"
		stageInfo, stageErr := ownerRoot.Stat(stagePath)
		blobInfo, blobErr := ownerRoot.Stat(blobPath)
		if stageErr != nil || blobErr != nil || !os.SameFile(stageInfo, blobInfo) {
			t.Fatal("published upload must retain its exact recovery link", stageErr, blobErr)
		}
		read, err := tree.AcquireReadFence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		dirID, err := tree.ResolveDirectoryWithLease(ctx, read, request.ParentPath, true)
		var rows []sealedtree.CatalogItem
		if err == nil {
			rows, _, err = tree.ListCatalogPageWithLease(ctx, read, dirID, "", 10, true)
		}
		read.Release()
		if err != nil || len(rows) != 1 || rows[0].Entry.Name != request.Filename {
			t.Fatal("uploaded fixture absent in exact catalog", err)
		}
		used := func() int64 {
			t.Helper()
			var n int64
			if err := masterDB.Database().QueryRowContext(ctx, `SELECT used_bytes FROM cluster_storage_members WHERE member_id=?`, ownerID.ID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := used()
		target := store.SelectedMediaDeleteTarget{Path: request.ParentPath + "/" + request.Filename, ResourceID: rows[0].Entry.ObjectID}
		lose := true
		transport.dropControlReply = func(route string) bool {
			if lose && route == protocol.OpaqueDeletePath {
				lose = false
				return true
			}
			return false
		}
		call := func(target store.SelectedMediaDeleteTarget, status int) store.SelectedMediaDeleteItem {
			t.Helper()
			result := requestAdmin("POST", base+"/delete", gin.H{"targets": []store.SelectedMediaDeleteTarget{target}})
			var reply store.SelectedMediaDeleteResult
			if result.Code != status || json.Unmarshal(result.Body.Bytes(), &reply) != nil || len(reply.Items) != 1 || reply.Items[0].ResourceID != target.ResourceID {
				t.Fatalf("Admin delete HTTP %d want %d: %s", result.Code, status, result.Body.String())
			}
			return reply.Items[0]
		}
		pending := call(target, http.StatusAccepted)
		if pending.State != store.SelectedMediaDeletePending || pending.OperationID == "" || lose || used() != before {
			t.Fatal("lost Owner reply did not preserve pending quota", pending)
		}
		checkAdminTree := func(wantPending bool) {
			t.Helper()
			response := requestAdmin(http.MethodGet, base+"/tree?path="+url.QueryEscape(request.ParentPath), nil)
			var directory media.Tree
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &directory) != nil || directory.Path != request.ParentPath {
				t.Fatal("could not read exact Admin folder after deletion", response.Code)
			}
			for _, row := range directory.Items {
				if row.Path != target.Path {
					continue
				}
				if !wantPending || row.MediaID != target.ResourceID || row.MutationState != "pending_delete" || row.MutationID != pending.OperationID {
					t.Fatal("Admin folder did not bind the exact pending deletion")
				}
				return
			}
			if wantPending {
				t.Fatal("pending deletion vanished from the Admin folder")
			}
		}
		checkAdminTree(true)
		if _, err := ownerRoot.Stat(blobPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("Owner did not actually unlink ciphertext before the lost reply", err)
		}
		if _, err := ownerRoot.Stat(stagePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("Owner retained the exact upload recovery link after deletion", err)
		}
		target.OperationID = pending.OperationID
		if relay {
			// Recover the durable operation with no browser retry or original
			// Admin session supplied to the worker.
			workerCtx, stopWorker := context.WithCancel(ctx)
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				runtime.RunMediaDeletions(workerCtx, masterPublic.media)
			}()
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) && used() == before {
				time.Sleep(20 * time.Millisecond)
			}
			stopWorker()
			<-stopped
			if used() != before-receipt.Receipt.Bytes {
				t.Fatal("background worker did not settle durable deletion")
			}
		}
		deleted := call(target, http.StatusOK)
		if deleted.State != store.SelectedMediaDeleteDeleted || deleted.OperationID != pending.OperationID || used() != before-receipt.Receipt.Bytes {
			t.Fatal("exact replay did not settle the original deletion", deleted)
		}
		if replay := call(target, http.StatusOK); replay != deleted || used() != before-receipt.Receipt.Bytes {
			t.Fatal("terminal replay changed quota or operation", replay)
		}
		checkAdminTree(false)
		return
	}
	if local {
		// Upload a separate encrypted lyric, then bind it through Admin HTTP.
		lyricPlain := []byte("[00:01.00]hello lyric\n")
		lyricPrep := requestAdmin("POST", base+"/crypto/prepare", map[string]any{"session_id": cryptoSession.SessionID, "plaintext_size": len(lyricPlain)})
		var lp struct {
			Encryption mediacrypto.Metadata    `json:"encryption"`
			Envelope   mediacrypto.KeyEnvelope `json:"key_envelope"`
			Token      string                  `json:"preparation_token"`
		}
		if lyricPrep.Code != 200 || json.Unmarshal(lyricPrep.Body.Bytes(), &lp) != nil || lp.Token == "" {
			t.Fatal("lyric crypto prepare", lyricPrep.Code)
		}
		wrapBlock, e := aes.NewCipher(wrapping)
		if e != nil {
			t.Fatal(e)
		}
		wrapAEAD, e := cipher.NewGCM(wrapBlock)
		if e != nil {
			t.Fatal(e)
		}
		iv, e := base64.StdEncoding.DecodeString(lp.Envelope.IV)
		if e != nil {
			t.Fatal(e)
		}
		wrapped, e := base64.StdEncoding.DecodeString(lp.Envelope.WrappedKey)
		if e != nil {
			t.Fatal(e)
		}
		key, e := wrapAEAD.Open(nil, iv, wrapped, []byte("frontiercloud:key-envelope:v1:"+cryptoSession.SessionID+":"+lp.Encryption.FileID))
		if e != nil {
			t.Fatal(e)
		}
		block, e := aes.NewCipher(key)
		if e != nil {
			t.Fatal(e)
		}
		crypt, e := cipher.NewGCM(block)
		if e != nil {
			t.Fatal(e)
		}
		nonce, e := lp.Encryption.ChunkNonce(0)
		if e != nil {
			t.Fatal(e)
		}
		lyricBytes := crypt.Seal(nil, nonce, lyricPlain, lp.Encryption.ChunkAAD(0))
		sum := sha256.Sum256(lyricBytes)
		if _, e = rand.Read(idBytes); e != nil {
			t.Fatal(e)
		}
		lyricUploadID := hex.EncodeToString(idBytes)
		lyricReq := business.SelectedPrepareRequest{UploadID: lyricUploadID, ParentPath: "lyrics/artist", Filename: "private-song.lrc", MemberID: masterID.ID, CipherSHA256: hex.EncodeToString(sum[:]), Encryption: lp.Encryption, Preparation: lp.Token}
		wrong := lyricReq
		wrong.MemberID = ownerID.ID
		if response := requestAdmin("POST", base+"/upload/selected/prepare", wrong); response.Code == 200 {
			t.Fatal("lyric allowed a Follower target")
		}
		reserved := lyricReq
		reserved.ParentPath = "lyrics"
		reserved.Filename = "default.lrc"
		if response := requestAdmin("POST", base+"/upload/selected/prepare", reserved); response.Code == 200 {
			t.Fatal("reserved default lyric accepted")
		}
		lyricAdmission := requestAdmin("POST", base+"/upload/selected/prepare", lyricReq)
		var lyricTicket business.SelectedDirectTicket
		if lyricAdmission.Code != 200 || json.Unmarshal(lyricAdmission.Body.Bytes(), &lyricTicket) != nil || lyricTicket.Transport != "Local" || lyricTicket.MemberID != masterID.ID {
			t.Fatal("lyric admission", lyricAdmission.Code, lyricAdmission.Body.String())
		}
		uploadID = lyricUploadID
		lyricUpload := sendOwner("PUT", "/api/v1/node/selected-upload", "", lyricBytes)
		lyricRaw, e := io.ReadAll(lyricUpload.Body)
		lyricUpload.Body.Close()
		var lyricReceipt selectedSignedReceipt
		if e != nil || lyricUpload.StatusCode != 200 || json.Unmarshal(lyricRaw, &lyricReceipt) != nil {
			t.Fatal("lyric upload", lyricUpload.StatusCode, e)
		}
		lyricFinish := requestAdmin("POST", base+"/upload/selected/"+lyricUploadID+"/complete", lyricReceipt)
		if lyricFinish.Code != 200 {
			t.Fatal("lyric complete", lyricFinish.Code)
		}
		readLease, e := tree.AcquireReadFence(ctx)
		if e != nil {
			t.Fatal(e)
		}
		trackDir, e := tree.ResolveDirectoryWithLease(ctx, readLease, "music/category", true)
		if e != nil {
			readLease.Release()
			t.Fatal(e)
		}
		tracks, _, e := tree.ListVisibleWithLease(ctx, readLease, trackDir, "", 10)
		if e != nil || len(tracks) != 1 {
			readLease.Release()
			t.Fatal("track lookup", e, len(tracks))
		}
		lyricDir, e := tree.ResolveDirectoryWithLease(ctx, readLease, "lyrics/artist", true)
		if e != nil {
			readLease.Release()
			t.Fatal(e)
		}
		lyrics, _, e := tree.ListVisibleWithLease(ctx, readLease, lyricDir, "", 10)
		if e != nil || len(lyrics) != 1 || lyrics[0].Kind != "lyric" {
			readLease.Release()
			t.Fatal("lyric lookup", e, len(lyrics))
		}
		trackID, lyricID := tracks[0].ObjectID, lyrics[0].ObjectID
		downloadTarget := media.OpaqueAdminDownloadTarget{Path: request.ParentPath + "/" + request.Filename, ResourceID: trackID, Kind: "file"}
		downloadPlan := func(target media.OpaqueAdminDownloadTarget, zip bool) media.OpaqueAdminDownloadEntry {
			t.Helper()
			response := requestAdmin("POST", base+"/download/plan", gin.H{"targets": []media.OpaqueAdminDownloadTarget{target}})
			var plan struct {
				Items []media.OpaqueAdminDownloadEntry `json:"items"`
				ZIP   bool                             `json:"force_zip"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &plan) != nil || len(plan.Items) != 1 || plan.ZIP != zip ||
				plan.Items[0].ResourceID != trackID || plan.Items[0].Path != downloadTarget.Path || plan.Items[0].Encryption != prepared.Encryption {
				t.Fatalf("exact Admin download plan %d: %s", response.Code, response.Body.String())
			}
			return plan.Items[0]
		}
		item := downloadPlan(downloadTarget, false)
		folderResponse := requestAdmin("GET", base+"/tree?path=music", nil)
		var folderTree media.Tree
		if folderResponse.Code != http.StatusOK || json.Unmarshal(folderResponse.Body.Bytes(), &folderTree) != nil || len(folderTree.Items) != 1 || folderTree.Items[0].Path != request.ParentPath || folderTree.Items[0].MediaID == "" {
			t.Fatalf("Admin tree did not supply exact folder ID: %d %s", folderResponse.Code, folderResponse.Body.String())
		}
		folderItem := downloadPlan(media.OpaqueAdminDownloadTarget{Path: request.ParentPath, ResourceID: folderTree.Items[0].MediaID, Kind: "directory"}, true)
		if folderItem.Snapshot != item.Snapshot {
			t.Fatal("folder plan did not pin the same immutable child")
		}
		downloadKeyRequest := cryptoKeyBody{SessionID: cryptoSession.SessionID, FilePath: item.Path, ResourceID: item.ResourceID, DownloadSnapshot: item.Snapshot}
		keyResponse := requestAdmin("POST", base+"/crypto/key", downloadKeyRequest)
		var downloadGrant struct {
			ResourceID string                  `json:"resource_id"`
			Snapshot   string                  `json:"download_snapshot"`
			Source     string                  `json:"source_url"`
			Envelope   mediacrypto.KeyEnvelope `json:"key_envelope"`
		}
		if keyResponse.Code != http.StatusOK || json.Unmarshal(keyResponse.Body.Bytes(), &downloadGrant) != nil || downloadGrant.ResourceID != trackID ||
			downloadGrant.Snapshot != item.Snapshot || !strings.HasPrefix(downloadGrant.Source, base+"/download/bytes?") || strings.Contains(downloadGrant.Source, request.Filename) {
			t.Fatalf("Admin download key did not bind the plan: %d %s", keyResponse.Code, keyResponse.Body.String())
		}
		if actual := selectedRecordingCipher(t, browser, cryptoSession, item.Encryption, downloadGrant.Envelope, plain); !bytes.Equal(actual, ciphertext) {
			t.Fatal("Admin download envelope did not unwrap the uploaded object's key")
		}
		readAdminDownload := func(source, rangeValue, sessionID string) *httptest.ResponseRecorder {
			t.Helper()
			r := httptest.NewRequest(http.MethodGet, "https://master.test"+source, nil)
			r.AddCookie(&http.Cookie{Name: cfg.AdminCookieName(), Value: login.Cookie})
			r.Header.Set("Range", rangeValue)
			r.Header.Set("X-Fc-Download-Session", sessionID)
			w := httptest.NewRecorder()
			masterRouter.ServeHTTP(w, r)
			return w
		}
		cipherRange := fmt.Sprintf("bytes=0-%d", len(ciphertext)-1)
		rangeResponse := readAdminDownload(downloadGrant.Source, cipherRange, cryptoSession.SessionID)
		if rangeResponse.Code != http.StatusPartialContent || rangeResponse.Header().Get("ETag") != `"`+item.Snapshot+`"` || !bytes.Equal(rangeResponse.Body.Bytes(), ciphertext) {
			t.Fatalf("Admin download returned wrong ciphertext: HTTP %d", rangeResponse.Code)
		}
		if denied := readAdminDownload(downloadGrant.Source, "bytes=0-0", cryptoSession.SessionID); denied.Code != http.StatusRequestedRangeNotSatisfiable {
			t.Fatal("partial GCM chunk was accepted", denied.Code)
		}
		staleSource := strings.Replace(downloadGrant.Source, item.Snapshot, strings.Repeat("f", 64), 1)
		if denied := readAdminDownload(staleSource, cipherRange, cryptoSession.SessionID); denied.Code != http.StatusConflict {
			t.Fatal("stale download snapshot was accepted", denied.Code)
		}
		downloadKeyRequest.FilePath = "music/category/replacement.mp3"
		if denied := requestAdmin("POST", base+"/crypto/key", downloadKeyRequest); denied.Code != http.StatusConflict {
			t.Fatal("Admin key followed a different path", denied.Code)
		}
		page, _, e := tree.ListCatalogPageWithLease(ctx, readLease, trackDir, "", 10, false)
		if e != nil || tree.VerifyNativeCatalogLyricFactsWithLease(ctx, readLease, page) != nil {
			readLease.Release()
			t.Fatal("new audio catalog lyric proof", e)
		}
		selection, e := tree.SelectLyricForDisplayWithLease(ctx, readLease, trackID)
		if e != nil || !selection.BuiltinFallback {
			readLease.Release()
			t.Fatal("new audio default lyric decision", e)
		}
		readLease.Release()
		var legacyRows int
		if e = masterDB.Database().QueryRowContext(ctx, `SELECT COUNT(*) FROM global_media_objects`).Scan(&legacyRows); e != nil || legacyRows != 0 {
			t.Fatal("fresh tree unexpectedly relies on old catalog", legacyRows, e)
		}
		lyricMetadata := func(track, id string) *httptest.ResponseRecorder {
			t.Helper()
			query := url.Values{"track": {track}, "resource_id": {id}}
			r := httptest.NewRequest(http.MethodGet, "https://master.test/api/v1/media/lyrics/content?"+query.Encode(), nil)
			w := httptest.NewRecorder()
			masterRouter.ServeHTTP(w, r)
			return w
		}
		defaultResponse := lyricMetadata("music/category/private-song.mp3", trackID)
		if defaultResponse.Code != http.StatusOK || !strings.Contains(defaultResponse.Body.String(), `"entries"`) {
			t.Fatal("fresh sealed default lyric", defaultResponse.Code, defaultResponse.Body.String())
		}
		if response := lyricMetadata("music/category/not-the-track.mp3", trackID); response.Code == http.StatusOK {
			t.Fatal("mismatched track path admitted")
		}
		if response := lyricMetadata("music/category/private-song.mp3", strings.Repeat("0", 64)); response.Code == http.StatusOK {
			t.Fatal("mismatched track ID admitted")
		}
		if _, _, e = masterPublic.media.OpaqueTrackBuiltinFallback(ctx, tree, trackID, "music/category/private-song.mp3"); e == nil {
			t.Fatal("default lyric admitted without ingress authority")
		}
		if _, e = masterDB.Database().ExecContext(ctx, `UPDATE cluster_storage_members SET health='offline' WHERE member_id=?`, masterID.ID); e != nil {
			t.Fatal("disable owner", e)
		}
		if response := lyricMetadata("music/category/private-song.mp3", trackID); response.Code == http.StatusOK {
			t.Fatal("offline owner admitted")
		}
		if _, e = masterDB.Database().ExecContext(ctx, `UPDATE cluster_storage_members SET health='online' WHERE member_id=?`, masterID.ID); e != nil {
			t.Fatal("restore owner", e)
		}
		badBinding := requestAdmin("POST", base+"/lyrics/relations", gin.H{"origin_kind": "track", "origin_path": "music/category/private-song.mp3", "linked_paths": []string{"lyrics/artist/missing.lrc"}})
		if badBinding.Code == 200 {
			t.Fatal("missing lyric accepted")
		}
		binding := requestAdmin("POST", base+"/lyrics/relations", gin.H{"origin_kind": "track", "origin_path": "music/category/private-song.mp3", "linked_paths": []string{"lyrics/artist/private-song.lrc"}})
		if binding.Code != 200 || !strings.Contains(binding.Body.String(), `"relations":1`) {
			t.Fatal("new-tree Admin lyric binding", binding.Code, binding.Body.String())
		}
		explicitResponse := lyricMetadata("music/category/private-song.mp3", trackID)
		if explicitResponse.Code != http.StatusOK || !strings.Contains(explicitResponse.Body.String(), `"resource_id":"`+lyricID+`"`) || !strings.Contains(explicitResponse.Body.String(), `"native_source":true`) {
			t.Fatal("fresh sealed explicit lyric", explicitResponse.Code, explicitResponse.Body.String())
		}
		for _, hidden := range []bool{true, false} {
			visibility := requestAdmin(http.MethodPost, base+"/hide", gin.H{"paths": []string{"music/category"}, "hidden": hidden})
			var change struct {
				Hidden         bool   `json:"hidden"`
				Changed        int    `json:"changed"`
				ExistingGrants string `json:"existing_grants"`
			}
			if visibility.Code != http.StatusOK || json.Unmarshal(visibility.Body.Bytes(), &change) != nil ||
				change.Hidden != hidden || change.Changed != 1 || (change.ExistingGrants == "expire_normally") != hidden {
				t.Fatal("sealed directory visibility mutation", visibility.Code, visibility.Body.String())
			}
			treeResponse := requestAdmin(http.MethodGet, base+"/tree?path=music", nil)
			var treeView struct {
				Items []struct {
					Path         string `json:"path"`
					Hideable     bool   `json:"hideable"`
					Hidden       bool   `json:"hidden"`
					HiddenDirect bool   `json:"hidden_direct"`
				} `json:"items"`
			}
			if treeResponse.Code != http.StatusOK || json.Unmarshal(treeResponse.Body.Bytes(), &treeView) != nil {
				t.Fatal("sealed directory visibility readback", treeResponse.Code, treeResponse.Body.String())
			}
			found := false
			for _, item := range treeView.Items {
				if item.Path == "music/category" {
					found = item.Hideable && item.Hidden == hidden && item.HiddenDirect == hidden
				}
			}
			if !found {
				t.Fatal("sealed Admin visibility differs from its committed rule", treeResponse.Body.String())
			}
			publicLyric := lyricMetadata("music/category/private-song.mp3", trackID)
			if publicLyric.Code != http.StatusOK || !strings.Contains(publicLyric.Body.String(), `"resource_id":"`+lyricID+`"`) {
				t.Fatal("sealed exact public lyric lost its link after a visibility change", hidden, publicLyric.Code)
			}
		}
		catalogResponse := requestAdmin(http.MethodGet, base+"/lyrics/catalog?track_path=music%2Fcategory&lyric_path=lyrics%2Fartist", nil)
		var catalog struct {
			Scope       string `json:"sealed_scope"`
			CountScope  string `json:"counts_scope"`
			UsageScope  string `json:"lyric_usage_scope"`
			UsageFilter bool   `json:"lyric_usage_filter"`
			Tracks      []struct {
				MediaID string `json:"media_id"`
			} `json:"tracks"`
			Lyrics []struct {
				LyricID     string `json:"lyric_id"`
				LinkedCount *int   `json:"linked_count"`
			} `json:"lyrics"`
			Relations []struct {
				Track string `json:"track"`
				Lyric string `json:"lyric"`
			} `json:"relations"`
		}
		if catalogResponse.Code != http.StatusOK || json.Unmarshal(catalogResponse.Body.Bytes(), &catalog) != nil ||
			catalog.Scope != "directory" || catalog.CountScope != "subtree" || catalog.UsageScope != "track_subtree" || !catalog.UsageFilter ||
			len(catalog.Tracks) != 1 || catalog.Tracks[0].MediaID != trackID || len(catalog.Lyrics) != 1 || catalog.Lyrics[0].LyricID != lyricID ||
			catalog.Lyrics[0].LinkedCount == nil || *catalog.Lyrics[0].LinkedCount != 1 ||
			len(catalog.Relations) != 1 || catalog.Relations[0].Track != "music/category/private-song.mp3" || catalog.Relations[0].Lyric != "lyrics/artist/private-song.lrc" {
			t.Fatal("new-tree Admin lyric catalog", catalogResponse.Code, catalogResponse.Body.String())
		}
		searchCatalog := requestAdmin(http.MethodGet, base+"/lyrics/catalog?track_q=category%2Fprivate-song&lyric_q=artist%2Fprivate-song&lyric_usage=used", nil)
		if searchCatalog.Code != http.StatusOK || json.Unmarshal(searchCatalog.Body.Bytes(), &catalog) != nil || len(catalog.Tracks) != 1 ||
			catalog.Tracks[0].MediaID != trackID || len(catalog.Lyrics) != 1 || catalog.Lyrics[0].LinkedCount == nil || *catalog.Lyrics[0].LinkedCount != 1 {
			t.Fatal("new-tree Admin scoped search and usage", searchCatalog.Code, searchCatalog.Body.String())
		}
		readLease, e = tree.AcquireReadFence(ctx)
		if e != nil {
			t.Fatal(e)
		}
		linkedTrack, linked, e := tree.ReadLinkedVisibleLyricWithLease(ctx, readLease, trackID)
		readLease.Release()
		if e != nil || linked.Entry.ObjectID != lyricID {
			t.Fatal("new-tree linked lyric", e)
		}
		lyricPatch := func(linked, unlinked []string) *httptest.ResponseRecorder {
			return requestAdmin(http.MethodPost, base+"/lyrics/relations", gin.H{
				"origin_kind": "lyric", "origin_path": "lyrics/artist/private-song.lrc", "linked_paths": linked, "unlinked_paths": unlinked,
			})
		}
		track := "music/category/private-song.mp3"
		if response := lyricPatch([]string{track}, []string{track}); response.Code != http.StatusBadRequest {
			t.Fatal("overlapping lyric patch accepted", response.Code)
		}
		if response := lyricPatch([]string{}, []string{track}); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"unlinked":1`) {
			t.Fatal("new-tree Admin lyric unlink", response.Code, response.Body.String())
		}
		unusedCatalog := requestAdmin(http.MethodGet, base+"/lyrics/catalog?lyric_usage=unused", nil)
		if unusedCatalog.Code != http.StatusOK || json.Unmarshal(unusedCatalog.Body.Bytes(), &catalog) != nil || len(catalog.Lyrics) != 1 ||
			catalog.Lyrics[0].LyricID != lyricID || catalog.Lyrics[0].LinkedCount == nil || *catalog.Lyrics[0].LinkedCount != 0 {
			t.Fatal("new-tree Admin verified unused lyric", unusedCatalog.Code, unusedCatalog.Body.String())
		}
		if response := lyricPatch([]string{}, []string{track}); response.Code != http.StatusConflict {
			t.Fatal("stale lyric unlink accepted", response.Code)
		}
		if response := requestAdmin(http.MethodPost, base+"/lyrics/auto-relate", gin.H{"manual": false}); response.Code != http.StatusBadRequest {
			t.Fatal("non-manual automatic lyric action accepted", response.Code)
		}
		if response := requestAdmin(http.MethodPost, base+"/lyrics/auto-relate", gin.H{"manual": true, "track_path": "vido"}); response.Code != http.StatusBadRequest {
			t.Fatal("invalid automatic lyric scope accepted", response.Code, response.Body.String())
		}
		if response := lyricMetadata(track, trackID); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"entries"`) {
			t.Fatal("refused automatic action changed the fallback", response.Code, response.Body.String())
		}
		if response := requestAdmin(http.MethodPost, base+"/lyrics/auto-relate", gin.H{"manual": true, "track_path": "music/category", "lyric_path": "lyrics/artist"}); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"linked":1`) {
			t.Fatal("new-tree automatic lyric link", response.Code, response.Body.String())
		}
		if response := lyricMetadata(track, trackID); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"resource_id":"`+lyricID+`"`) {
			t.Fatal("automatically linked lyric did not reach the player", response.Code, response.Body.String())
		}
		if response := requestAdmin(http.MethodPost, base+"/lyrics/auto-relate", gin.H{"manual": true}); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"preserved":1`) || !strings.Contains(response.Body.String(), `"linked":0`) {
			t.Fatal("automatic lyric action did not preserve an existing binding", response.Code, response.Body.String())
		}
		var browserCookie *http.Cookie
		activeRecordingLogin := recordingLogin
		publicPost := func(route string, data any) (*http.Response, []byte) {
			t.Helper()
			encoded, e := json.Marshal(data)
			if e != nil {
				t.Fatal(e)
			}
			r, e := http.NewRequest(http.MethodPost, masterServer.URL+route, bytes.NewReader(encoded))
			if e != nil {
				t.Fatal(e)
			}
			r.Host = "master.test"
			r.Header.Set("Origin", "https://master.test")
			r.Header.Set("Content-Type", "application/json")
			if browserCookie != nil {
				r.AddCookie(browserCookie)
			}
			if route == recordingPrepareRoute || route == recordingTicketRoute || route == recordingLogoutRoute || strings.HasSuffix(route, "/audio-key") {
				r.AddCookie(&http.Cookie{Name: "__Host-karaoke_session", Value: activeRecordingLogin.Token})
				r.AddCookie(&http.Cookie{Name: "__Host-karaoke_csrf", Value: activeRecordingLogin.CSRF})
				r.Header.Set("X-Karaoke-CSRF", activeRecordingLogin.CSRF)
			}
			response, e := masterServer.Client().Do(r)
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			body, e := io.ReadAll(io.LimitReader(response.Body, 64<<10))
			if e != nil {
				t.Fatal(e)
			}
			return response, body
		}
		loginRecording := func(username string) karaoke.Session {
			t.Helper()
			response, _ := publicPost(recordingLoginRoute, gin.H{"username": username, "password": recordingPassword})
			var result karaoke.Session
			for _, cookie := range response.Cookies() {
				if cookie.Name == "__Host-karaoke_session" && cookie.Secure && cookie.HttpOnly && cookie.Path == "/" {
					result.Token = cookie.Value
				}
				if cookie.Name == "__Host-karaoke_csrf" && cookie.Secure && !cookie.HttpOnly && cookie.Path == "/" {
					result.CSRF = cookie.Value
				}
			}
			if response.StatusCode != http.StatusOK || len(result.Token) != 43 || len(result.CSRF) != 32 {
				t.Fatal("recording account login did not issue normal cookies", response.StatusCode)
			}
			if exists, err := realRecordingRedis.Exists(ctx, "karaoke:session:"+karaokeSessionHash(result.Token)).Result(); err != nil || exists != 1 {
				t.Fatal("recording account session not present in Redis", err)
			}
			return result
		}
		if realRecordingRedis != nil {
			recordingLogin = loginRecording("selected-recording")
			otherRecordingLogin = loginRecording("other-recording")
			activeRecordingLogin = recordingLogin
		}
		checkRecordingStatus := func(directAvailable bool) {
			t.Helper()
			status, err := http.NewRequest(http.MethodGet, masterServer.URL+"/api/v1/karaoke/account/status", nil)
			if err != nil {
				t.Fatal(err)
			}
			status.Host = "master.test"
			status.AddCookie(&http.Cookie{Name: "__Host-karaoke_session", Value: activeRecordingLogin.Token})
			response, err := masterServer.Client().Do(status)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var result struct {
				ReadAvailable   bool                                       `json:"recording_read_available"`
				DeleteAvailable bool                                       `json:"recording_delete_available"`
				UploadEnabled   bool                                       `json:"storage_available"`
				Destinations    []business.RecordingAudioDirectDestination `json:"recording_destinations"`
			}
			err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&result)
			if err != nil || response.StatusCode != http.StatusOK || !result.ReadAvailable || !result.DeleteAvailable || result.UploadEnabled != directAvailable {
				t.Fatal("sealed read and upload status disagree", response.StatusCode, result, err)
			}
			if !directAvailable {
				if len(result.Destinations) != 0 {
					t.Fatal("ineligible recording destination was advertised", result.Destinations)
				}
				return
			}
			if len(result.Destinations) != 1 || result.Destinations[0].MemberID != ownerID.ID ||
				result.Destinations[0].Transport != "Direct" || result.Destinations[0].Address != "https://follower.test" || result.Destinations[0].AvailableBytes <= 0 {
				t.Fatal("expected only the writable Direct follower", result.Destinations)
			}
		}
		checkRecordingStatus(directRecording)
		response, raw := publicPost("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(browser.PublicKey().Bytes())})
		var playbackSession mediacrypto.SessionGrant
		if response.StatusCode != http.StatusOK || json.Unmarshal(raw, &playbackSession) != nil || len(response.Cookies()) != 1 {
			t.Fatal("public crypto session", response.StatusCode)
		}
		browserCookie = response.Cookies()[0]
		var countBefore, countAfter int
		if e = masterDB.Database().QueryRowContext(ctx, "SELECT COUNT(*) FROM sealed_tree_encryption_ids").Scan(&countBefore); e != nil {
			t.Fatal(e)
		}
		recordingPlain := bytes.Repeat([]byte("fixture!"), int(mediacrypto.ChunkSize/8)+8)
		recordingResponse, raw := publicPost(recordingPrepareRoute, gin.H{"session_id": playbackSession.SessionID, "plaintext_size": len(recordingPlain)})
		var recordingGrant struct {
			ID         string                  `json:"recording_id"`
			Encryption mediacrypto.Metadata    `json:"encryption"`
			Envelope   mediacrypto.KeyEnvelope `json:"key_envelope"`
			Token      string                  `json:"preparation_token"`
		}
		if recordingResponse.StatusCode != http.StatusOK || json.Unmarshal(raw, &recordingGrant) != nil ||
			!node.ValidIdentifier(recordingGrant.ID) || recordingGrant.Encryption.FileID == recordingGrant.ID || recordingGrant.Encryption.Validate() != nil ||
			recordingGrant.Encryption.PlaintextSize != int64(len(recordingPlain)) || recordingGrant.Envelope.ExpiresAt != playbackSession.ExpiresAt || recordingGrant.Token == "" {
			t.Fatal("durable recording preparation", recordingResponse.StatusCode)
		}
		if e = masterDB.Database().QueryRowContext(ctx, "SELECT COUNT(*) FROM sealed_tree_encryption_ids").Scan(&countAfter); e != nil || countAfter != countBefore+2 {
			t.Fatal("recording descriptor was issued without its durable reservation", countBefore, countAfter, e)
		}
		recordingCipher := selectedRecordingCipher(t, browser, playbackSession, recordingGrant.Encryption, recordingGrant.Envelope, recordingPlain)
		recordingDigest := sha256.Sum256(recordingCipher)
		recordingTicket := store.RecordingAudioTicketRequest{
			RecordingID: recordingGrant.ID, MemberID: masterID.ID, CipherSHA256: hex.EncodeToString(recordingDigest[:]),
			ContentType: "audio/webm", Title: "缁変焦婀佽ぐ鏇㈢叾", SessionID: playbackSession.SessionID,
			Encryption: recordingGrant.Encryption, PreparationToken: recordingGrant.Token,
		}
		if directRecording {
			reservedBytes := func(memberID string) int64 {
				t.Helper()
				var n int64
				if err := masterDB.Database().QueryRowContext(ctx, "SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", memberID).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			masterReserved, ownerReserved := reservedBytes(masterID.ID), reservedBytes(ownerID.ID)
			deniedTicket := func(ticket store.RecordingAudioTicketRequest, label string) {
				t.Helper()
				if denied, raw := publicPost(recordingTicketRoute, ticket); denied.StatusCode != http.StatusInsufficientStorage || bytes.Contains(raw, []byte(`"capability"`)) {
					t.Fatalf("%s received a recording capability: HTTP %d %s", label, denied.StatusCode, raw)
				}
			}
			deniedTicket(recordingTicket, "forged Master destination")
			recordingTicket.MemberID = ownerID.ID
			setWritable := func(writable int) {
				t.Helper()
				if _, err := masterDB.Database().ExecContext(ctx, "UPDATE cluster_storage_members SET writable=? WHERE member_id=?", writable, ownerID.ID); err != nil {
					t.Fatal(err)
				}
			}
			setWritable(0)
			checkRecordingStatus(false)
			deniedTicket(recordingTicket, "non-writable Direct follower")
			setWritable(1)
			relayPolicy, err := routing.ConfirmNativeTransport(ctx, ownerID.ID, "Relay", policy.Revision, store.NodeAudit{})
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.RecordNativeTransportApplication(ctx, rid, relayPolicy.Revision, "Relay"); err != nil {
				t.Fatal(err)
			}
			checkRecordingStatus(false)
			deniedTicket(recordingTicket, "writable Relay follower")
			directPolicy, err := routing.ConfirmNativeTransport(ctx, ownerID.ID, "Direct", relayPolicy.Revision, store.NodeAudit{})
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.RecordNativeDirectApplication(ctx, rid, directPolicy.Revision, "https://follower.test"); err != nil {
				t.Fatal(err)
			}
			checkRecordingStatus(true)
			if user, err := masterDB.Karaoke().UserByID(ctx, recordingUserID); err != nil || user == nil || user.Used != 0 ||
				reservedBytes(masterID.ID) != masterReserved || reservedBytes(ownerID.ID) != ownerReserved {
				t.Fatal("a rejected destination consumed recording or storage quota", err)
			}
			reserved, raw := publicPost(recordingTicketRoute, recordingTicket)
			var reply business.RecordingAudioDirectTicket
			if reserved.StatusCode != http.StatusOK || json.Unmarshal(raw, &reply) != nil || reply.RecordingID != recordingGrant.ID ||
				reply.MemberID != ownerID.ID || reply.Transport != "Direct" || reply.State != "pending" ||
				reply.URL != "https://follower.test/api/v1/node/recording-selected-upload" {
				t.Fatal("writable Direct follower did not receive a recording ticket", reserved.StatusCode, string(raw))
			}
			credential, err := masterVault.Unseal(relation.Credential)
			if err != nil {
				t.Fatal(err)
			}
			claim, err := protocol.VerifySelectedRecordingUpload(credential, reply.Capability, time.Now().Unix())
			if err != nil || claim.Owner != ownerID.ID || claim.Master != masterID.ID || claim.UploadID != recordingGrant.ID || claim.Revision != directPolicy.Revision {
				t.Fatal("recording capability was not bound to the writable Direct owner", err)
			}
			row, err := masterDB.Recordings().Recording(ctx, recordingGrant.ID)
			if err != nil || row == nil || row.MemberID != ownerID.ID || row.State != "pending" ||
				reservedBytes(masterID.ID) != masterReserved || reservedBytes(ownerID.ID) != ownerReserved+recordingTicket.Encryption.CiphertextSize {
				t.Fatal("recording reservation was not isolated to the Direct owner", err)
			}
			return
		}
		wrongOwner := recordingTicket
		wrongOwner.MemberID = ownerID.ID
		if denied, _ := publicPost(recordingTicketRoute, wrongOwner); denied.StatusCode != http.StatusConflict {
			t.Fatal("unavailable recording owner was reserved", denied.StatusCode)
		}
		for i := 0; i < 2; i++ {
			reserved, raw := publicPost(recordingTicketRoute, recordingTicket)
			var reply struct {
				ID    string `json:"recording_id"`
				Owner string `json:"storage_member_id"`
				State string `json:"state"`
			}
			if reserved.StatusCode != http.StatusOK || json.Unmarshal(raw, &reply) != nil || reply.ID != recordingGrant.ID || reply.Owner != masterID.ID || reply.State != "pending" {
				t.Fatal("durable recording ticket", reserved.StatusCode, string(raw))
			}
		}
		recordingUser, e := masterDB.Karaoke().UserByID(ctx, recordingUserID)
		if e != nil || recordingUser == nil || recordingUser.Used != recordingTicket.Encryption.CiphertextSize {
			t.Fatal("recording retries must reserve user quota once", e)
		}
		recordingRow, e := masterDB.Recordings().Recording(ctx, recordingGrant.ID)
		if e != nil || recordingRow == nil || recordingRow.State != "pending" || recordingRow.MemberID != masterID.ID {
			t.Fatal("recording ticket lacks the durable pending row", e)
		}
		uploadRecording := func(payload []byte, csrf bool) int {
			t.Helper()
			url := masterServer.URL + "/api/v1/karaoke/account/recordings/" + recordingGrant.ID + "/content"
			r, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "master.test"
			r.Header.Set("Origin", "https://master.test")
			r.Header.Set("Content-Type", "application/octet-stream")
			r.Header.Set("X-Fc-Recording-Session", playbackSession.SessionID)
			r.AddCookie(browserCookie)
			r.AddCookie(&http.Cookie{Name: "__Host-karaoke_session", Value: recordingLogin.Token})
			r.AddCookie(&http.Cookie{Name: "__Host-karaoke_csrf", Value: recordingLogin.CSRF})
			if csrf {
				r.Header.Set("X-Karaoke-CSRF", recordingLogin.CSRF)
			}
			response, err := masterServer.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			return response.StatusCode
		}
		if status := uploadRecording(recordingCipher, false); status != http.StatusForbidden {
			t.Fatal("recording ciphertext accepted without CSRF", status)
		}
		if status := uploadRecording(recordingCipher[:len(recordingCipher)-1], true); status != http.StatusConflict {
			t.Fatal("invalid recording length accepted", status)
		}
		if status := uploadRecording(recordingCipher, true); status != http.StatusOK {
			t.Fatal("recording ciphertext upload", status)
		}
		blob, e := business.FixtureRecordingAudioBlob(ctx, repo, capKey, recordingGrant.ID)
		if e != nil {
			t.Fatal(e)
		}
		blobPath, e := sealedtree.BlobPath(blob)
		if e != nil {
			t.Fatal(e)
		}
		physical, e := masterRoot.ReadFile(blobPath)
		if e != nil || !bytes.Equal(physical, recordingCipher) || bytes.Contains(physical, recordingPlain) {
			t.Fatal("recording Owner bytes do not match browser ciphertext", e)
		}
		recordingRow, e = masterDB.Recordings().Recording(ctx, recordingGrant.ID)
		if e != nil || recordingRow == nil || recordingRow.State != "ready" {
			t.Fatal("recording Owner receipt did not settle", e)
		}
		recordingBase := "/api/v1/karaoke/account/recordings/" + recordingGrant.ID
		audioKeyRequest := gin.H{"session_id": playbackSession.SessionID}
		activeRecordingLogin = otherRecordingLogin
		if denied, raw := publicPost(recordingBase+"/audio-key", audioKeyRequest); denied.StatusCode != http.StatusForbidden || bytes.Contains(raw, []byte("key_envelope")) {
			t.Fatal("another account received the recording key", denied.StatusCode)
		}
		activeRecordingLogin = recordingLogin
		keyHTTP, keyBody := publicPost(recordingBase+"/audio-key", audioKeyRequest)
		var audioGrant struct {
			ID         string                  `json:"recording_id"`
			Revision   string                  `json:"source_revision"`
			Title      string                  `json:"title"`
			Type       string                  `json:"content_type"`
			Filename   string                  `json:"filename"`
			Encryption mediacrypto.Metadata    `json:"encryption"`
			Envelope   mediacrypto.KeyEnvelope `json:"key_envelope"`
		}
		if keyHTTP.StatusCode != http.StatusOK || json.Unmarshal(keyBody, &audioGrant) != nil || audioGrant.ID != recordingGrant.ID ||
			audioGrant.Revision != recordingTicket.CipherSHA256 || audioGrant.Encryption != recordingGrant.Encryption || audioGrant.Envelope.WrappedKey == "" ||
			audioGrant.Type != "audio/webm" || audioGrant.Title != recordingTicket.Title || audioGrant.Filename != "recording-"+recordingGrant.ID+".webm" || bytes.Contains(keyBody, []byte(blob)) {
			t.Fatal("recording key failed to bind the authenticated descriptor", keyHTTP.StatusCode)
		}
		readAudio := func(account, rangeHeader, origin string) (*http.Response, []byte) {
			t.Helper()
			r, err := http.NewRequest(http.MethodGet, masterServer.URL+recordingBase+"/audio-bytes", nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "master.test"
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("X-Fc-Recording-Session", playbackSession.SessionID)
			if rangeHeader != "" {
				r.Header.Set("Range", rangeHeader)
			}
			r.AddCookie(browserCookie)
			r.AddCookie(&http.Cookie{Name: "__Host-karaoke_session", Value: account})
			response, err := masterServer.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, mediacrypto.ChunkSize+17))
			if err != nil {
				t.Fatal(err)
			}
			return response, body
		}
		stride := mediacrypto.ChunkSize + 16
		firstRange := fmt.Sprintf("bytes=0-%d", stride-1)
		if r, _ := readAudio(otherRecordingLogin.Token, firstRange, ""); r.StatusCode != http.StatusForbidden {
			t.Fatal("another account read recording ciphertext", r.StatusCode)
		}
		if r, _ := readAudio(recordingLogin.Token, firstRange, "https://other.test"); r.StatusCode != http.StatusForbidden {
			t.Fatal("cross-origin recording read", r.StatusCode)
		}
		for _, requested := range []string{"", "bytes=0-1", "bytes=0-1,3-4"} {
			if r, _ := readAudio(recordingLogin.Token, requested, ""); r.StatusCode != http.StatusRequestedRangeNotSatisfiable {
				t.Fatal("recording accepted an unbounded or incomplete GCM range", r.StatusCode)
			}
		}
		decoder := selectedRecordingAEAD(t, browser, playbackSession, audioGrant.Encryption, audioGrant.Envelope)
		for index, requested := range []string{firstRange, fmt.Sprintf("bytes=%d-%d", stride, len(recordingCipher)-1)} {
			start := int64(index) * stride
			end := min(start+stride, int64(len(recordingCipher))) - 1
			r, data := readAudio(recordingLogin.Token, requested, "")
			if r.StatusCode != http.StatusPartialContent || r.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", start, end, len(recordingCipher)) ||
				r.Header.Get("ETag") != `"`+audioGrant.Revision+`"` || !strings.Contains(r.Header.Get("Cache-Control"), "no-store") || !bytes.Equal(data, recordingCipher[start:end+1]) {
				t.Fatal("recording wire range disagrees with the stored ciphertext", r.StatusCode, index)
			}
			nonce, err := audioGrant.Encryption.ChunkNonce(uint32(index))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decoder.Open(nil, nonce, data, audioGrant.Encryption.ChunkAAD(uint32(index)))
			plainStart := int64(index) * mediacrypto.ChunkSize
			if err != nil || !bytes.Equal(decoded, recordingPlain[plainStart:min(plainStart+mediacrypto.ChunkSize, int64(len(recordingPlain)))]) {
				t.Fatal("issued key did not authenticate the ciphertext range", err, index)
			}
		}
		if realRecordingRedis != nil {
			if r, _ := publicPost(recordingLogoutRoute, gin.H{}); r.StatusCode != http.StatusOK {
				t.Fatal("recording account logout failed", r.StatusCode)
			}
			oldToken := recordingLogin.Token
			if exists, err := realRecordingRedis.Exists(ctx, "karaoke:session:"+karaokeSessionHash(oldToken)).Result(); err != nil || exists != 0 {
				t.Fatal("logout did not revoke the Redis session", err)
			}
			if r, raw := publicPost(recordingBase+"/audio-key", audioKeyRequest); r.StatusCode != http.StatusUnauthorized || bytes.Contains(raw, []byte("key_envelope")) {
				t.Fatal("revoked recording session still issued a file key", r.StatusCode)
			}
			if r, _ := readAudio(oldToken, firstRange, ""); r.StatusCode != http.StatusUnauthorized {
				t.Fatal("revoked recording session still served ciphertext", r.StatusCode)
			}
			recordingLogin = loginRecording("selected-recording")
			if recordingLogin.Token == oldToken {
				t.Fatal("normal login reused a revoked cookie")
			}
			if r, raw := readAudio(recordingLogin.Token, firstRange, ""); r.StatusCode != http.StatusPartialContent || !bytes.Equal(raw, recordingCipher[:stride]) {
				t.Fatal("new valid account session could not read the retained recording", r.StatusCode)
			}
			remove := func(login karaoke.Session, origin, session string, sendCSRF bool) int {
				t.Helper()
				req, e := http.NewRequest(http.MethodDelete, masterServer.URL+recordingBase, nil)
				if e != nil {
					t.Fatal(e)
				}
				req.Host = "master.test"
				req.Header.Set("Origin", origin)
				if session != "" {
					req.Header.Set("X-Fc-Recording-Session", session)
				}
				req.AddCookie(browserCookie)
				req.AddCookie(&http.Cookie{Name: "__Host-karaoke_session", Value: login.Token})
				req.AddCookie(&http.Cookie{Name: "__Host-karaoke_csrf", Value: login.CSRF})
				if sendCSRF {
					req.Header.Set("X-Karaoke-CSRF", login.CSRF)
				}
				r, e := masterServer.Client().Do(req)
				if e != nil {
					t.Fatal(e)
				}
				defer r.Body.Close()
				_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
				return r.StatusCode
			}
			for _, tc := range []struct {
				name, origin, session string
				login                 karaoke.Session
				csrf                  bool
			}{
				{"missing CSRF", "https://master.test", playbackSession.SessionID, recordingLogin, false},
				{"different origin", "https://other.test", playbackSession.SessionID, recordingLogin, true},
				{"missing crypto session", "https://master.test", "", recordingLogin, true},
				{"different account", "https://master.test", playbackSession.SessionID, otherRecordingLogin, true},
			} {
				if code := remove(tc.login, tc.origin, tc.session, tc.csrf); code < 400 || code >= 500 {
					t.Fatal("recording deletion authentication", tc.name, code)
				}
			}
			if r, _ := readAudio(recordingLogin.Token, firstRange, ""); r.StatusCode != http.StatusPartialContent {
				t.Fatal("denied deletes altered recording", r.StatusCode)
			}
			for range 2 {
				if code := remove(recordingLogin, "https://master.test", playbackSession.SessionID, true); code != http.StatusOK {
					t.Fatal("authenticated recording deletion or replay failed", code)
				}
			}
			refunded, e := masterDB.Karaoke().UserByID(ctx, recordingUserID)
			if e != nil || refunded == nil || refunded.Used != 0 {
				t.Fatal("authenticated recording deletion did not return quota exactly once", e)
			}
			if r, _ := readAudio(recordingLogin.Token, firstRange, ""); r.StatusCode != http.StatusForbidden {
				t.Fatal("deleted recording retained a readable ciphertext route", r.StatusCode)
			}
		}
		keyRequest := cryptoKeyBody{SessionID: playbackSession.SessionID, FilePath: linkedTrack.Path, ResourceID: trackID, ObjectID: strings.Repeat("f", 64)}
		if denied, raw := publicPost("/api/v1/media/crypto/key", keyRequest); denied.StatusCode != http.StatusServiceUnavailable || bytes.Contains(raw, []byte("key_envelope")) {
			t.Fatal("wrong tree object ID received a key", denied.StatusCode)
		}
		grant := func(object sealedtree.VisibleObject, track string, route string) string {
			t.Helper()
			r, raw := publicPost("/api/v1/media/crypto/key", cryptoKeyBody{SessionID: playbackSession.SessionID, FilePath: object.Path, ResourceID: object.Entry.ObjectID, ObjectID: object.Placement.NativeObjectID, TrackResourceID: track})
			var plan struct {
				URL       string            `json:"source_url"`
				Headers   map[string]string `json:"source_headers"`
				Transport string            `json:"source_transport"`
				Envelope  json.RawMessage   `json:"key_envelope"`
			}
			if r.StatusCode != http.StatusOK || json.Unmarshal(raw, &plan) != nil || plan.Transport != "Local" || plan.URL != "https://master.test"+route || len(plan.Envelope) == 0 || plan.Headers["X-Media-Capability"] == "" {
				t.Fatal("public crypto key", r.StatusCode, string(raw))
			}
			return plan.Headers["X-Media-Capability"]
		}
		readRange := func(route, token string, expected []byte) {
			t.Helper()
			r, e := http.NewRequest("GET", masterServer.URL+route, nil)
			if e != nil {
				t.Fatal(e)
			}
			r.Host = "master.test"
			r.Header.Set("Origin", "https://master.test")
			r.Header.Set("X-Media-Capability", token)
			r.Header.Set("Range", "bytes=1-4")
			response, e := masterServer.Client().Do(r)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := io.ReadAll(response.Body)
			response.Body.Close()
			if e != nil || response.StatusCode != http.StatusPartialContent || !bytes.Equal(raw, expected[1:5]) {
				t.Fatal("new-tree HTTP range", response.StatusCode, e)
			}
		}
		audioRoute := "/api/v1/media/master-local/" + linkedTrack.Placement.ReadAlias
		lyricRoute := "/api/v1/media/master-local-lyric/" + linked.Placement.ReadAlias
		readRange(audioRoute, grant(linkedTrack, "", audioRoute), ciphertext)
		readRange(lyricRoute, grant(linked, trackID, lyricRoute), lyricBytes)
	}
	// Cancel a second reservation before any Owner bytes exist. Master must
	// persist cancellation before requesting the Owner tombstone, and the
	// original capability must not be usable after the tombstone is installed.
	prep2 := requestAdmin("POST", base+"/crypto/prepare", map[string]any{"session_id": cryptoSession.SessionID, "plaintext_size": len(plain)})
	var prepared2 struct {
		Encryption mediacrypto.Metadata `json:"encryption"`
		Token      string               `json:"preparation_token"`
	}
	if prep2.Code != 200 || json.Unmarshal(prep2.Body.Bytes(), &prepared2) != nil || prepared2.Token == "" {
		t.Fatal("second crypto prepare", prep2.Code)
	}
	if _, err = rand.Read(idBytes); err != nil {
		t.Fatal(err)
	}
	cancelID := hex.EncodeToString(idBytes)
	cancelRequest := business.SelectedPrepareRequest{UploadID: cancelID, ParentPath: request.ParentPath, Filename: "cancelled.mp3", MemberID: selectedMember, CipherSHA256: request.CipherSHA256, Encryption: prepared2.Encryption, Preparation: prepared2.Token}
	secondAdmission := requestAdmin("POST", base+"/upload/selected/prepare", cancelRequest)
	var secondTicket business.SelectedDirectTicket
	if secondAdmission.Code != 200 || json.Unmarshal(secondAdmission.Body.Bytes(), &secondTicket) != nil || (!relay && !local && secondTicket.Capability == "") || ((relay || local) && secondTicket.Capability != "") {
		t.Fatal("second admission", secondAdmission.Code)
	}
	cancelResponse := requestAdmin("POST", base+"/upload/selected/"+cancelID+"/cancel", nil)
	var cleanupTicket business.SelectedDirectTicket
	if cancelResponse.Code != 200 || json.Unmarshal(cancelResponse.Body.Bytes(), &cleanupTicket) != nil || (!relay && !local && cleanupTicket.Capability == "") || ((relay || local) && cleanupTicket.Capability != "") {
		t.Fatal("begin cancel", cancelResponse.Code)
	}
	if relay || local {
		uploadID = cancelID
	}
	cleaned := sendOwner("POST", "/api/v1/node/selected-upload/cleanup", cleanupTicket.Capability, nil)
	cleanupRaw, err := io.ReadAll(cleaned.Body)
	cleaned.Body.Close()
	if err != nil || cleaned.StatusCode != 200 {
		t.Fatal("Owner cleanup", cleaned.StatusCode, err)
	}
	var cleanupReceipt selectedSignedReceipt
	if err = json.Unmarshal(cleanupRaw, &cleanupReceipt); err != nil {
		t.Fatal(err)
	}
	finishCancel := requestAdmin("POST", base+"/upload/selected/"+cancelID+"/cancel/finish", cleanupReceipt)
	if finishCancel.Code != 200 {
		t.Fatal("finish cancel", finishCancel.Code)
	}
	cancelStatus := requestAdmin("GET", base+"/upload/selected/"+cancelID+"/status", nil)
	if cancelStatus.Code != 200 || !strings.Contains(cancelStatus.Body.String(), `"cancelled"`) {
		t.Fatal("cancel status", cancelStatus.Code)
	}
	replay := sendOwner("PUT", "/api/v1/node/selected-upload", secondTicket.Capability, ciphertext)
	replay.Body.Close()
	if replay.StatusCode == 200 {
		t.Fatal("cancelled operation accepted old upload capability")
	}
}

// selectedE2ERelaySender substitutes the transport only: it uses the real
// Owner TLS router and exact Node request authentication; startup readiness is
// still synthetic and this helper is never registered in production.
type selectedE2ERelaySender struct {
	server                   *httptest.Server
	relationship, credential string
}

func (f *selectedE2ERelaySender) call(ctx context.Context, relationship, token, method, route string, body io.Reader, size int64) (map[string]any, error) {
	if relationship != f.relationship {
		return nil, store.ErrNodeState
	}
	headers, err := protocol.AuthHeaders(f.credential, relationship, method, route, []byte(token), time.Now().Unix())
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, f.server.URL+route, body)
	if err != nil {
		return nil, err
	}
	if size > 0 {
		req.ContentLength = size
	}
	req.Header.Set("X-Fc-Selected-Upload", token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := f.server.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, store.ErrNodeState
	}
	var result map[string]any
	if err = json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}
func (f *selectedE2ERelaySender) ForwardSelectedRelay(ctx context.Context, rel, token string, r io.Reader, size int64) (map[string]any, error) {
	return f.call(ctx, rel, token, http.MethodPut, "/internal/v1/selected-upload/relay", r, size)
}
func (f *selectedE2ERelaySender) RecoverSelectedRelay(ctx context.Context, rel, token string) (map[string]any, error) {
	return f.call(ctx, rel, token, http.MethodPost, "/internal/v1/selected-upload/relay/recover", nil, 0)
}
func (f *selectedE2ERelaySender) CleanupSelectedRelay(ctx context.Context, rel, token string) (map[string]any, error) {
	return f.call(ctx, rel, token, http.MethodPost, "/internal/v1/selected-upload/relay/cleanup", nil, 0)
}

func selectedRecordingCipher(t *testing.T, browser *ecdh.PrivateKey, session mediacrypto.SessionGrant, metadata mediacrypto.Metadata, envelope mediacrypto.KeyEnvelope, plain []byte) []byte {
	t.Helper()
	aead := selectedRecordingAEAD(t, browser, session, metadata, envelope)
	var ciphertext []byte
	for index, start := uint32(0), int64(0); start < int64(len(plain)); index, start = index+1, start+mediacrypto.ChunkSize {
		nonce, err := metadata.ChunkNonce(index)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext = aead.Seal(ciphertext, nonce, plain[start:min(start+mediacrypto.ChunkSize, int64(len(plain)))], metadata.ChunkAAD(index))
	}
	return ciphertext
}

func selectedRecordingAEAD(t *testing.T, browser *ecdh.PrivateKey, session mediacrypto.SessionGrant, metadata mediacrypto.Metadata, envelope mediacrypto.KeyEnvelope) cipher.AEAD {
	t.Helper()
	decode := func(encoded string) []byte {
		v, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	server, err := ecdh.P256().NewPublicKey(decode(session.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := browser.ECDH(server)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(shared)
	key := make([]byte, 32)
	defer clear(key)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, decode(session.Salt), []byte("frontiercloud:browser-wrap:v1:"+session.SessionID)), key); err != nil {
		t.Fatal(err)
	}
	newAEAD := func(k []byte) cipher.AEAD {
		block, err := aes.NewCipher(k)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return aead
	}
	fileKey, err := newAEAD(key).Open(nil, decode(envelope.IV), decode(envelope.WrappedKey), []byte("frontiercloud:key-envelope:v1:"+session.SessionID+":"+metadata.FileID))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fileKey)
	return newAEAD(fileKey)
}
