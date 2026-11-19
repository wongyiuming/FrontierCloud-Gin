//go:build linux

package preprodimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	storepkg "github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	nodevault "github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestLegacyCoordinatorClosedBeforeVaultOrNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	projection, sourcePremaster, _, _ := fixture(t)
	media := projection.Media[0]
	complete := completeSourceFixture(projection)
	strongETag := "\"" + media.SHA256 + "\""
	for i := range complete.Facts.Placements {
		if complete.Facts.Placements[i].MediaID == media.MediaID {
			complete.Facts.Placements[i].ETag = strongETag
		}
	}
	generation, err := completeSnapshotDigest(complete)
	if err != nil {
		t.Fatal(err)
	}
	source, err := mediacrypto.New(sourcePremaster)
	if err != nil {
		t.Fatal(err)
	}
	var sourceRequests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceRequests.Add(1)
		if r.Header.Get("Cookie") != "admin=fixture" || r.Header.Get("X-CSRF-Token") != "fixture" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/api/v1/media/admin/crypto/session" {
			var body struct {
				PublicKey string `json:"public_key"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			grant, e := source.NewSession("admin:fixture", body.PublicKey)
			if e != nil {
				w.WriteHeader(401)
				return
			}
			_ = json.NewEncoder(w).Encode(grant)
			return
		}
		if r.URL.Path == "/api/v1/media/admin/crypto/key" {
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["file_path"] != media.Path || body["resource_id"] != media.MediaID || body["object_id"] != media.MediaID {
				w.WriteHeader(404)
				return
			}
			envelope, e := source.Wrap("admin:fixture", body["session_id"], *media.Encryption)
			if e != nil {
				w.WriteHeader(401)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"encryption": media.Encryption, "key_envelope": envelope})
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	tlsHash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	collectorPub, collector, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	masterSeed := bytes.Repeat([]byte{71}, 32)
	masterKey := ed25519.NewKeyFromSeed(masterSeed)
	receiver, err := receiverFromMasterSeed(masterSeed)
	if err != nil {
		t.Fatal(err)
	}
	app, err := sqlitestore.Open(filepath.Join(t.TempDir(), "app.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err = app.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	nodeDir := t.TempDir()
	if err = os.Chmod(nodeDir, 0700); err != nil {
		t.Fatal(err)
	}
	nv, err := nodevault.Open(nodeDir)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := nv.Seal(protocol.Encode(masterSeed))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err = app.Nodes().InitializeIdentity(ctx, storepkg.NodeIdentity{ID: projection.Mappings[0].TargetID, Role: "Standalone", PrivateKey: sealed, CreatedAt: now.Unix()}); err != nil {
		t.Fatal(err)
	}
	if _, err = app.Nodes().PromoteIdentity(ctx, storepkg.NodePromotion{Role: "Master", Endpoint: "https://target.test", Allocation: 5 * storepkg.GiB, PhysicalFree: 10 * storepkg.GiB}, storepkg.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = app.Nodes().(storepkg.PublicRoutingRepository).ConfigurePublicOrigin("https://target.test"); err != nil {
		t.Fatal(err)
	}
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "ssh-collector-v1", SourceSSHHostKeySHA256: strings.Repeat("9", 64), SourceTLSOrigin: server.URL, SourceTLSSPKISHA256: hex.EncodeToString(tlsHash[:]), SourceNode: projection.Mappings[0].SourceID, SourceKeyID: projection.PremasterKeyID, SourcePublic: collectorPub, TargetNode: projection.Mappings[0].TargetID, TargetMasterPublic: masterKey.Public().(ed25519.PublicKey), TargetX25519: receiver.PublicKey().Bytes(), Generation: generation}
	pin.ImportScope = syntheticImportScope(projection)
	for _, mapping := range projection.Mappings {
		pin.SourceOwners = append(pin.SourceOwners, sourceOwnerPin{NodeID: mapping.SourceID, SSHHostKeySHA256: pin.SourceSSHHostKeySHA256})
	}
	if err = provisionSourceAuthority(ctx, app, nv, pin); err != nil {
		t.Fatal(err)
	}
	treeKey, err := sealedtree.New(bytes.Repeat([]byte{41}, 32), bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	treeDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tree.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer treeDB.Close()
	rootID := strings.Repeat("f", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, treeDB, treeKey, rootID)
	if err != nil {
		t.Fatal(err)
	}
	treeDir := t.TempDir()
	if err = os.Chmod(treeDir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(treeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = sealedtree.InitializeFence(ctx, tree, root, treeDir); err != nil {
		t.Fatal(err)
	}
	music := sealedtree.Entry{ParentID: rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	if err = tree.CreateDirectoryWithFacts(ctx, music, sealedtree.Facts{ObjectID: music.ObjectID}); err != nil {
		t.Fatal(err)
	}
	album := sealedtree.Entry{ParentID: music.ObjectID, ObjectID: projection.Directories[0].ID, Kind: "directory", Name: "album"}
	if err = tree.CreateDirectoryWithFacts(ctx, album, sealedtree.Facts{ObjectID: album.ObjectID}); err != nil {
		t.Fatal(err)
	}
	s := syntheticSourceForComplete(complete)
	s.Version, s.AuthorityKind, s.SourceSSHHostKeySHA256, s.SourceNode, s.SourcePublic = 1, pin.AuthorityKind, pin.SourceSSHHostKeySHA256, pin.SourceNode, protocol.Encode(collectorPub)
	s.TargetNode, s.TargetReceiver, s.Challenge, s.IssuedUnix, s.ExpiresUnix = pin.TargetNode, pin.TargetX25519, strings.Repeat("8", 64), now.Unix(), now.Add(4*time.Minute).Unix()
	raw, _ := json.Marshal(s)
	sum := sha256.Sum256(raw)
	payload := map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hex.EncodeToString(sum[:]), "source_node": s.SourceNode, "target_node": s.TargetNode, "challenge": s.Challenge}
	signature, err := protocol.Sign(protocol.Encode(collector.Seed()), payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshotcrypt.Seal(storepkg.SignedMediaSourceSnapshot{Snapshot: s, Signature: signature}, receiver.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := sourceLyricResolution(complete, media, hex.EncodeToString(sum[:]), generation)
	if err != nil {
		t.Fatal(err)
	}
	pendingFacts, err := sourceObjectTreeFacts(complete, media, resolution)
	if err != nil {
		t.Fatal(err)
	}
	placement := sealedtree.Placement{ObjectID: media.MediaID, NativeObjectID: media.ObjectID, OwnerID: projection.Mappings[0].TargetID, Bytes: media.Size, SHA256: media.SHA256, ETag: strongETag, State: "active", CreatedAt: 1, UpdatedAt: 2, Encryption: media.Encryption}
	pending, err := tree.PrepareFileWithFreshLocators(ctx, sealedtree.Entry{ParentID: album.ObjectID, ObjectID: media.MediaID, Kind: media.Kind, Name: "song.mp3"}, placement, pendingFacts)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	vaultDir := t.TempDir()
	if err = os.Chmod(vaultDir, 0700); err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(vaultDir, "legacy.sqlite")
	vaultDB, err := sql.Open("sqlite", vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	defer vaultDB.Close()
	vaultDB.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "CREATE TABLE preprod_source_evidence(evidence_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,challenge_tag TEXT NOT NULL UNIQUE)", "CREATE TABLE legacy_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)", "CREATE TABLE legacy_key_requests(request_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,consumed INTEGER NOT NULL CHECK(consumed IN(0,1)))", "CREATE TABLE legacy_key_vault(object_tag TEXT PRIMARY KEY,file_tag TEXT NOT NULL UNIQUE,challenge_tag TEXT NOT NULL UNIQUE,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)"} {
		if _, err = vaultDB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Chmod(vaultPath, 0600); err != nil {
		t.Fatal(err)
	}
	vaultRoot := bytes.Repeat([]byte{8}, 32)
	if _, err = vaultDB.Exec("INSERT INTO legacy_key_vault_meta VALUES(1,?)", legacyVaultTag(vaultRoot, "verifier", pin.TargetNode)); err != nil {
		t.Fatal(err)
	}
	key := keyScope{Version: 1, SourceNode: pin.SourceNode, SourceKeyID: pin.SourceKeyID, TargetNode: pin.TargetNode, Snapshot: generation, MediaID: media.MediaID, SourceObjectID: media.ObjectID, TargetOwnerID: placement.OwnerID, TargetBlobID: pending.BlobID, TargetReadAlias: pending.ReadAlias, ContentSHA256: media.SHA256, StoredBytes: media.Size, Challenge: strings.Repeat("7", 64), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(3 * time.Minute).Unix(), Descriptor: *media.Encryption}
	if _, err = observeLegacyObject(ctx, app, nv, tree, lease, vaultDB, vaultRoot, envelope, nil, s.Challenge, complete, key, server.Client(), "admin=fixture", "fixture"); err == nil {
		t.Fatal("unordered legacy coordinator must remain disabled")
	}
	var count int
	if err = vaultDB.QueryRow("SELECT COUNT(*) FROM legacy_key_vault").Scan(&count); err != nil || count != 0 {
		t.Fatal("disabled coordinator wrote a key", err)
	}
	if err = vaultDB.QueryRow("SELECT COUNT(*) FROM preprod_source_evidence").Scan(&count); err != nil || count != 0 {
		t.Fatal("disabled coordinator wrote source evidence", err)
	}
	beforeRetry := sourceRequests.Load()
	if _, err = observeLegacyObject(ctx, app, nv, tree, lease, vaultDB, vaultRoot, envelope, nil, s.Challenge, complete, key, server.Client(), "admin=fixture", "fixture"); err == nil {
		t.Fatal("unordered legacy coordinator must remain disabled")
	}
	if sourceRequests.Load() != beforeRetry {
		t.Fatal("disabled coordinator contacted source")
	}
}
