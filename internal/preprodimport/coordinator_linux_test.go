//go:build linux

package preprodimport

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	storepkg "github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	nodevault "github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestSyntheticCoordinatorReconcilesPendingUnderTreeLease(t *testing.T) {
	ctx := context.Background()
	s, sourcePremaster, _, _ := fixture(t)
	plainMedia := Media{MediaID: strings.Repeat("3", 64), ObjectID: strings.Repeat("5", 64), SourceID: s.Mappings[0].SourceID, Path: "music/album/plain.mp3", Kind: "audio", Size: 5, SHA256: digest([]byte("plain"))}
	s.Media = append(s.Media, plainMedia)
	complete := completeSnapshot{Projection: s, Facts: syntheticCompleteFacts(s)}
	m := s.Media[0]
	master := bytes.Repeat([]byte{41}, 32)
	salt := bytes.Repeat([]byte{42}, 32)
	tree, err := sealedtree.New(master, salt)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tree.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rootID := strings.Repeat("f", 64)
	store, err := sealedtree.InitializeSQLite(ctx, db, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = sealedtree.InitializeFence(ctx, store, root, dir); err != nil {
		t.Fatal(err)
	}
	music := sealedtree.Entry{ParentID: rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	if err = store.CreateDirectoryWithFacts(ctx, music, sealedtree.Facts{ObjectID: music.ObjectID}); err != nil {
		t.Fatal(err)
	}
	album := sealedtree.Entry{ParentID: music.ObjectID, ObjectID: s.Directories[0].ID, Kind: "directory", Name: "album"}
	if err = store.CreateDirectoryWithFacts(ctx, album, sealedtree.Facts{ObjectID: album.ObjectID, Visibility: &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01T00:00:00Z"}}); err != nil {
		t.Fatal(err)
	}
	link := complete.Facts.LyricLinks[0]
	facts := sealedtree.Facts{ObjectID: m.MediaID, Lyric: &sealedtree.LyricFact{LyricID: link.LyricID, LegacyMediaPath: link.MediaPath, LegacyLyricPath: link.LyricPath, CreatedAt: link.CreatedAt, UpdatedAt: link.UpdatedAt}}
	placement := sealedtree.Placement{ObjectID: m.MediaID, NativeObjectID: m.ObjectID, OwnerID: s.Mappings[0].TargetID, Bytes: m.Size, SHA256: m.SHA256, ETag: "opaque", State: "active", CreatedAt: 1, UpdatedAt: 2, Encryption: m.Encryption}
	prepared, err := store.PrepareFileWithFreshLocators(ctx, sealedtree.Entry{ParentID: album.ObjectID, ObjectID: m.MediaID, Kind: m.Kind, Name: "song.mp3"}, placement, facts)
	if err != nil {
		t.Fatal(err)
	}
	plainPlacement := sealedtree.Placement{ObjectID: plainMedia.MediaID, NativeObjectID: plainMedia.ObjectID, OwnerID: s.Mappings[0].TargetID, Bytes: plainMedia.Size, SHA256: plainMedia.SHA256, ETag: "opaque", State: "active", CreatedAt: 1, UpdatedAt: 2}
	plainPrepared, err := store.PrepareFileWithFreshLocators(ctx, sealedtree.Entry{ParentID: album.ObjectID, ObjectID: plainMedia.MediaID, Kind: plainMedia.Kind, Name: "plain.mp3"}, plainPlacement, sealedtree.Facts{ObjectID: plainMedia.MediaID})
	if err != nil {
		t.Fatal(err)
	}
	locators := map[string]pendingLocatorBinding{}
	stages := map[string]string{}
	i := 0
	for _, item := range s.Media {
		i++
		locators[item.MediaID] = pendingLocatorBinding{BlobID: fmt.Sprintf("%064x", 2000+i), ReadAlias: fmt.Sprintf("%064x", 3000+i)}
		stages[item.MediaID] = fmt.Sprintf("%064x", 1000+i)
	}
	for _, item := range s.Lyrics {
		i++
		locators[item.ID] = pendingLocatorBinding{BlobID: fmt.Sprintf("%064x", 2000+i), ReadAlias: fmt.Sprintf("%064x", 3000+i)}
		stages[item.ID] = fmt.Sprintf("%064x", 1000+i)
	}
	locators[m.MediaID] = pendingLocatorBinding{BlobID: prepared.BlobID, ReadAlias: prepared.ReadAlias}
	locators[plainMedia.MediaID] = pendingLocatorBinding{BlobID: plainPrepared.BlobID, ReadAlias: plainPrepared.ReadAlias}
	now := time.Now().UTC().Truncate(time.Second)
	masterSeed := bytes.Repeat([]byte{71}, 32)
	target, err := receiverFromMasterSeed(masterSeed)
	if err != nil {
		t.Fatal(err)
	}
	sourcePub, sourceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := completeSnapshotDigest(complete)
	if err != nil {
		t.Fatal(err)
	}
	entry := snapshotGrantEntry{MediaID: m.MediaID, SourceObjectID: m.ObjectID, TargetOwnerID: s.Mappings[0].TargetID, TargetBlobID: prepared.BlobID, TargetReadAlias: prepared.ReadAlias, ContentSHA256: m.SHA256, StoredBytes: m.Size, Challenge: strings.Repeat("2", 64), Descriptor: *m.Encryption}
	body := snapshotGrantBody{Version: 1, SourceNode: s.Mappings[0].SourceID, SourceKeyID: s.PremasterKeyID, TargetNode: s.Mappings[0].TargetID, TargetPublic: target.PublicKey().Bytes(), Generation: generation, BatchCount: 1, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(3 * time.Minute).Unix(), Entries: []snapshotGrantEntry{entry}}
	batch, err := signApprovedSnapshot(body, sourceKey, now)
	if err != nil {
		t.Fatal(err)
	}
	batchDigest, err := snapshotGrantDigest(body, now)
	if err != nil {
		t.Fatal(err)
	}
	pb := snapshotPlanBody{Version: 1, SourceNode: body.SourceNode, SourceKeyID: body.SourceKeyID, TargetNode: body.TargetNode, TargetPublic: body.TargetPublic, Generation: generation, IssuedUnix: body.IssuedUnix, ExpiresUnix: body.ExpiresUnix, Batches: []snapshotPlanBatch{{Digest: hex.EncodeToString(batchDigest), Count: 1}}}
	plan, err := signApprovedSnapshotPlan(pb, sourceKey, now)
	if err != nil {
		t.Fatal(err)
	}
	pd, err := snapshotPlanDigest(pb, now)
	if err != nil {
		t.Fatal(err)
	}
	trust := snapshotPlanTrust{SourceNode: pb.SourceNode, SourceKeyID: pb.SourceKeyID, SourcePublic: sourcePub, TargetNode: pb.TargetNode, TargetPublic: pb.TargetPublic, Generation: generation, PlanDigest: hex.EncodeToString(pd)}
	challenges := map[string]string{"master": strings.Repeat("7", 64), "direct": strings.Repeat("8", 64), "relay": strings.Repeat("9", 64)}
	requests, err := buildCompleteStageReceiptRequests(complete, trust, plan, []signedSnapshotGrant{batch}, locators, stages, challenges, now)
	if err != nil {
		t.Fatal(err)
	}
	receipts := map[string]signedStageReceipt{}
	pins := map[string]ed25519.PublicKey{}
	masterSigningKey := ed25519.NewKeyFromSeed(masterSeed)
	for role, r := range requests {
		var pub ed25519.PublicKey
		var key ed25519.PrivateKey
		if role == "master" {
			key = masterSigningKey
			pub = masterSigningKey.Public().(ed25519.PublicKey)
		} else {
			pub, key, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
		}
		b := stageReceiptBody{Request: r, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(5 * time.Minute).Unix()}
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		receipts[role] = signedStageReceipt{Body: b, Signature: ed25519.Sign(key, append([]byte("frontiercloud:preprod-stage-receipt:v2\x00"), raw...))}
		pins[role] = pub
	}
	lease, err := store.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reconcilePendingMedia(ctx, store, lease, complete, trust, plan, []signedSnapshotGrant{batch}, locators, stages, challenges, receipts, pins, m.MediaID, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.OperationID != prepared.OperationID || got.BlobID != prepared.BlobID || got.SourceAuthenticated || got.SnapshotConsistent || got.VaultAuthenticated || got.OwnerFinalPublished || got.RuntimeReady {
		t.Fatalf("incorrect observation: %+v", got)
	}
	vault, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	vault.SetMaxOpenConns(1)
	for _, q := range []string{
		"CREATE TABLE preprod_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)",
		"CREATE TABLE preprod_key_vault(object_tag TEXT PRIMARY KEY,grant_tag TEXT NOT NULL UNIQUE,file_tag TEXT NOT NULL UNIQUE,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)",
		"CREATE TABLE preprod_key_requests(request_tag TEXT PRIMARY KEY,nonce BLOB NOT NULL UNIQUE,cipher BLOB NOT NULL)",
		"CREATE TABLE preprod_key_request_consumed(request_tag TEXT PRIMARY KEY,receipt BLOB NOT NULL)",
		"CREATE TABLE preprod_snapshot_proofs(snapshot_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)",
		"CREATE TABLE preprod_snapshot_plans(plan_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)",
		"CREATE TABLE preprod_snapshot_batch_links(batch_tag TEXT PRIMARY KEY,plan_tag TEXT NOT NULL)",
	} {
		if _, err = vault.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	vaultRoot := bytes.Repeat([]byte{43}, 32)
	if _, err = vault.Exec("INSERT INTO preprod_key_vault_meta VALUES(1,?)", vaultTag(vaultRoot, "verifier", trust.TargetNode)); err != nil {
		t.Fatal(err)
	}
	scope := keyScope{Version: 1, SourceNode: body.SourceNode, SourceKeyID: body.SourceKeyID, TargetNode: body.TargetNode, Snapshot: hex.EncodeToString(batchDigest), MediaID: m.MediaID, SourceObjectID: m.ObjectID, TargetOwnerID: entry.TargetOwnerID, TargetBlobID: entry.TargetBlobID, TargetReadAlias: entry.TargetReadAlias, ContentSHA256: m.SHA256, StoredBytes: m.Size, Challenge: entry.Challenge, IssuedUnix: body.IssuedUnix, ExpiresUnix: body.ExpiresUnix, Descriptor: entry.Descriptor}
	if _, err = reconcilePendingEncryptedMediaAndVault(ctx, store, lease, vault, vaultRoot, complete, trust, plan, []signedSnapshotGrant{batch}, locators, stages, challenges, receipts, pins, scope, now); err == nil {
		t.Fatal("missing vault accepted")
	}
	manager, err := mediacrypto.New(sourcePremaster)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := sealSnapshotBoundDerivedFileKey(batch, scope, manager, target.PublicKey(), sourcePub, sourceKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveAuthorizedRequest(ctx, vault, vaultRoot, scope, sourcePub, target.PublicKey().Bytes(), now); err != nil {
		t.Fatal(err)
	}
	if _, err = importSnapshotAuthorizedFileKeyGrant(ctx, vault, vaultRoot, trust, plan, []signedSnapshotGrant{batch}, batch, scope, target, grant, now); err != nil {
		t.Fatal(err)
	}
	observed, err := reconcilePendingEncryptedMediaAndVault(ctx, store, lease, vault, vaultRoot, complete, trust, plan, []signedSnapshotGrant{batch}, locators, stages, challenges, receipts, pins, scope, now)
	if err != nil {
		t.Fatal(err)
	}
	if !observed.VaultAuthenticated || observed.SourceAuthenticated || observed.SnapshotConsistent || observed.OwnerFinalPublished || observed.RuntimeReady {
		t.Fatal("vault observation became publication permit")
	}
	// The admission below uses the real SQLite node/pool repositories and the
	// existing target node vault, but only synthetic keys and data.
	app, err := sqlitestore.Open(filepath.Join(t.TempDir(), "app.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err = app.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	nodeDir := t.TempDir()
	if err = os.Chmod(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	nv, err := nodevault.Open(nodeDir)
	if err != nil {
		t.Fatal(err)
	}
	sealedKey, err := nv.Seal(protocol.Encode(masterSeed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.Nodes().InitializeIdentity(ctx, storepkg.NodeIdentity{ID: trust.TargetNode, Role: "Standalone", PrivateKey: sealedKey, CreatedAt: now.Unix()}); err != nil {
		t.Fatal(err)
	}
	if _, err = app.Nodes().PromoteIdentity(ctx, storepkg.NodePromotion{Role: "Master", Endpoint: "https://master.example", Allocation: 5 * storepkg.GiB, PhysicalFree: 10 * storepkg.GiB}, storepkg.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	for i, role := range []string{"direct", "relay"} {
		mapping := s.Mappings[i+1]
		relationID := strings.Repeat(fmt.Sprint(i+8), 32)
		relation := storepkg.Relationship{ID: relationID, PeerID: mapping.TargetID, Endpoint: fmt.Sprintf("https://peer%d.example", i), PublicKey: protocol.Encode(pins[role]), Credential: "synthetic-sealed", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: now.Unix()}
		if err = app.Nodes().PrepareRelationship(ctx, relation, storepkg.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		if err = app.Nodes().ActivateRelationship(ctx, relationID, storepkg.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		if role == "direct" {
			if err = app.Nodes().SetRelationshipMode(ctx, relationID, "Direct", false, storepkg.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
		}
		config := storepkg.ResourceConfiguration{}
		config.Storage.Enabled = true
		config.Storage.Allocation = storepkg.GiB
		if err = app.Pool().ConfigureMember(ctx, mapping.TargetID, config, storepkg.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
	}
	routing := app.Nodes().(storepkg.PublicRoutingRepository)
	if err = routing.ConfigurePublicOrigin("https://public.example"); err != nil {
		t.Fatal(err)
	}
	authority := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "source-node-v1", SourceNode: trust.SourceNode, SourceKeyID: trust.SourceKeyID, SourcePublic: trust.SourcePublic, TargetNode: trust.TargetNode, TargetMasterPublic: pins["master"], TargetX25519: trust.TargetPublic, Generation: trust.Generation}
	wrongTarget := authority
	wrongTarget.TargetNode = strings.Repeat("f", 32)
	if err = provisionSourceAuthority(ctx, app, nv, wrongTarget); err == nil {
		t.Fatal("source pin accepted for a different Master identity")
	}
	wrongMasterKey := authority
	wrongMasterKey.TargetMasterPublic = bytes.Repeat([]byte{0x92}, ed25519.PublicKeySize)
	if err = provisionSourceAuthority(ctx, app, nv, wrongMasterKey); err == nil {
		t.Fatal("source pin accepted for a different Master signing key")
	}
	wrongReceiver, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongReceiverPin := authority
	wrongReceiverPin.TargetX25519 = wrongReceiver.PublicKey().Bytes()
	if err = provisionSourceAuthority(ctx, app, nv, wrongReceiverPin); err == nil {
		t.Fatal("source pin accepted for a different receiver key")
	}
	if err = provisionSourceAuthority(ctx, app, nv, authority); err != nil {
		t.Fatal(err)
	}
	if err = provisionSourceAuthority(ctx, app, nv, authority); err != nil {
		t.Fatalf("identical source pin retry: %v", err)
	}
	wrongGeneration := authority
	wrongGeneration.Generation = strings.Repeat("a", 64)
	if err = provisionSourceAuthority(ctx, app, nv, wrongGeneration); err == nil {
		t.Fatal("different source pin replaced the existing pin")
	}
	if _, err := authorizeOwnerPublish(ctx, app, nv, store, lease, vault, vaultRoot, complete, trust, plan, []signedSnapshotGrant{batch}, locators, stages, challenges, receipts, m.MediaID, &scope); err == nil {
		t.Fatal("unordered owner admission must remain disabled")
	}
	// The closed admission rejects this request too; signature validation is
	// covered by the independent receipt verifier tests, not by this guard.
	relayReceipt := receipts["relay"]
	wrongReceipt := relayReceipt
	relayBytes, err := json.Marshal(relayReceipt.Body)
	if err != nil {
		t.Fatal(err)
	}
	wrongReceipt.Signature = ed25519.Sign(masterSigningKey, append([]byte("frontiercloud:preprod-stage-receipt:v2\x00"), relayBytes...))
	receipts["relay"] = wrongReceipt
	if _, err = authorizeOwnerPublish(ctx, app, nv, store, lease, vault, vaultRoot, complete, trust, plan, []signedSnapshotGrant{batch}, locators, stages, challenges, receipts, m.MediaID, &scope); err == nil {
		t.Fatal("unordered admission accepted a request with a changed receipt")
	}
	receipts["relay"] = relayReceipt
	if _, err := authorizeOwnerPublish(ctx, app, nv, store, lease, nil, nil, complete, trust, plan, []signedSnapshotGrant{batch}, locators, stages, challenges, receipts, plainMedia.MediaID, nil); err == nil {
		t.Fatal("unordered plaintext admission must remain disabled")
	}
	badAuthority := authority
	badAuthority.Generation = strings.Repeat("a", 64)
	changedJSON, err := json.Marshal(badAuthority)
	if err != nil {
		t.Fatal(err)
	}
	badSealed, err := nv.Seal(string(changedJSON))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.Database().ExecContext(ctx, "UPDATE sealed_tree_source_pin SET sealed=? WHERE singleton=1", []byte(badSealed)); err != nil {
		t.Fatal(err)
	}
	if _, err = authorizeOwnerPublish(ctx, app, nv, store, lease, vault, vaultRoot, complete, trust, plan, []signedSnapshotGrant{batch}, locators, stages, challenges, receipts, m.MediaID, &scope); err == nil {
		t.Fatal("wrong independently pinned generation accepted")
	}
	bad := locators[m.MediaID]
	locators[m.MediaID] = pendingLocatorBinding{BlobID: strings.Repeat("3", 64), ReadAlias: bad.ReadAlias}
	if _, err = reconcilePendingMedia(ctx, store, lease, complete, trust, plan, []signedSnapshotGrant{batch}, locators, stages, challenges, receipts, pins, m.MediaID, now); err == nil {
		t.Fatal("changed pending mapping accepted")
	}
	locators[m.MediaID] = bad
	lease.Release()
	if _, err = reconcilePendingMedia(ctx, store, lease, complete, trust, plan, []signedSnapshotGrant{batch}, locators, stages, challenges, receipts, pins, m.MediaID, now); err == nil {
		t.Fatal("released tree lease accepted")
	}
}
