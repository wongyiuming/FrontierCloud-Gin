package preprodimport

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestSyntheticSignedSnapshotRestrictsDerivedKeyToExactObject(t *testing.T) {
	s, _, target, sourcePub, sourcePriv, now := keyGrantFixture(t)
	manager, err := mediacrypto.New(bytes.Repeat([]byte{0x49}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.SourceKeyID = manager.KeyID()
	entry := snapshotGrantEntry{MediaID: s.MediaID, SourceObjectID: s.SourceObjectID, TargetOwnerID: s.TargetOwnerID, TargetBlobID: s.TargetBlobID, TargetReadAlias: s.TargetReadAlias, ContentSHA256: s.ContentSHA256, StoredBytes: s.StoredBytes, Challenge: s.Challenge, Descriptor: s.Descriptor}
	body := snapshotGrantBody{Version: 1, SourceNode: s.SourceNode, SourceKeyID: s.SourceKeyID, TargetNode: s.TargetNode, TargetPublic: target.PublicKey().Bytes(), Generation: strings.Repeat("e", 64), BatchCount: 1, IssuedUnix: s.IssuedUnix, ExpiresUnix: s.ExpiresUnix, Entries: []snapshotGrantEntry{entry}}
	signed, err := signApprovedSnapshot(body, sourcePriv, now)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := snapshotGrantDigest(body, now)
	if err != nil {
		t.Fatal(err)
	}
	s.Snapshot = hex.EncodeToString(digest)
	grant, err := sealSnapshotBoundDerivedFileKey(signed, s, manager, target.PublicKey(), sourcePub, sourcePriv, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openFileKey(grant, s, target, sourcePub, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	want, err := manager.FileKey(s.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	if !bytes.Equal(got, want) {
		t.Fatal("signed snapshot derived the wrong key")
	}
	for name, mutate := range map[string]func(*keyScope){
		"snapshot":   func(x *keyScope) { x.Snapshot = strings.Repeat("f", 64) },
		"content":    func(x *keyScope) { x.ContentSHA256 = strings.Repeat("f", 64) },
		"media":      func(x *keyScope) { x.MediaID = strings.Repeat("f", 64) },
		"owner":      func(x *keyScope) { x.TargetOwnerID = strings.Repeat("f", 32) },
		"blob":       func(x *keyScope) { x.TargetBlobID = strings.Repeat("f", 64) },
		"alias":      func(x *keyScope) { x.TargetReadAlias = strings.Repeat("f", 64) },
		"challenge":  func(x *keyScope) { x.Challenge = strings.Repeat("f", 64) },
		"descriptor": func(x *keyScope) { x.Descriptor.FileID = strings.Repeat("f", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			mutate(&changed)
			if _, err := sealSnapshotBoundDerivedFileKey(signed, changed, manager, target.PublicKey(), sourcePub, sourcePriv, now); err == nil {
				t.Fatal("changed scope accepted")
			}
		})
	}
	wrongTarget, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sealSnapshotBoundDerivedFileKey(signed, s, manager, wrongTarget.PublicKey(), sourcePub, sourcePriv, now); err == nil {
		t.Fatal("wrong target accepted")
	}
	wrongPub, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sealSnapshotBoundDerivedFileKey(signed, s, manager, target.PublicKey(), wrongPub, wrongPriv, now); err == nil {
		t.Fatal("wrong source signer accepted")
	}
	if _, err = sealSnapshotBoundDerivedFileKey(signed, s, manager, target.PublicKey(), sourcePub, sourcePriv, now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired snapshot accepted")
	}
	tampered := signed
	tampered.Signature = append([]byte(nil), signed.Signature...)
	tampered.Signature[0] ^= 1
	if _, err = sealSnapshotBoundDerivedFileKey(tampered, s, manager, target.PublicKey(), sourcePub, sourcePriv, now); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestSyntheticSnapshotRejectsDuplicateOrCrossObjectLocators(t *testing.T) {
	s, _, target, _, source, now := keyGrantFixture(t)
	entry := snapshotGrantEntry{MediaID: s.MediaID, SourceObjectID: s.SourceObjectID, TargetOwnerID: s.TargetOwnerID, TargetBlobID: s.TargetBlobID, TargetReadAlias: s.TargetReadAlias, ContentSHA256: s.ContentSHA256, StoredBytes: s.StoredBytes, Challenge: s.Challenge, Descriptor: s.Descriptor}
	other := entry
	other.MediaID = strings.Repeat("6", 64)
	other.SourceObjectID = strings.Repeat("7", 64)
	other.TargetBlobID = strings.Repeat("c", 64)
	other.TargetReadAlias = strings.Repeat("d", 64)
	other.Challenge = strings.Repeat("f", 64)
	other.Descriptor.FileID = strings.Repeat("d", 32)
	body := snapshotGrantBody{Version: 1, SourceNode: s.SourceNode, SourceKeyID: s.SourceKeyID, TargetNode: s.TargetNode, TargetPublic: target.PublicKey().Bytes(), Generation: strings.Repeat("e", 64), BatchCount: 1, IssuedUnix: s.IssuedUnix, ExpiresUnix: s.ExpiresUnix, Entries: []snapshotGrantEntry{entry, other}}
	if _, err := signApprovedSnapshot(body, source, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*snapshotGrantBody){
		"unsorted":                func(x *snapshotGrantBody) { x.Entries[0], x.Entries[1] = x.Entries[1], x.Entries[0] },
		"duplicate challenge":     func(x *snapshotGrantBody) { x.Entries[1].Challenge = x.Entries[0].Challenge },
		"duplicate file":          func(x *snapshotGrantBody) { x.Entries[1].Descriptor.FileID = x.Entries[0].Descriptor.FileID },
		"duplicate blob":          func(x *snapshotGrantBody) { x.Entries[1].TargetBlobID = x.Entries[0].TargetBlobID },
		"alias equals other blob": func(x *snapshotGrantBody) { x.Entries[1].TargetReadAlias = x.Entries[0].TargetBlobID },
		"blob equals other alias": func(x *snapshotGrantBody) { x.Entries[1].TargetBlobID = x.Entries[0].TargetReadAlias },
		"other source id":         func(x *snapshotGrantBody) { x.Entries[0].TargetBlobID = x.Entries[1].SourceObjectID },
		"other media id":          func(x *snapshotGrantBody) { x.Entries[0].TargetBlobID = x.Entries[1].MediaID },
	} {
		t.Run(name, func(t *testing.T) {
			copyBody := body
			copyBody.Entries = append([]snapshotGrantEntry(nil), body.Entries...)
			mutate(&copyBody)
			if _, err := signApprovedSnapshot(copyBody, source, now); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestSyntheticSnapshotAndAuthorizedRequestGateVaultInstall(t *testing.T) {
	s, _, target, sourcePub, sourcePriv, now := keyGrantFixture(t)
	manager, err := mediacrypto.New(bytes.Repeat([]byte{0x49}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.SourceKeyID = manager.KeyID()
	entry := snapshotGrantEntry{MediaID: s.MediaID, SourceObjectID: s.SourceObjectID, TargetOwnerID: s.TargetOwnerID, TargetBlobID: s.TargetBlobID, TargetReadAlias: s.TargetReadAlias, ContentSHA256: s.ContentSHA256, StoredBytes: s.StoredBytes, Challenge: s.Challenge, Descriptor: s.Descriptor}
	body := snapshotGrantBody{Version: 1, SourceNode: s.SourceNode, SourceKeyID: s.SourceKeyID, TargetNode: s.TargetNode, TargetPublic: target.PublicKey().Bytes(), Generation: strings.Repeat("e", 64), BatchCount: 1, IssuedUnix: s.IssuedUnix, ExpiresUnix: s.ExpiresUnix, Entries: []snapshotGrantEntry{entry}}
	snapshot, err := signApprovedSnapshot(body, sourcePriv, now)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := snapshotGrantDigest(body, now)
	if err != nil {
		t.Fatal(err)
	}
	s.Snapshot = hex.EncodeToString(digest)
	planBody := snapshotPlanBody{Version: 1, SourceNode: body.SourceNode, SourceKeyID: body.SourceKeyID, TargetNode: body.TargetNode, TargetPublic: body.TargetPublic, Generation: body.Generation, IssuedUnix: body.IssuedUnix, ExpiresUnix: body.ExpiresUnix, Batches: []snapshotPlanBatch{{Digest: s.Snapshot, Count: 1}}}
	plan, err := signApprovedSnapshotPlan(planBody, sourcePriv, now)
	if err != nil {
		t.Fatal(err)
	}
	batches := []signedSnapshotGrant{snapshot}
	planDigest, err := snapshotPlanDigest(plan.Body, now)
	if err != nil {
		t.Fatal(err)
	}
	trust := snapshotPlanTrust{SourceNode: body.SourceNode, SourceKeyID: body.SourceKeyID, SourcePublic: sourcePub, TargetNode: body.TargetNode, TargetPublic: target.PublicKey().Bytes(), Generation: body.Generation, PlanDigest: hex.EncodeToString(planDigest)}
	grant, err := sealSnapshotBoundDerivedFileKey(snapshot, s, manager, target.PublicKey(), sourcePub, sourcePriv, now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot-fixture.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL",
		"CREATE TABLE preprod_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)",
		"CREATE TABLE preprod_key_vault(object_tag TEXT PRIMARY KEY,grant_tag TEXT NOT NULL UNIQUE,file_tag TEXT NOT NULL UNIQUE,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)",
		"CREATE TABLE preprod_key_requests(request_tag TEXT PRIMARY KEY,nonce BLOB NOT NULL UNIQUE,cipher BLOB NOT NULL)",
		"CREATE TABLE preprod_key_request_consumed(request_tag TEXT PRIMARY KEY,receipt BLOB NOT NULL)",
		"CREATE TABLE preprod_snapshot_proofs(snapshot_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)",
		"CREATE TABLE preprod_snapshot_plans(plan_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)",
		"CREATE TABLE preprod_snapshot_batch_links(batch_tag TEXT PRIMARY KEY,plan_tag TEXT NOT NULL)",
	} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	root := bytes.Repeat([]byte{0x82}, 32)
	ctx := context.Background()
	if _, err = db.Exec("INSERT INTO preprod_key_vault_meta VALUES(1,?)", vaultTag(root, "verifier", s.TargetNode)); err != nil {
		t.Fatal(err)
	}
	if _, err = importSnapshotAuthorizedFileKeyGrant(ctx, db, root, trust, plan, batches, snapshot, s, target, grant, now); err == nil {
		t.Fatal("unrequested snapshot accepted")
	}
	var proofs int
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_snapshot_proofs").Scan(&proofs); err != nil || proofs != 0 {
		t.Fatal("failed request left a snapshot proof")
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_snapshot_plans").Scan(&proofs); err != nil || proofs != 0 {
		t.Fatal("failed request left a snapshot plan")
	}
	if err = saveAuthorizedRequest(ctx, db, root, s, sourcePub, target.PublicKey().Bytes(), now); err != nil {
		t.Fatal(err)
	}
	tampered := snapshot
	tampered.Signature = append([]byte(nil), snapshot.Signature...)
	tampered.Signature[0] ^= 1
	if _, err = importSnapshotAuthorizedFileKeyGrant(ctx, db, root, trust, plan, batches, tampered, s, target, grant, now); err == nil {
		t.Fatal("invalid snapshot accepted")
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_key_vault").Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid snapshot installed a key")
	}
	if _, err = importSnapshotAuthorizedFileKeyGrant(ctx, db, root, trust, plan, nil, snapshot, s, target, grant, now); err == nil {
		t.Fatal("incomplete snapshot plan accepted")
	}
	for name, mutate := range map[string]func(*snapshotPlanTrust){
		"source node":      func(v *snapshotPlanTrust) { v.SourceNode = strings.Repeat("f", 32) },
		"source media key": func(v *snapshotPlanTrust) { v.SourceKeyID = strings.Repeat("f", 64) },
		"target node":      func(v *snapshotPlanTrust) { v.TargetNode = strings.Repeat("f", 32) },
		"generation":       func(v *snapshotPlanTrust) { v.Generation = strings.Repeat("f", 64) },
		"plan digest":      func(v *snapshotPlanTrust) { v.PlanDigest = strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := trust
			mutate(&bad)
			if _, err := importSnapshotAuthorizedFileKeyGrant(ctx, db, root, bad, plan, batches, snapshot, s, target, grant, now); err == nil {
				t.Fatal("incorrect external trust pin accepted")
			}
		})
	}
	if already, err := importSnapshotAuthorizedFileKeyGrant(ctx, db, root, trust, plan, batches, snapshot, s, target, grant, now); err != nil || already {
		t.Fatalf("initial install: %v", err)
	}
	if err = verifyInstalledKeyPlan(ctx, db, root, trust, plan, batches, s, now); err != nil {
		t.Fatalf("installed plan and vault: %v", err)
	}
	if err = verifyInstalledKeyPlan(ctx, db, root, trust, plan, batches, s, now.Add(6*time.Minute)); err == nil {
		t.Fatal("expired vault plan accepted for a new action")
	}
	badTrust := trust
	badTrust.TargetNode = strings.Repeat("f", 32)
	if err = verifyInstalledKeyPlan(ctx, db, root, badTrust, plan, batches, s, now); err == nil {
		t.Fatal("wrong target vault pin accepted")
	}
	var requestTag string
	var requestReceipt []byte
	if err = db.QueryRow("SELECT request_tag,receipt FROM preprod_key_request_consumed").Scan(&requestTag, &requestReceipt); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DELETE FROM preprod_key_request_consumed WHERE request_tag=?", requestTag); err != nil {
		t.Fatal(err)
	}
	if err = verifyInstalledKeyPlan(ctx, db, root, trust, plan, batches, s, now); err == nil {
		t.Fatal("orphan vault accepted")
	}
	if _, err = db.Exec("INSERT INTO preprod_key_request_consumed(request_tag,receipt) VALUES (?,?)", requestTag, requestReceipt); err != nil {
		t.Fatal(err)
	}
	if already, err := importSnapshotAuthorizedFileKeyGrant(ctx, db, root, trust, plan, batches, snapshot, s, target, grant, now); err != nil || !already {
		t.Fatalf("lost-reply retry: %v", err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_snapshot_proofs").Scan(&proofs); err != nil || proofs != 1 {
		t.Fatal("signed proof not retained")
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_snapshot_plans").Scan(&proofs); err != nil || proofs != 1 {
		t.Fatal("signed complete plan not retained")
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_snapshot_batch_links").Scan(&proofs); err != nil || proofs != 1 {
		t.Fatal("signed batch link not retained")
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	recoveredPlan, recoveredBatches, foundPlan, err := recoverCompletePlan(ctx, db, root, s, trust)
	if err != nil || !foundPlan {
		t.Fatalf("recover complete signed plan: %v", err)
	}
	if err = verifyCompleteSnapshotPlan(recoveredPlan, recoveredBatches, sourcePub, target.PublicKey().Bytes(), now.Add(6*time.Minute)); err == nil {
		t.Fatal("recovered expired plan renewed authorization")
	}
	var savedPlan []byte
	if err = db.QueryRow("SELECT cipher FROM preprod_snapshot_plans").Scan(&savedPlan); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE preprod_snapshot_plans SET cipher=zeroblob(length(cipher))"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = recoverCompletePlan(ctx, db, root, s, trust); err == nil {
		t.Fatal("tampered plan recovered")
	}
	if _, err = db.Exec("UPDATE preprod_snapshot_plans SET cipher=?", savedPlan); err != nil {
		t.Fatal(err)
	}
	recovered, found, err := recoverSnapshotProof(ctx, db, root, s, sourcePub, target.PublicKey().Bytes())
	if err != nil || !found {
		t.Fatalf("recover original proof: %v", err)
	}
	if err = verifySnapshotGrant(recovered, sourcePub, target.PublicKey().Bytes(), s, now.Add(6*time.Minute)); err == nil {
		t.Fatal("recovered expired proof renewed authorization")
	}
	if _, err = importSnapshotAuthorizedFileKeyGrant(ctx, db, root, trust, plan, batches, recovered, s, target, grant, now.Add(6*time.Minute)); err == nil {
		t.Fatal("expired proof reinstalled a key")
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = recoverSnapshotProof(ctx, db, root, s, wrongPub, target.PublicKey().Bytes()); err == nil {
		t.Fatal("untrusted source recovered proof")
	}
	wrongTrust := trust
	wrongTrust.SourcePublic = wrongPub
	if _, _, _, err = recoverCompletePlan(ctx, db, root, s, wrongTrust); err == nil {
		t.Fatal("untrusted source recovered complete plan")
	}
	fileKey, err := manager.FileKey(s.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fileKey)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, readErr := os.ReadFile(path + suffix)
		if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatal(readErr)
		}
		for _, sensitive := range [][]byte{fileKey, []byte(s.MediaID), []byte(s.SourceObjectID), []byte(s.TargetBlobID), []byte(s.TargetReadAlias), []byte(s.Challenge), []byte(s.Descriptor.FileID), []byte(s.Snapshot)} {
			if bytes.Contains(data, sensitive) {
				t.Fatal("snapshot evidence leaked plaintext")
			}
		}
	}
	if _, err = db.Exec("UPDATE preprod_snapshot_proofs SET cipher=zeroblob(length(cipher))"); err != nil {
		t.Fatal(err)
	}
	if _, err = importSnapshotAuthorizedFileKeyGrant(ctx, db, root, trust, plan, batches, snapshot, s, target, grant, now); err == nil {
		t.Fatal("tampered persisted proof accepted")
	}
}
