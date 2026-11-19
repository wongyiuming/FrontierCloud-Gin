//go:build linux && owner_publish_fixture && ledger_fixture

package preprodimport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// This joins the real Owner filesystem/fence fixture to the real Master
// business/tree transaction. Source/key-vault authorization, production
// activation, and the cross-database recovery fence are not implemented here.
func TestFixtureOwnerReceiptThroughMasterTreeAndCapacity(t *testing.T) {
	ctx := context.Background()
	mk := func(role string) (*sqlite.Store, *node.Identity, *vault.Vault, string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "business.db")
		secrets := filepath.Join(dir, "secrets")
		cfg := config.Config{DataRoot: dir, SQLitePath: path, DatabaseType: config.DatabaseSQLite, SecretsDirectory: secrets}
		// Match production startup: select the authoritative store before the
		// node vault or database identity is initialized.
		if err := deployment.Bind(ctx, cfg, nil); err != nil {
			t.Fatal("initial deployment binding", err)
		}
		db, err := sqlite.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if err = db.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
		if err = os.Mkdir(secrets, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err = node.Initialize(ctx, db.Nodes(), secrets); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: role, Endpoint: "https://" + strings.ToLower(role) + ".test", Allocation: 2 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		id, err := node.OpenExisting(ctx, db.Nodes(), secrets)
		if err != nil {
			t.Fatal(err)
		}
		v, err := vault.OpenExisting(secrets)
		if err != nil {
			t.Fatal(err)
		}
		return db, id, v, dir
	}
	master, masterID, masterVault, masterDir := mk("Master")
	owner, ownerID, ownerVault, ownerDir := mk("Follower")
	masterSeed, err := masterVault.Unseal(masterID.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	masterPublic, err := protocol.PublicKey(masterSeed)
	if err != nil {
		t.Fatal(err)
	}
	ownerSeed, err := ownerVault.Unseal(ownerID.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	ownerPublic, err := protocol.PublicKey(ownerSeed)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	relID := strings.Repeat("3", 32)
	pair := store.PairPackage{Nonce: strings.Repeat("4", 32), TokenHash: strings.Repeat("5", 64), ExpiresAt: now + 250}
	if _, err = owner.Nodes().IssuePair(ctx, pair, now, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	ownerRel := store.Relationship{ID: relID, PeerID: masterID.ID, Endpoint: "https://master.test", PublicKey: masterPublic, Credential: "sealed-owner-fixture", Direction: "upstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: now}
	if err = owner.Nodes().ConsumePair(ctx, pair, ownerRel, now, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = owner.Nodes().ActivateRelationship(ctx, relID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	masterRel := store.Relationship{ID: relID, PeerID: ownerID.ID, Endpoint: "https://follower.test", PublicKey: ownerPublic, Credential: "sealed-master-fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: now}
	if err = master.Nodes().PrepareRelationship(ctx, masterRel, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = master.Nodes().ActivateRelationship(ctx, relID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	ownerRel, err = owner.Nodes().Relationship(ctx, relID)
	if err != nil {
		t.Fatal(err)
	}
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 2*store.GiB
	if err = master.Pool().ConfigureMember(ctx, ownerID.ID, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = master.Nodes().RecordHeartbeat(ctx, relID, true, 1, map[string]any{"storage_free": int64(10 * store.GiB)}, now); err != nil {
		t.Fatal(err)
	}

	if err = os.Mkdir(filepath.Join(ownerDir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	ownerRoot, err := os.OpenRoot(ownerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerRoot.Close()
	ownerFence, err := ownerfence.Create(ownerRoot, ownerDir, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	ownerRepo := owner.Nodes().(*business.Repository)
	if err = ownerRepo.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return ownerFence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = ownerRepo.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}

	masterPath := filepath.Join(masterDir, "business.db")
	cfg := config.Config{DataRoot: masterDir, SQLitePath: masterPath, DatabaseType: config.DatabaseSQLite, SecretsDirectory: filepath.Join(masterDir, "secrets")}
	if err = deployment.Bind(ctx, cfg, nil); err != nil {
		t.Fatal(err)
	}
	fenceDir := filepath.Join(masterDir, "tree-private")
	if err = os.Mkdir(fenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(masterDir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.New(bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID := strings.Repeat("a", 64)
	if err = sealedtree.FixtureInitializeExisting(ctx, cfg, gate, tree, rootID, fenceDir); err != nil {
		t.Fatal(err)
	}
	storeTree, err := sealedtree.OpenSQLite(ctx, master.Database(), tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(fenceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	if _, err = sealedtree.OpenFence(ctx, storeTree, treeRoot, fenceDir); err != nil {
		t.Fatal(err)
	}
	existing := sealedtree.Entry{ParentID: rootID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "kept"}
	if err = storeTree.CreateDirectoryWithFacts(ctx, existing, sealedtree.Facts{ObjectID: existing.ObjectID}); err != nil {
		t.Fatal(err)
	}
	if _, err = master.Database().ExecContext(ctx, `CREATE TABLE legacy_fixture(value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = master.Database().ExecContext(ctx, `INSERT INTO legacy_fixture VALUES('preserved')`); err != nil {
		t.Fatal(err)
	}
	data := []byte("real owner published fixture bytes")
	sum := sha256.Sum256(data)
	object := strings.Repeat("b", 64)
	source := makeSignedSourceForOwnerFixture(t, master, masterVault, ownerID.ID, object, strings.Repeat("7", 64), data)
	resolution, err := sourceLyricResolution(source.Complete, source.Media, source.SourceDigest, source.Pin.Generation)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := sourceObjectTreeFacts(source.Complete, source.Media, resolution)
	if err != nil {
		t.Fatal(err)
	}
	music := sealedtree.Entry{ParentID: rootID, ObjectID: strings.Repeat("e", 64), Kind: "directory", Name: "music"}
	if err = storeTree.CreateDirectoryWithFacts(ctx, music, sealedtree.Facts{ObjectID: music.ObjectID}); err != nil {
		t.Fatal(err)
	}
	directory := sealedtree.Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("f", 64), Kind: "directory", Name: "fixture"}
	if err = storeTree.CreateDirectoryWithFacts(ctx, directory, sealedtree.Facts{ObjectID: directory.ObjectID}); err != nil {
		t.Fatal(err)
	}
	entry := sealedtree.Entry{ParentID: directory.ObjectID, ObjectID: object, Kind: "audio", Name: "track.mp3"}
	placement := sealedtree.Placement{ObjectID: object, NativeObjectID: source.Media.ObjectID, OwnerID: ownerID.ID, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), ETag: `W/"legacy"`, State: "active", CreatedAt: 1, UpdatedAt: 2}
	pending, err := storeTree.PrepareFileWithFreshLocators(ctx, entry, placement, facts)
	if err != nil {
		t.Fatal(err)
	}
	placement.BlobID, placement.ReadAlias = pending.BlobID, pending.ReadAlias
	proofScope := objectProofScope{TargetOwnerID: ownerID.ID, TargetBlobID: pending.BlobID, TargetReadAlias: pending.ReadAlias, Challenge: strings.Repeat("c", 64)}
	objectProof := source.objectProof(t, proofScope)
	proof, err := decodeObjectEvidenceProof(objectProof, source.Receiver)
	if err != nil {
		t.Fatal(err)
	}
	readLease, err := storeTree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	observed, reconcileErr := reconcilePlainOrLyric(ctx, storeTree, readLease, source.Receiver, source.Pin, source.Envelope, objectProof, source.Challenge, source.Complete, object, proofScope, time.Now())
	readLease.Release()
	if reconcileErr != nil || observed.OperationID != pending.OperationID || observed.BlobID != pending.BlobID || observed.ReadAlias != pending.ReadAlias {
		t.Fatal("signed source pending reconciliation", reconcileErr)
	}
	selected := sealedtree.LyricSelection{BuiltinFallback: resolution.State != "explicit", Evidence: resolution.Evidence, SourceDigest: source.SourceDigest, SourceGeneration: source.Pin.Generation}
	capability, err := prepareCompleteSourceLyric(source.Envelope, source.Receiver, source.Pin, source.Challenge, source.Complete, 1)
	if err != nil || capability.check(source.Pin, source.Envelope, 1, object, selected) != nil {
		t.Fatal("source capability", err)
	}
	masterRepo := master.Nodes().(*business.Repository)
	key := bytes.Repeat([]byte{7}, 32)
	if err = masterRepo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	intent := business.OpaqueCapacityIntent{OperationID: pending.OperationID, MasterID: masterID.ID, MemberID: ownerID.ID, BlobID: pending.BlobID, Digest: placement.SHA256, Bytes: placement.Bytes}
	if _, err = masterRepo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); err != nil {
		t.Fatal(err)
	}
	scope, _, err := masterRepo.BindOpaqueCapacityScope(ctx, key, intent.OperationID, source.Pin.Generation, strings.Repeat("8", 64))
	if err != nil {
		t.Fatal(err)
	}
	receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: masterID.ID, OwnerID: ownerID.ID, RelationshipID: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding, Generation: scope.Generation, OperationID: intent.OperationID, StageID: scope.StageID, BlobID: intent.BlobID, Digest: intent.Digest, Challenge: scope.PublishChallenge, Bytes: intent.Bytes, State: "published"}
	auth := fixtureOwnerAuthorization{Receipt: receipt, ExpiresAt: time.Now().Unix() + 240}
	payload, err := auth.payload()
	if err != nil {
		t.Fatal(err)
	}
	masterSignature, err := protocol.Sign(masterSeed, payload)
	if err != nil {
		t.Fatal(err)
	}
	publisher := fixtureOwnerPublisher{db: owner, repo: ownerRepo, fence: ownerFence, root: ownerRoot, expectedOwner: ownerID.NodeIdentity, expectedRelationship: ownerRel, beforeSign: func() error { return errors.New("lost receipt") }}
	if _, err = publisher.publish(ctx, auth, masterSignature, bytes.NewReader(data), false); err == nil {
		t.Fatal("injected receipt loss ignored")
	}
	if _, _, err = storeTree.Get(ctx, object); err == nil {
		t.Fatal("owner publication exposed pending tree")
	}
	ownerFence, err = ownerfence.Open(ownerRoot, ownerDir, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	publisher.fence, publisher.beforeSign = ownerFence, nil
	signedReceipt, err := publisher.publish(ctx, auth, masterSignature, bytes.NewReader(nil), false)
	if err != nil {
		t.Fatal("owner recovery", err)
	}
	if _, err = masterRepo.RecordOpaquePublishedReceipt(ctx, key, masterVault, receipt, signedReceipt); err != nil {
		t.Fatal("record real owner signature", err)
	}
	if _, err = master.Database().ExecContext(ctx, `CREATE TRIGGER fail_fixture_settle BEFORE UPDATE ON sealed_tree_capacity_scopes BEGIN SELECT RAISE(ABORT,'settlement-fault'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = sealedtree.FixtureCommitSignedPending(ctx, storeTree, key, masterVault, receipt, signedReceipt); err == nil || !strings.Contains(err.Error(), "settlement-fault") {
		t.Fatal("settlement fault", err)
	}
	if _, _, err = storeTree.Get(ctx, object); err == nil {
		t.Fatal("partial publication")
	}
	var used, reserved int64
	if err = master.Database().QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, ownerID.ID).Scan(&used, &reserved); err != nil || used != 0 || reserved != int64(len(data)) {
		t.Fatalf("partial capacity %d/%d: %v", used, reserved, err)
	}
	if _, err = master.Database().ExecContext(ctx, `DROP TRIGGER fail_fixture_settle`); err != nil {
		t.Fatal(err)
	}
	if err = master.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlite.OpenExisting(ctx, masterPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedTree, err := sealedtree.OpenSQLite(ctx, reopened.Database(), tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sealedtree.OpenFence(ctx, reopenedTree, treeRoot, fenceDir); err != nil {
		t.Fatal(err)
	}
	reopenedRepo := reopened.Nodes().(*business.Repository)
	if already, e := reopenedRepo.RecordOpaquePublishedReceipt(ctx, key, masterVault, receipt, signedReceipt); e != nil || !already {
		t.Fatal("recover owner receipt", already, e)
	}
	identity, err := reopened.Nodes().ReadIdentity(ctx)
	if err != nil || identity != masterID.NodeIdentity {
		t.Fatal("master identity changed", err)
	}
	sealedPin, found, err := reopenedRepo.LoadOpaqueSourcePin(ctx, identity, masterVault)
	if err != nil || !found {
		t.Fatal("source pin unavailable", err)
	}
	decodedPin, err := decodeSourceAuthority(masterVault, sealedPin)
	if err != nil || !reflect.DeepEqual(decodedPin, source.Pin) {
		t.Fatal("source pin changed", err)
	}
	// Expensive complete source verification happens before the source SQLite
	// writer reservation. Capture its exact encrypted row in the same read
	// snapshot as the authenticated envelope for the final short comparison.
	readTx, err := source.EvidenceDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	recorded, _, err := readSourceEvidenceTx(ctx, readTx, source.EvidenceRoot, source.Receiver, source.Pin, source.EvidenceRef)
	if err != nil || !reflect.DeepEqual(recorded.Envelope, source.Envelope) {
		t.Fatal("source vault evidence", err)
	}
	tag, err := sourceEvidenceTag(source.EvidenceRoot, source.EvidenceRef.Digest)
	if err != nil {
		t.Fatal(err)
	}
	rowHash, err := fixtureEvidenceRowHash(ctx, readTx, tag)
	if err != nil {
		t.Fatal(err)
	}
	if err = readTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var originalCipher []byte
	if err = source.EvidenceDB.QueryRowContext(ctx, `SELECT cipher FROM preprod_source_evidence WHERE evidence_tag=?`, tag).Scan(&originalCipher); err != nil {
		t.Fatal(err)
	}
	if _, err = source.EvidenceDB.ExecContext(ctx, `UPDATE preprod_source_evidence SET cipher=zeroblob(length(cipher)) WHERE evidence_tag=?`, tag); err != nil {
		t.Fatal(err)
	}
	if bad, e := fixtureAcquireEvidenceFence(ctx, source.EvidenceDB, source.EvidencePath, tag, rowHash, source.Source.ExpiresUnix); e == nil {
		bad.Release()
		t.Fatal("changed source ciphertext accepted")
	}
	if _, err = source.EvidenceDB.ExecContext(ctx, `UPDATE preprod_source_evidence SET cipher=? WHERE evidence_tag=?`, originalCipher, tag); err != nil {
		t.Fatal(err)
	}
	deadline := source.Source.ExpiresUnix
	if proof.Proof.ExpiresUnix < deadline {
		deadline = proof.Proof.ExpiresUnix
	}
	evidenceFence, err := fixtureAcquireEvidenceFence(ctx, source.EvidenceDB, source.EvidencePath, tag, rowHash, deadline)
	if err != nil {
		t.Fatal("source fence", err)
	}
	defer evidenceFence.Release()
	before := func(conn *sql.Conn) error {
		if e := evidenceFence.Check(ctx); e != nil {
			return e
		}
		var actual store.NodeIdentity
		if e := conn.QueryRowContext(ctx, "SELECT node_id,`role`,endpoint,private_key,created_at FROM node_identity WHERE singleton=1").Scan(&actual.ID, &actual.Role, &actual.Endpoint, &actual.PrivateKey, &actual.CreatedAt); e != nil || actual != identity {
			return errors.New("fixture target identity changed")
		}
		var currentPin string
		if e := conn.QueryRowContext(ctx, `SELECT sealed FROM sealed_tree_source_pin WHERE singleton=1`).Scan(&currentPin); e != nil || currentPin != sealedPin {
			return errors.New("fixture target pin changed")
		}
		return sealedtree.FixtureValidatePendingExact(ctx, reopenedTree, conn, pending.OperationID, source.Media.Path, entry, placement, facts)
	}
	after := func() error { return evidenceFence.Check(ctx) }
	// An actual source DB pathname swap during the held writer reservation
	// must fail before COMMIT and leave both business mutations uncommitted.
	savedPath := source.EvidencePath + ".fixture-saved"
	if err = os.Rename(source.EvidencePath, savedPath); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(source.EvidencePath, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	_, rejected := sealedtree.FixtureCommitSignedPendingWithChecks(ctx, reopenedTree, key, masterVault, receipt, signedReceipt, before, after)
	if err = os.Remove(source.EvidencePath); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(savedPath, source.EvidencePath); err != nil {
		t.Fatal(err)
	}
	if rejected == nil {
		t.Fatal("source inode replacement accepted")
	}
	if _, _, err = reopenedTree.Get(ctx, object); err == nil {
		t.Fatal("source replacement exposed pending tree")
	}
	actualDeadline := evidenceFence.expiresAt
	evidenceFence.expiresAt = time.Now().Unix()
	if _, err = sealedtree.FixtureCommitSignedPendingWithChecks(ctx, reopenedTree, key, masterVault, receipt, signedReceipt, before, after); err == nil {
		t.Fatal("expired source fence accepted")
	}
	evidenceFence.expiresAt = actualDeadline
	// The child independently reopens both databases and re-verifies the
	// signed source, Owner receipt and authenticated pending object. Terminate
	// it once before COMMIT and once after COMMIT but before acknowledgement.
	evidenceFence.Release()
	childInput := sourceOwnerCrashInput{
		MasterDir: masterDir, TreeFenceDir: fenceDir, SourceDBPath: source.EvidencePath, OwnerDir: ownerDir, RootID: rootID,
		TreeIndexKey: bytes.Repeat([]byte{0x42}, 32), TreeFactsKey: bytes.Repeat([]byte{0x91}, 32), CapacityKey: key, EvidenceRoot: source.EvidenceRoot,
		SourceRef: source.EvidenceRef, Pin: source.Pin, Complete: source.Complete, Envelope: source.Envelope, ObjectProof: objectProof, Challenge: source.Challenge, MediaID: object, ProofScope: proofScope,
		Entry: entry, Placement: placement, Facts: facts, OwnerAuth: auth, MasterSignature: masterSignature, OwnerReceiptSignature: signedReceipt,
	}
	executable, err := os.Executable()
	if err != nil { t.Fatal(err) }
	runCrash := func(phase string, expected int) {
		t.Helper()
		childInput.Phase = phase
		input, e := json.Marshal(childInput)
		if e != nil { t.Fatal(e) }
		child := exec.Command(executable, "-test.run=^TestFixtureSourceOwnerCrashHelper$")
		child.Env = append(os.Environ(), "FC_SOURCE_OWNER_CRASH_CHILD=1")
		child.Stdin = bytes.NewReader(input)
		output, e := child.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(e, &exit) || exit.ExitCode() != expected { t.Fatalf("%s crash checkpoint: %v %s", phase, e, output) }
	}
	runCrash("before", 74)
	if _, _, err = reopenedTree.Get(ctx, object); err == nil { t.Fatal("pre-commit crash exposed pending tree") }
	if err = reopened.Database().QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, ownerID.ID).Scan(&used, &reserved); err != nil || used != 0 || reserved != int64(len(data)) { t.Fatalf("pre-commit crash changed capacity %d/%d: %v", used, reserved, err) }
	runCrash("after", 73)
	if err = reopened.Close(); err != nil { t.Fatal(err) }
	committed, err := sqlite.OpenExisting(ctx, masterPath)
	if err != nil { t.Fatal(err) }
	defer committed.Close()
	reopened = committed
	reopenedTree, err = sealedtree.OpenSQLite(ctx, reopened.Database(), tree, rootID)
	if err != nil { t.Fatal(err) }
	if _, err = sealedtree.OpenFence(ctx, reopenedTree, treeRoot, fenceDir); err != nil { t.Fatal(err) }
	if already, e := sealedtree.FixtureCommitSignedPending(ctx, reopenedTree, key, masterVault, receipt, signedReceipt); e != nil || !already {
		t.Fatal("commit retry", already, e)
	}
	if _, _, err = reopenedTree.Get(ctx, object); err != nil {
		t.Fatal(err)
	}
	if got, _, e := reopenedTree.Get(ctx, existing.ObjectID); e != nil || got.Name != existing.Name {
		t.Fatal("existing tree object", e)
	}
	if err = reopened.Database().QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, ownerID.ID).Scan(&used, &reserved); err != nil || used != int64(len(data)) || reserved != 0 {
		t.Fatalf("settled capacity %d/%d: %v", used, reserved, err)
	}
	var legacy string
	if err = reopened.Database().QueryRowContext(ctx, `SELECT value FROM legacy_fixture`).Scan(&legacy); err != nil || legacy != "preserved" {
		t.Fatal("legacy data", err)
	}
}
