//go:build linux && ledger_fixture

package preprodimport

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	_ "modernc.org/sqlite"
)

func TestAuthenticatedSourceIDBatchesIntoFencedTreeResume(t *testing.T) {
	sourceDB := fixtureSQLSource(t, false)
	for i := 0; i < 200; i++ {
		if _, err := sourceDB.Exec(`INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES('recording_lyric',?,?,NULL,1)`, fmt.Sprintf("private-recording-%d", i), fmt.Sprintf("%032x", i+1000)); err != nil {
			t.Fatal(err)
		}
	}
	var seq int
	var name, sourceDBPath string
	if err := sourceDB.QueryRow(`SELECT seq,name,file FROM pragma_database_list WHERE name='main'`).Scan(&seq, &name, &sourceDBPath); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Dir(sourceDBPath)
	if err := os.Chmod(sourceDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sourceDBPath, 0600); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.Encode(bytes.Repeat([]byte{8}, 32))
	sealed, err := v.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	public, err := protocol.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	source, target := strings.Repeat("2", 32), strings.Repeat("3", 32)
	if _, err = sourceDB.Exec(`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,private_key TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err = sourceDB.Exec(`INSERT INTO node_identity VALUES(1,?,'Master',?)`, source, sealed); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	sourceRoot, err := os.OpenRoot(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceRoot.Close()
	now := time.Now().UTC()
	intent := sourceCaptureIntent{Version: 1, Purpose: "frontiercloud:source-capture-intent:v1", CaptureID: strings.Repeat("1", 32), SourceNode: source, TargetNode: target, Challenge: strings.Repeat("4", 64), ScopeDigest: strings.Repeat("5", 64), SourceKeyID: strings.Repeat("6", 64), Receiver: strings.Repeat("7", 64), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(time.Minute).Unix()}
	targetSeed := bytes.Repeat([]byte{29}, 32)
	receiver, err := receiverFromMasterSeed(targetSeed)
	if err != nil {
		t.Fatal(err)
	}
	intent.Receiver = hex.EncodeToString(receiver.PublicKey().Bytes())
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	signed, err := captureSourceStreamV2(ctx, gate, sourceRoot, sourceDir, sourceDBPath, v, intent, public, receiver.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	stage, err := os.Open(filepath.Join(sourceDir, sourceCaptureIntentDir, intent.CaptureID+".stage"))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()

	targetDir := t.TempDir()
	targetDBPath := filepath.Join(targetDir, "target.sqlite")
	treeDB, err := sql.Open("sqlite", targetDBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer treeDB.Close()
	tree, err := sealedtree.New(bytes.Repeat([]byte{41}, 32), bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	targetTree, err := sealedtree.InitializeSQLite(ctx, treeDB, tree, strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	lockDir := t.TempDir()
	if err = os.Chmod(lockDir, 0700); err != nil {
		t.Fatal(err)
	}
	lockRoot, err := os.OpenRoot(lockDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lockRoot.Close()
	if _, err = sealedtree.InitializeFence(ctx, targetTree, lockRoot, lockDir); err != nil {
		t.Fatal(err)
	}
	targetVault, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{30}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	targetPrivate := protocol.Encode(targetSeed)
	targetSealed, err := targetVault.Seal(targetPrivate)
	if err != nil {
		t.Fatal(err)
	}
	targetPublicText, err := protocol.PublicKey(targetPrivate)
	if err != nil {
		t.Fatal(err)
	}
	targetPublic, err := protocol.Decode(targetPublicText)
	if err != nil {
		t.Fatal(err)
	}
	sourcePublic, err := protocol.Decode(public)
	if err != nil {
		t.Fatal(err)
	}
	targetIdentity := store.NodeIdentity{ID: target, Role: "Master", Endpoint: "https://target.invalid", PrivateKey: targetSealed, CreatedAt: 1}
	targetPin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "source-node-v1", SourceNode: source, SourceKeyID: intent.SourceKeyID, SourcePublic: sourcePublic, TargetNode: target, TargetMasterPublic: targetPublic, TargetX25519: receiver.PublicKey().Bytes(), Generation: strings.Repeat("9", 64)}
	pinRaw, err := json.Marshal(targetPin)
	if err != nil {
		t.Fatal(err)
	}
	sealedPin, err := targetVault.Seal(string(pinRaw))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,endpoint TEXT,private_key TEXT,created_at INTEGER)`} {
		if _, err = treeDB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = treeDB.Exec(`INSERT INTO node_identity VALUES(1,?,?,?,?,?)`, targetIdentity.ID, targetIdentity.Role, targetIdentity.Endpoint, targetIdentity.PrivateKey, targetIdentity.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err = treeDB.Exec(`INSERT INTO sealed_tree_source_pin VALUES(1,?)`, sealedPin); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		t.Helper()
		var n int
		if e := treeDB.QueryRow(`SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	stop := errors.New("synthetic interruption")
	precommitReached := false
	err = replayAuthenticatedSourceIDBatches(ctx, signed, intent, public, receiver, stage, func(proof *SourceIDBatch) error {
		view, e := proof.View()
		if e != nil {
			return e
		}
		return targetTree.ApplyHistoricalMediaIDBatch(ctx, view.ManifestDigest, uint64(view.Index), view.Last, view.Digest, view.IDs, func([]string) error { precommitReached = true; return stop })
	})
	if err == nil || !precommitReached || count() != 1 {
		t.Fatal("failed pre-commit proof did not roll back", err, count())
	}
	checkpointCommitted := false
	err = replayAuthenticatedSourceIDBatches(ctx, signed, intent, public, receiver, stage, func(proof *SourceIDBatch) error {
		if e := applySourceIDBatchToTree(ctx, targetTree, proof); e != nil {
			return e
		}
		checkpointCommitted = true
		return stop
	})
	if err == nil || !checkpointCommitted || count() != 261 {
		t.Fatal("interrupted first checkpoint", err, count())
	}
	var stale *SourceIDBatch
	completionReached := false
	err = withAuthenticatedSourceIDCompletion(ctx, signed, intent, public, receiver, stage, func(proof *SourceIDBatch) error {
		return applySourceIDBatchToTree(ctx, targetTree, proof)
	}, func(proof *SourceIDCompletion) error {
		view, e := proof.View()
		if e != nil {
			return e
		}
		return targetTree.CompleteHistoricalMediaIDs(ctx, view.ManifestDigest, uint64(view.BatchCount), view.Empty, view.FinalBatchDigest, func() error { completionReached = true; return stop })
	})
	if err == nil || !completionReached || count() != 346 {
		t.Fatal("completion proof failure did not roll back", err, count())
	}
	expected := historicalSourceScope{SourceNode: source, TargetNode: target, SourceKeyID: intent.SourceKeyID, ScopeDigest: intent.ScopeDigest}
	var staleCompletion *SourceIDCompletion
	for pass := 0; pass < 2; pass++ {
		if err = withAuthenticatedSourceIDCompletion(ctx, signed, intent, public, receiver, stage, func(proof *SourceIDBatch) error {
			stale = proof
			return applySourceIDBatchToTree(ctx, targetTree, proof)
		}, func(proof *SourceIDCompletion) error {
			staleCompletion = proof
			wrong := expected
			wrong.TargetNode = strings.Repeat("a", 32)
			if completeSourceIDsInTree(ctx, targetTree, wrong, proof) == nil {
				return invalid("wrong completion target accepted")
			}
			return completeSourceIDsInTree(ctx, targetTree, expected, proof)
		}); err != nil {
			t.Fatal("authenticated replay", pass, err)
		}
		if count() != 348 { // 337 IDs, source binding, batch, end and completion markers, root.
			t.Fatal("wrong reservation count", count())
		}
	}
	if err = applySourceIDBatchToTree(ctx, targetTree, stale); err == nil {
		t.Fatal("expired batch proof accepted")
	}
	if err = completeSourceIDsInTree(ctx, targetTree, expected, staleCompletion); err == nil {
		t.Fatal("expired completion proof accepted")
	}
	// Synthetic signer exercises the target-side resume contract only; the
	// source-side maintenance/identity-authorized renewal remains separate.
	manifestDigest, err := sourceStreamManifestDigest(signed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	signFor := func(i sourceCaptureIntent) signedSourceStream {
		t.Helper()
		payload := map[string]any{"kind": "frontiercloud-preprod-source-stream-v2", "capture_id": i.CaptureID, "source_node": i.SourceNode, "target_node": i.TargetNode, "challenge": i.Challenge, "scope_sha256": i.ScopeDigest, "sha256": manifestDigest, "expires_unix": i.ExpiresUnix}
		value := signed
		value.Signature, err = protocol.Sign(seed, payload)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	expired := intent
	expired.IssuedUnix, expired.ExpiresUnix = time.Now().Add(-2*time.Minute).Unix(), time.Now().Add(-time.Minute).Unix()
	if verifySourceStreamManifest(signFor(expired), expired, public, receiver.PublicKey().Bytes(), time.Now()) == nil {
		t.Fatal("expired source authority accepted")
	}
	renewed := intent
	renewed.IssuedUnix, renewed.ExpiresUnix = time.Now().Unix(), time.Now().Add(time.Minute).Unix()
	newSignature := signFor(renewed)
	if err = withAuthenticatedSourceIDCompletion(ctx, newSignature, renewed, public, receiver, stage, func(proof *SourceIDBatch) error {
		return applySourceIDBatchToTree(ctx, targetTree, proof)
	}, func(proof *SourceIDCompletion) error {
		return completeSourceIDsInTree(ctx, targetTree, expected, proof)
	}); err != nil || count() != 348 {
		t.Fatal("renewed identical manifest failed target checkpoint replay", err, count())
	}
	if err = os.Chmod(targetDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(targetDBPath, 0600); err != nil {
		t.Fatal(err)
	}
	targetGate, err := maintenance.Open(targetDir)
	if err != nil {
		t.Fatal(err)
	}
	defer targetGate.Close()
	if err = importHistoricalIDsOffline(ctx, targetGate, targetDir, targetDBPath, targetTree, targetVault, targetIdentity, targetPin, intent.ScopeDigest, newSignature, renewed, receiver, stage); err == nil {
		t.Fatal("unguarded target maintenance accepted")
	}
	if err = targetGate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = importHistoricalIDsOffline(ctx, targetGate, targetDir, targetDBPath, targetTree, targetVault, targetIdentity, targetPin, intent.ScopeDigest, newSignature, renewed, receiver, stage); err != nil || count() != 348 {
		t.Fatal("real target maintenance/identity coordinator", err, count())
	}
	wrongIdentity := targetIdentity
	wrongIdentity.ID = strings.Repeat("8", 32)
	if err = importHistoricalIDsOffline(ctx, targetGate, targetDir, targetDBPath, targetTree, targetVault, wrongIdentity, targetPin, intent.ScopeDigest, newSignature, renewed, receiver, stage); err == nil || count() != 348 {
		t.Fatal("wrong actual target identity accepted", err)
	}
	wrongPin := targetPin
	wrongPin.SourceKeyID = strings.Repeat("7", 64)
	if err = importHistoricalIDsOffline(ctx, targetGate, targetDir, targetDBPath, targetTree, targetVault, targetIdentity, wrongPin, intent.ScopeDigest, newSignature, renewed, receiver, stage); err == nil || count() != 348 {
		t.Fatal("wrong target source pin accepted", err)
	}
	// A second fresh target proves guarded replay actually writes new reservations,
	// rather than exercising only the idempotent checkpoint path above.
	freshDir := t.TempDir()
	freshPath := filepath.Join(freshDir, "target.sqlite")
	freshDB, err := sql.Open("sqlite", freshPath)
	if err != nil {
		t.Fatal(err)
	}
	defer freshDB.Close()
	freshTreeKey, err := sealedtree.New(bytes.Repeat([]byte{51}, 32), bytes.Repeat([]byte{52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	freshTree, err := sealedtree.InitializeSQLite(ctx, freshDB, freshTreeKey, strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	freshLockDir := t.TempDir()
	if err = os.Chmod(freshLockDir, 0700); err != nil {
		t.Fatal(err)
	}
	freshLockRoot, err := os.OpenRoot(freshLockDir)
	if err != nil {
		t.Fatal(err)
	}
	defer freshLockRoot.Close()
	if _, err = sealedtree.InitializeFence(ctx, freshTree, freshLockRoot, freshLockDir); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,endpoint TEXT,private_key TEXT,created_at INTEGER)`} {
		if _, err = freshDB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = freshDB.Exec(`INSERT INTO node_identity VALUES(1,?,?,?,?,?)`, targetIdentity.ID, targetIdentity.Role, targetIdentity.Endpoint, targetIdentity.PrivateKey, targetIdentity.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err = freshDB.Exec(`INSERT INTO sealed_tree_source_pin VALUES(1,?)`, sealedPin); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(freshDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(freshPath, 0600); err != nil {
		t.Fatal(err)
	}
	freshGate, err := maintenance.Open(freshDir)
	if err != nil {
		t.Fatal(err)
	}
	defer freshGate.Close()
	if err = freshGate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	freshCount := func() int {
		var n int
		if e := freshDB.QueryRow(`SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	if err = importHistoricalIDsOffline(ctx, freshGate, freshDir, freshPath, freshTree, targetVault, wrongIdentity, targetPin, intent.ScopeDigest, newSignature, renewed, receiver, stage); err == nil || freshCount() != 1 {
		t.Fatal("wrong target caused writes", err, freshCount())
	}
	if err = importHistoricalIDsOffline(ctx, freshGate, freshDir, freshPath, freshTree, targetVault, targetIdentity, targetPin, intent.ScopeDigest, newSignature, renewed, receiver, stage); err != nil || freshCount() != 348 {
		t.Fatal("guarded new target import", err, freshCount())
	}
}
