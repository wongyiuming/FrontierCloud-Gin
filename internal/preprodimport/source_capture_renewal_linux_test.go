//go:build linux && ledger_fixture

package preprodimport

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
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
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	_ "modernc.org/sqlite"
)

func TestSourceRenewalRetainsAuthenticatedCheckpoint(t *testing.T) {
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
	intent := sourceCaptureIntent{Version: 1, Purpose: "frontiercloud:source-capture-intent:v1", CaptureID: strings.Repeat("1", 32), SourceNode: source, TargetNode: target, Challenge: strings.Repeat("4", 64), ScopeDigest: strings.Repeat("5", 64), SourceKeyID: strings.Repeat("6", 64), Receiver: strings.Repeat("7", 64), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(8 * time.Second).Unix()}
	receiver, err := ecdh.X25519().GenerateKey(rand.Reader)
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

	treeDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "target.sqlite"))
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
	originalIntent, originalSigned := intent, signed
	if wait := time.Until(time.Unix(intent.ExpiresUnix, 0)); wait > 0 {
		time.Sleep(wait + 50*time.Millisecond)
	}
	if verifySourceStreamManifest(originalSigned, originalIntent, public, receiver.PublicKey().Bytes(), time.Now()) == nil {
		t.Fatal("old signature remains valid")
	}
	started := time.Now()
	freshIntent, freshSigned, freshStage, e := renewCapturedSourceStreamV2(ctx, gate, sourceRoot, sourceDir, sourceDBPath, v, originalIntent, public, receiver.PublicKey().Bytes(), time.Minute)
	if e != nil {
		t.Fatal("renewal failed", e)
	}
	defer freshStage.Close()
	t.Logf("synthetic renewal wall time %s (does not establish production timing)", time.Since(started))
	oldDigest, _ := sourceStreamManifestDigest(originalSigned.Manifest)
	newDigest, _ := sourceStreamManifestDigest(freshSigned.Manifest)
	if oldDigest != newDigest || freshIntent.ExpiresUnix <= originalIntent.ExpiresUnix {
		t.Fatal("manifest changed or expiry not renewed")
	}
	stored, e := readSourceCaptureIntent(sourceRoot, v)
	if e != nil || stored != originalIntent {
		t.Fatal("original intent overwritten", e)
	}
	intent, signed, stage = freshIntent, freshSigned, freshStage
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
	if _, e := sourceDB.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('changed','media','music/changed.mp3','changed','1','1')`); e != nil {
		t.Fatal(e)
	}
	if _, _, fd, e := renewCapturedSourceStreamV2(ctx, gate, sourceRoot, sourceDir, sourceDBPath, v, originalIntent, public, receiver.PublicKey().Bytes(), time.Minute); e == nil {
		fd.Close()
		t.Fatal("changed source accepted")
	}
	if _, _, fd, e := renewCapturedSourceStreamV2(ctx, gate, sourceRoot, sourceDir, sourceDBPath, v, originalIntent, public, bytes.Repeat([]byte{1}, 32), time.Minute); e == nil {
		fd.Close()
		t.Fatal("wrong receiver accepted")
	}
	cancelled, done := context.WithCancel(context.Background())
	done()
	if _, _, fd, e := renewCapturedSourceStreamV2(cancelled, gate, sourceRoot, sourceDir, sourceDBPath, v, originalIntent, public, receiver.PublicKey().Bytes(), time.Minute); e == nil {
		fd.Close()
		t.Fatal("cancelled renewal accepted")
	}
}
