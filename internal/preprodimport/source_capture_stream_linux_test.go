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
)

func TestSourceCaptureStreamV2RealVaultTargetKeyAndTampering(t *testing.T) {
	db := fixtureSQLSource(t, false)
	retiredRecordingID := strings.Repeat("f", 32)
	if _, err := db.Exec(`INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES('recording_lyric','private-recording-object',?,NULL,1)`, retiredRecordingID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if _, err := db.Exec(`INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES('recording_lyric',?,?,NULL,1)`, fmt.Sprintf("recording-private-%d", i), fmt.Sprintf("%032x", i+1000)); err != nil {
			t.Fatal(err)
		}
	}
	var sequence int
	var name, path string
	if err := db.QueryRow(`SELECT seq,name,file FROM pragma_database_list WHERE name='main'`).Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	data := filepath.Dir(path)
	if err := os.Chmod(data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
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
	if _, err = db.Exec(`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,private_key TEXT)`); err != nil {
		t.Fatal(err)
	}
	source, target := strings.Repeat("2", 32), strings.Repeat("3", 32)
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master',?)`, source, sealed); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	now := time.Now().UTC()
	intent := sourceCaptureIntent{Version: 1, Purpose: "frontiercloud:source-capture-intent:v1", CaptureID: strings.Repeat("1", 32), SourceNode: source, TargetNode: target, Challenge: strings.Repeat("4", 64), ScopeDigest: strings.Repeat("5", 64), SourceKeyID: strings.Repeat("6", 64), Receiver: strings.Repeat("7", 64), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(time.Minute).Unix()}
	receiver, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intent.Receiver = hex.EncodeToString(receiver.PublicKey().Bytes())
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	wrongKeyIntent := intent
	wrongKeyIntent.SourceKeyID = strings.Repeat("8", 64)
	if _, err = captureSourceStreamV2(ctx, gate, root, data, path, v, wrongKeyIntent, public, receiver.PublicKey().Bytes()); err == nil {
		t.Fatal("wrong source media key identity accepted")
	}
	otherReceiver, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = captureSourceStreamV2(ctx, gate, root, data, path, v, intent, public, otherReceiver.PublicKey().Bytes()); err == nil {
		t.Fatal("wrong receiver scope accepted")
	}
	signed, err := captureSourceStreamV2(ctx, gate, root, data, path, v, intent, public, receiver.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err = verifySourceStreamManifest(signed, intent, public, receiver.PublicKey().Bytes(), time.Now()); err != nil {
		t.Fatal(err)
	}
	reopened, recoveredStage, err := reopenCapturedSourceStream(ctx, root, v, intent, public, receiver.PublicKey().Bytes(), time.Now())
	if err != nil || reopened.Signature != signed.Signature {
		t.Fatal("completed capture did not reopen", err)
	}
	if err = recoveredStage.Close(); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(data, sourceCaptureIntentDir, intent.CaptureID+".manifest")
	sealedManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealedManifest, []byte("source_node")) {
		t.Fatal("manifest was not encrypted")
	}
	brokenManifest := append([]byte(nil), sealedManifest...)
	brokenManifest[len(brokenManifest)/2] ^= 1
	if err = os.WriteFile(manifestPath, brokenManifest, 0600); err != nil {
		t.Fatal(err)
	}
	if _, f, e := reopenCapturedSourceStream(ctx, root, v, intent, public, receiver.PublicKey().Bytes(), time.Now()); e == nil {
		f.Close()
		t.Fatal("tampered persisted manifest accepted")
	}
	if err = os.WriteFile(manifestPath, sealedManifest, 0600); err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join(data, sourceCaptureIntentDir, intent.CaptureID+".stage")
	stage, err := os.Open(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if err = validateCapturedSourceStreamV2(ctx, signed, intent, public, receiver, stage, time.Now()); err != nil {
		t.Fatal("complete receiver verification", err)
	}
	var views []SourceIDBatchView
	var stale *SourceIDBatch
	err = replayAuthenticatedSourceIDBatches(ctx, signed, intent, public, receiver, stage, func(batch *SourceIDBatch) error {
		view, e := batch.View()
		if e != nil {
			return e
		}
		if len(view.IDs) == 0 || len(view.IDs) > 256 {
			return invalid("fixture batch bounds")
		}
		if e = batch.CheckForCommit(view.IDs[:len(view.IDs)-1]); e == nil {
			return invalid("changed batch accepted")
		}
		if e = batch.CheckForCommit(view.IDs); e != nil {
			return e
		}
		views = append(views, view)
		stale = batch
		return nil
	})
	if err != nil || len(views) != 2 || views[0].Index != 0 || views[0].Last || len(views[0].IDs) != 256 || views[1].Index != 1 || !views[1].Last || len(views[1].IDs) != 82 || views[0].IDs[255] >= views[1].IDs[0] {
		t.Fatal("authenticated ID batch sequence", err)
	}
	if _, err = stale.View(); err == nil {
		t.Fatal("ID batch survived callback")
	}
	var completion *SourceIDCompletion
	err = withAuthenticatedSourceIDCompletion(ctx, signed, intent, public, receiver, stage, func(batch *SourceIDBatch) error {
		view, e := batch.View()
		if e != nil {
			return e
		}
		return batch.CheckForCommit(view.IDs)
	}, func(proof *SourceIDCompletion) error {
		view, e := proof.View()
		if e != nil {
			return e
		}
		if view.IDCount != 338 || view.BatchCount != 2 || view.Empty || !id64.MatchString(view.FinalBatchDigest) {
			return invalid("completion scope")
		}
		modified := view
		modified.IDCount--
		if e = proof.CheckForCommit(modified); e == nil {
			return invalid("changed completion accepted")
		}
		if e = proof.CheckForCommit(view); e != nil {
			return e
		}
		completion = proof
		return nil
	})
	if err != nil {
		t.Fatal("authenticated completion", err)
	}
	if _, err = completion.View(); err == nil {
		t.Fatal("completion survived callback")
	}
	finished := false
	err = withAuthenticatedSourceIDCompletion(ctx, signed, intent, public, receiver, stage, func(*SourceIDBatch) error { return invalid("batch failed") }, func(*SourceIDCompletion) error { finished = true; return nil })
	if err == nil || finished {
		t.Fatal("completion emitted after batch failure", err)
	}
	called := 0
	stop := errors.New("synthetic target failure")
	err = replayAuthenticatedSourceIDBatches(ctx, signed, intent, public, receiver, stage, func(batch *SourceIDBatch) error { called++; return stop })
	if !errors.Is(err, stop) || called != 1 {
		t.Fatal("failed target batch did not stop replay", err)
	}
	plainBytes, err := hex.DecodeString(signed.Manifest.PlainSHA256)
	if err != nil {
		t.Fatal(err)
	}
	cipherBytes, err := hex.DecodeString(signed.Manifest.CipherSHA256)
	if err != nil {
		t.Fatal(err)
	}
	var plainDigest, cipherDigest [32]byte
	copy(plainDigest[:], plainBytes)
	copy(cipherDigest[:], cipherBytes)
	var output bytes.Buffer
	if err = openSourceStreamV2(ctx, signed.Manifest.Header, receiver, stage, &output, plainDigest, cipherDigest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte("music/秘密/track-0000.mp3")) {
		t.Fatal("complete plaintext rows missing")
	}
	if !bytes.Contains(output.Bytes(), []byte(retiredRecordingID)) || bytes.Contains(output.Bytes(), []byte("private-recording-object")) {
		t.Fatal("recording tombstone ID missing or private recording metadata exported")
	}
	if last := signed.Manifest.Sections[len(signed.Manifest.Sections)-1]; last.Name != "encryption_ids" || last.Rows != 338 {
		t.Fatal("reserved ID scope incomplete", last)
	}
	if err = verifySourceRowsV2(ctx, bytes.NewReader(output.Bytes()), signed.Manifest.Header.PlainSize, signed.Manifest.Sections, intent.SourceKeyID); err != nil {
		t.Fatal("source frame validation", err)
	}
	if err = verifySourceRowsV2(ctx, bytes.NewReader(output.Bytes()), signed.Manifest.Header.PlainSize, signed.Manifest.Sections, strings.Repeat("8", 64)); err == nil {
		t.Fatal("wrong media key identity accepted by frame verifier")
	}
	if err = verifySourceRowsV2(ctx, bytes.NewReader(output.Bytes()[:len(output.Bytes())-1]), signed.Manifest.Header.PlainSize, signed.Manifest.Sections, intent.SourceKeyID); err == nil {
		t.Fatal("truncated frames accepted")
	}
	mutatedFrames := append([]byte(nil), output.Bytes()...)
	mutatedFrames[len(mutatedFrames)/2] ^= 1
	if err = verifySourceRowsV2(ctx, bytes.NewReader(mutatedFrames), int64(len(mutatedFrames)), signed.Manifest.Sections, intent.SourceKeyID); err == nil {
		t.Fatal("modified frames accepted")
	}
	ciphertext, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("music/秘密")) {
		t.Fatal("path leaked to encrypted stage")
	}
	wrong, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = openSourceStreamV2(ctx, signed.Manifest.Header, wrong, stage, &bytes.Buffer{}, plainDigest, cipherDigest); err == nil {
		t.Fatal("wrong receiver accepted")
	}
	if err = validateCapturedSourceStreamV2(ctx, signed, intent, public, wrong, stage, time.Now()); err == nil {
		t.Fatal("wrong receiver passed complete verification")
	}
	altered := signed
	altered.Manifest.Header.ScopeDigest = strings.Repeat("6", 64)
	if verifySourceStreamManifest(altered, intent, public, receiver.PublicKey().Bytes(), time.Now()) == nil {
		t.Fatal("changed scope accepted")
	}
	if verifySourceStreamManifest(signed, intent, public, receiver.PublicKey().Bytes(), time.Unix(intent.ExpiresUnix, 0)) == nil {
		t.Fatal("expired manifest accepted")
	}
	if _, err = captureSourceStreamV2(ctx, gate, root, data, path, v, intent, public, receiver.PublicKey().Bytes()); err == nil {
		t.Fatal("intent replay accepted")
	}
	if err = stage.Close(); err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)/2] ^= 1
	if err = os.WriteFile(stagePath, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	stage, err = os.Open(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	output.Reset()
	if err = validateCapturedSourceStreamV2(ctx, signed, intent, public, receiver, stage, time.Now()); err == nil {
		t.Fatal("corrupted stage passed complete verification")
	}
	if err = openSourceStreamV2(ctx, signed.Manifest.Header, receiver, stage, &output, plainDigest, cipherDigest); err == nil || output.Len() != 0 {
		t.Fatal("tampered ciphertext accepted or exposed", err)
	}
	if _, f, e := reopenCapturedSourceStream(ctx, root, v, intent, public, receiver.PublicKey().Bytes(), time.Now()); e == nil {
		f.Close()
		t.Fatal("tampered stage reopened")
	}
}

func TestSourceIDEmptyProofRequiresCompleteAuthenticatedStream(t *testing.T) {
	db := fixtureSQLSource(t, false)
	if _, err := db.Exec(`DELETE FROM media_encryption`); err != nil {
		t.Fatal(err)
	}
	var sequence int
	var name, path string
	if err := db.QueryRow(`SELECT seq,name,file FROM pragma_database_list WHERE name='main'`).Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	data := filepath.Dir(path)
	if err := os.Chmod(data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.Encode(bytes.Repeat([]byte{8}, 32))
	key, err := v.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	public, err := protocol.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,private_key TEXT)`); err != nil {
		t.Fatal(err)
	}
	source, target := strings.Repeat("2", 32), strings.Repeat("3", 32)
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master',?)`, source, key); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	receiver, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intent := sourceCaptureIntent{Version: 1, Purpose: "frontiercloud:source-capture-intent:v1", CaptureID: strings.Repeat("1", 32), SourceNode: source, TargetNode: target, SourceKeyID: strings.Repeat("6", 64), Receiver: hex.EncodeToString(receiver.PublicKey().Bytes()), Challenge: strings.Repeat("4", 64), ScopeDigest: strings.Repeat("5", 64), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(time.Minute).Unix()}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	signed, err := captureSourceStreamV2(ctx, gate, root, data, path, v, intent, public, receiver.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	stage, err := os.Open(filepath.Join(data, sourceCaptureIntentDir, intent.CaptureID+".stage"))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	called := 0
	if err = replayAuthenticatedSourceIDBatches(ctx, signed, intent, public, receiver, stage, func(*SourceIDBatch) error { called++; return nil }); err == nil || called != 0 {
		t.Fatal("legacy path accepted empty history", err)
	}
	if err = replayAuthenticatedSourceIDBatchesAllowEmpty(ctx, signed, intent, public, receiver, stage, func(*SourceIDBatch) error { return nil }); err == nil {
		t.Fatal("unchecked empty proof accepted")
	}
	var stale *SourceIDBatch
	err = replayAuthenticatedSourceIDBatchesAllowEmpty(ctx, signed, intent, public, receiver, stage, func(batch *SourceIDBatch) error {
		called++
		view, e := batch.View()
		if e != nil {
			return e
		}
		if view.Index != 0 || !view.Last || len(view.IDs) != 0 {
			return invalid("empty batch scope")
		}
		if e = batch.CheckForCommit(view.IDs); e != nil {
			return e
		}
		stale = batch
		return nil
	})
	if err != nil || called != 1 {
		t.Fatal("empty source proof", err)
	}
	if _, err = stale.View(); err == nil {
		t.Fatal("empty proof survived callback")
	}
	err = withAuthenticatedSourceIDCompletion(ctx, signed, intent, public, receiver, stage, func(batch *SourceIDBatch) error {
		view, e := batch.View()
		if e != nil {
			return e
		}
		return batch.CheckForCommit(view.IDs)
	}, func(proof *SourceIDCompletion) error {
		view, e := proof.View()
		if e != nil {
			return e
		}
		if !view.Empty || view.IDCount != 0 || view.BatchCount != 0 || !id64.MatchString(view.FinalBatchDigest) {
			return invalid("empty completion scope")
		}
		return proof.CheckForCommit(view)
	})
	if err != nil {
		t.Fatal("empty completion proof", err)
	}
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
	initial := count()
	stop := errors.New("synthetic empty precommit failure")
	err = replayAuthenticatedSourceIDBatchesAllowEmpty(ctx, signed, intent, public, receiver, stage, func(proof *SourceIDBatch) error {
		view, e := proof.View()
		if e != nil {
			return e
		}
		return targetTree.ApplyHistoricalMediaIDBatch(ctx, view.ManifestDigest, uint64(view.Index), view.Last, view.Digest, view.IDs, func([]string) error { return stop })
	})
	if err == nil || count() != initial {
		t.Fatal("empty marker failure did not roll back", err)
	}
	for pass := 0; pass < 2; pass++ {
		if err = replayAuthenticatedSourceIDBatchesAllowEmpty(ctx, signed, intent, public, receiver, stage, func(proof *SourceIDBatch) error { return applySourceIDBatchToTree(ctx, targetTree, proof) }); err != nil {
			t.Fatal("empty target replay", pass, err)
		}
		if count() != initial+4 {
			t.Fatal("empty completion marker count changed", count(), initial)
		}
	}
	expectedScope := historicalSourceScope{SourceNode: intent.SourceNode, TargetNode: intent.TargetNode, SourceKeyID: intent.SourceKeyID, ScopeDigest: intent.ScopeDigest}
	wrongScope := expectedScope
	wrongScope.TargetNode = strings.Repeat("8", 32)
	var completionStale *SourceIDCompletion
	complete := func(scope historicalSourceScope) error {
		return withAuthenticatedSourceIDCompletion(ctx, signed, intent, public, receiver, stage,
			func(proof *SourceIDBatch) error { return applySourceIDBatchToTree(ctx, targetTree, proof) },
			func(proof *SourceIDCompletion) error {
				completionStale = proof
				return completeSourceIDsInTree(ctx, targetTree, scope, proof)
			})
	}
	if err = complete(wrongScope); err == nil || count() != initial+4 {
		t.Fatal("wrong scope changed empty history", err)
	}
	for pass := 0; pass < 2; pass++ {
		if err = complete(expectedScope); err != nil || count() != initial+6 {
			t.Fatal("empty history completion or retry", pass, err, count(), initial)
		}
	}
	if err = completeSourceIDsInTree(ctx, targetTree, expectedScope, completionStale); err == nil {
		t.Fatal("expired empty completion accepted")
	}
	called = 0
	err = replayAuthenticatedSourceIDBatchesAllowEmpty(ctx, signed, intent, public, receiver, stage, func(batch *SourceIDBatch) error {
		called++
		view, e := batch.View()
		if e != nil {
			return e
		}
		future := time.Now().Add(time.Minute)
		if e = os.Chtimes(filepath.Join(data, sourceCaptureIntentDir, intent.CaptureID+".stage"), future, future); e != nil {
			return e
		}
		return batch.CheckForCommit(view.IDs)
	})
	if err == nil || called != 1 {
		t.Fatal("stage mutation did not invalidate empty proof", err)
	}
	modified := signed
	modified.Manifest.Sections = append([]sourceSectionDigest(nil), signed.Manifest.Sections...)
	modified.Manifest.Sections[len(modified.Manifest.Sections)-1].Rows = 1
	called = 0
	if err = replayAuthenticatedSourceIDBatchesAllowEmpty(ctx, modified, intent, public, receiver, stage, func(*SourceIDBatch) error { called++; return nil }); err == nil || called != 0 {
		t.Fatal("unverified empty proof emitted", err)
	}
}
