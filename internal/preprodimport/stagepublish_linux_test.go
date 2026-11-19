//go:build linux

package preprodimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestSyntheticOwnerPublishesStagedBlobAndRecovers(t *testing.T) {
	ctx := context.Background()
	stage := t.TempDir()
	owner := t.TempDir()
	for _, p := range []string{stage, owner} {
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(stage, "direct"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(stage, "direct/objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("isolated synthetic stage bytes")
	stageID := strings.Repeat("1", 64)
	source := filepath.Join(stage, "direct/objects", stageID+".blob")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000000000, 0)
	request := stagePublishRequest{Version: 1, MasterID: strings.Repeat("2", 32), OwnerID: strings.Repeat("3", 32), Role: "direct", Generation: strings.Repeat("4", 64), PlanDigest: strings.Repeat("5", 64), OperationID: strings.Repeat("6", 64), StageID: stageID, BlobID: strings.Repeat("7", 64), SHA256: digest(data), Challenge: strings.Repeat("8", 64), Size: int64(len(data)), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(3 * time.Minute).Unix()}
	masterPub, masterKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ownerPub, ownerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signSyntheticStagePublishRequest(request, masterKey, now)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{MaxBytesPerSecond: 4 * 1024 * 1024, Progress: func(Event) error { return nil }}
	journalDir := t.TempDir()
	if err = os.Chmod(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(journalDir, "owner-intents.sqlite")
	journal, err := sql.Open("sqlite", journalPath)
	journalKey := bytes.Repeat([]byte{44}, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if _, err = journal.Exec(`CREATE TABLE preprod_owner_publish_intents(operation_id TEXT PRIMARY KEY,blob_id TEXT NOT NULL UNIQUE,binding TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Exec(`CREATE TABLE preprod_owner_publish_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Exec(`CREATE TABLE preprod_owner_publish_authorizations(challenge_tag TEXT PRIMARY KEY,operation_id TEXT NOT NULL,authorization TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Exec(`INSERT INTO preprod_owner_publish_meta(singleton,verifier) VALUES(1,?)`, vaultTag(journalKey, "stage-journal-verifier", "v1")); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(journalPath, 0o600); err != nil {
		t.Fatal(err)
	}
	nestedOwner := filepath.Join(stage, "nested-owner")
	if err = os.Mkdir(nestedOwner, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, nestedOwner, journal, journalKey, signed, request, masterPub, ownerKey, opts, now); err == nil {
		t.Fatal("owner nested under stage accepted")
	}
	nestedStage := filepath.Join(owner, "nested-stage")
	if err = os.Mkdir(nestedStage, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err = publishSyntheticStagedBlob(ctx, nestedStage, owner, journal, journalKey, signed, request, masterPub, ownerKey, opts, now); err == nil {
		t.Fatal("stage nested under owner accepted")
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, signed, request, other, ownerKey, opts, now); err == nil {
		t.Fatal("untrusted master accepted")
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, bytes.Repeat([]byte{45}, 32), signed, request, masterPub, ownerKey, opts, now); err == nil {
		t.Fatal("wrong journal key accepted")
	}
	if _, err = journal.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		t.Fatal(err)
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, signed, request, masterPub, ownerKey, opts, now); err == nil {
		t.Fatal("weak journal sync accepted")
	}
	if _, err = journal.Exec(`PRAGMA synchronous=FULL`); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(journalPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, signed, request, masterPub, ownerKey, opts, now); err == nil {
		t.Fatal("public journal file accepted")
	}
	if err = os.Chmod(journalPath, 0o600); err != nil {
		t.Fatal(err)
	}
	interrupted := opts
	interrupted.Progress = func(event Event) error {
		if event.Kind == "stage_blob_linked" {
			return errors.New("synthetic interruption after link")
		}
		return nil
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, signed, request, masterPub, ownerKey, interrupted, now); err == nil {
		t.Fatal("link interruption ignored")
	}
	beforeSync := opts
	beforeSync.Progress = func(event Event) error {
		if event.Kind == "stage_blob_unlinked_before_sync" {
			return errors.New("synthetic interruption before directory sync")
		}
		return nil
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, signed, request, masterPub, ownerKey, beforeSync, now); err == nil {
		t.Fatal("pre-sync interruption ignored")
	}
	receipt, err := publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, signed, request, masterPub, ownerKey, opts, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyStagePublishReceipt(receipt, request, ownerPub, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = verifyStagePublishReceipt(receipt, request, other, now.Add(time.Second)); err == nil {
		t.Fatal("untrusted owner accepted")
	}
	t.Run("empty source has an authenticated empty digest", func(t *testing.T) {
		empty := request
		empty.StageID = strings.Repeat("c", 64)
		empty.BlobID = strings.Repeat("d", 64)
		empty.OperationID = strings.Repeat("e", 64)
		empty.Challenge = strings.Repeat("f", 64)
		empty.Size = 0
		empty.SHA256 = digest(nil)
		if err := os.WriteFile(filepath.Join(stage, "direct/objects", empty.StageID+".blob"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		auth, err := signSyntheticStagePublishRequest(empty, masterKey, now)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, auth, empty, masterPub, ownerKey, opts, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyStagePublishReceipt(proof, empty, ownerPub, now); err != nil {
			t.Fatal(err)
		}
		location, err := sealedtree.BlobPath(empty.BlobID)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := os.ReadFile(filepath.Join(owner, filepath.FromSlash(location)))
		if err != nil || len(blob) != 0 || digest(blob) != empty.SHA256 {
			t.Fatalf("empty final blob: %v", err)
		}
	})
	rel, err := sealedtree.BlobPath(request.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(owner, filepath.FromSlash(rel)))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("final bytes: %v", err)
	}
	info, err := os.Stat(filepath.Join(owner, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	links, ok := stagePublishLinkCount(info)
	if !ok || links != 1 {
		t.Fatal("final blob retains staging hard link")
	}
	if _, err = os.Lstat(filepath.Join(owner, "staging", request.OperationID+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staging link remains")
	}
	got, err = os.ReadFile(source)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("stage source removed or changed")
	}
	afterUnlink := opts
	afterUnlink.Progress = func(event Event) error {
		if event.Kind == "stage_blob_finalized" {
			return errors.New("synthetic interruption after unlink")
		}
		return nil
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, signed, request, masterPub, ownerKey, afterUnlink, now); err == nil {
		t.Fatal("unlink interruption ignored")
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, signed, request, masterPub, ownerKey, opts, now.Add(time.Second)); err != nil {
		t.Fatalf("idempotent recovery: %v", err)
	}
	renewed := request
	renewed.IssuedUnix = now.Add(4 * time.Minute).Unix()
	renewed.ExpiresUnix = now.Add(7 * time.Minute).Unix()
	renewed.PlanDigest = strings.Repeat("b", 64)
	renewed.Challenge = strings.Repeat("a", 64)
	renewedSigned, err := signSyntheticStagePublishRequest(renewed, masterKey, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, renewedSigned, renewed, masterPub, ownerKey, opts, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("renewed same intent: %v", err)
	}
	replayed := renewed
	replayed.PlanDigest = strings.Repeat("c", 64)
	replayedSigned, err := signSyntheticStagePublishRequest(replayed, masterKey, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, replayedSigned, replayed, masterPub, ownerKey, opts, now.Add(4*time.Minute)); err == nil {
		t.Fatal("challenge reuse with changed authorization accepted")
	}
	changedGeneration := renewed
	changedGeneration.Generation = strings.Repeat("d", 64)
	changedGeneration.Challenge = strings.Repeat("b", 64)
	changedSigned, err := signSyntheticStagePublishRequest(changedGeneration, masterKey, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, changedSigned, changedGeneration, masterPub, ownerKey, opts, now.Add(4*time.Minute)); err == nil {
		t.Fatal("changed generation reused existing intent")
	}
	otherOperation := request
	otherOperation.OperationID = strings.Repeat("9", 64)
	otherSigned, err := signSyntheticStagePublishRequest(otherOperation, masterKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, otherSigned, otherOperation, masterPub, ownerKey, opts, now); err == nil {
		t.Fatal("second operation reused a blob")
	}
	var operationTag, blobTag string
	if err = journal.QueryRow(`SELECT operation_id,blob_id FROM preprod_owner_publish_intents`).Scan(&operationTag, &blobTag); err != nil {
		t.Fatal(err)
	}
	if operationTag == request.OperationID || blobTag == request.BlobID {
		t.Fatal("journal stored raw operation or blob identifiers")
	}
	changed := request
	changed.BlobID = strings.Repeat("9", 64)
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, signed, changed, masterPub, ownerKey, opts, now); err == nil {
		t.Fatal("destination substitution accepted")
	}
	if err = os.WriteFile(filepath.Join(owner, filepath.FromSlash(rel)), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = publishSyntheticStagedBlob(ctx, stage, owner, journal, journalKey, signed, request, masterPub, ownerKey, opts, now); err == nil {
		t.Fatal("corrupt existing blob accepted")
	}
}

// Separate processes exit immediately at durable boundaries; no real media,
// production identity or deployed service participates in this fixture.
func TestSyntheticOwnerPublishSurvivesProcessExit(t *testing.T) {
	const rootEnv = "FRONTIERCLOUD_SYNTH_STAGE_CRASH_ROOT"
	const phaseEnv = "FRONTIERCLOUD_SYNTH_STAGE_CRASH_PHASE"
	data := []byte("synthetic process-exit fixture")
	now := time.Unix(2000000000, 0)
	request := stagePublishRequest{Version: 1, MasterID: strings.Repeat("2", 32), OwnerID: strings.Repeat("3", 32), Role: "direct", Generation: strings.Repeat("4", 64), PlanDigest: strings.Repeat("5", 64), OperationID: strings.Repeat("6", 64), StageID: strings.Repeat("1", 64), BlobID: strings.Repeat("7", 64), SHA256: digest(data), Challenge: strings.Repeat("8", 64), Size: int64(len(data)), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(3 * time.Minute).Unix()}
	journalKey := bytes.Repeat([]byte{53}, 32)
	masterKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, 32))
	ownerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{52}, 32))
	signed, err := signSyntheticStagePublishRequest(request, masterKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if base := os.Getenv(rootEnv); base != "" {
		journal, err := sql.Open("sqlite", filepath.Join(base, "journal", "intents.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		defer journal.Close()
		phase := os.Getenv(phaseEnv)
		opts := Options{MaxBytesPerSecond: 4 * 1024 * 1024, Progress: func(e Event) error {
			if phase == "after-link" && e.Kind == "stage_blob_linked" {
				os.Exit(73)
			}
			if phase == "before-sync" && e.Kind == "stage_blob_unlinked_before_sync" {
				os.Exit(74)
			}
			return nil
		}}
		if _, err = publishSyntheticStagedBlob(context.Background(), filepath.Join(base, "stage"), filepath.Join(base, "owner"), journal, journalKey, signed, request, masterKey.Public().(ed25519.PublicKey), ownerKey, opts, now); err != nil {
			t.Fatal(err)
		}
		if phase != "finish" {
			t.Fatal("expected crash boundary not reached")
		}
		return
	}
	base := t.TempDir()
	for _, d := range []string{"stage", "stage/direct", "stage/direct/objects", "owner", "journal"} {
		if err = os.Mkdir(filepath.Join(base, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(filepath.Join(base, "stage/direct/objects", request.StageID+".blob"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(base, "journal/intents.sqlite")
	journal, err := sql.Open("sqlite", journalPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"PRAGMA synchronous=FULL", `CREATE TABLE preprod_owner_publish_intents(operation_id TEXT PRIMARY KEY,blob_id TEXT NOT NULL UNIQUE,binding TEXT NOT NULL)`, `CREATE TABLE preprod_owner_publish_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)`, `CREATE TABLE preprod_owner_publish_authorizations(challenge_tag TEXT PRIMARY KEY,operation_id TEXT NOT NULL,authorization TEXT NOT NULL)`} {
		if _, err = journal.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = journal.Exec(`INSERT INTO preprod_owner_publish_meta(singleton,verifier) VALUES(1,?)`, vaultTag(journalKey, "stage-journal-verifier", "v1")); err != nil {
		t.Fatal(err)
	}
	if err = journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(journalPath, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		phase string
		exit  int
	}{{"after-link", 73}, {"before-sync", 74}, {"finish", 0}} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSyntheticOwnerPublishSurvivesProcessExit$")
		cmd.Env = append(os.Environ(), rootEnv+"="+base, phaseEnv+"="+step.phase)
		output, err := cmd.CombinedOutput()
		if step.exit == 0 {
			if err != nil {
				t.Fatalf("%s: %v %s", step.phase, err, output)
			}
		} else {
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != step.exit {
				t.Fatalf("%s: %v %s", step.phase, err, output)
			}
		}
	}
	rel, err := sealedtree.BlobPath(request.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(base, "owner", filepath.FromSlash(rel))
	got, err := os.ReadFile(final)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("recovered final: %v", err)
	}
	info, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	links, ok := stagePublishLinkCount(info)
	if !ok || links != 1 {
		t.Fatal("recovered blob has extra link")
	}
	if _, err = os.Lstat(filepath.Join(base, "owner/staging", request.OperationID+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovered staging link remains")
	}
}
