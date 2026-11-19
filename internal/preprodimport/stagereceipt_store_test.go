package preprodimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSyntheticStageEvidencePersistsPinnedReceiptSet(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "stage.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE preprod_stage_evidence(evidence_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{42}, 32)
	now := time.Unix(2000000000, 0)
	expected := map[string]stageReceiptRequest{}
	receipts := map[string]signedStageReceipt{}
	pins := map[string]ed25519.PublicKey{}
	for i, role := range []string{"master", "direct", "relay"} {
		owner := strings.Repeat(string('1'+rune(i)), 32)
		r := stageReceiptRequest{Version: 1, Role: role, OwnerID: owner, MasterID: strings.Repeat("1", 32), Generation: strings.Repeat("a", 64), PlanDigest: strings.Repeat("b", 64), Challenge: strings.Repeat(string('4'+rune(i)), 64), Items: []stageReceiptItem{{StageID: strings.Repeat(string('7'+rune(i)), 64), Size: 1, SHA256: strings.Repeat("c", 64)}}}
		expected[role] = r
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pins[role] = pub
		body := stageReceiptBody{Request: r, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(5 * time.Minute).Unix()}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		receipts[role] = signedStageReceipt{Body: body, Signature: ed25519.Sign(priv, append([]byte("frontiercloud:preprod-stage-receipt:v2\x00"), raw...))}
	}
	if err = saveStageEvidence(ctx, db, root, expected, receipts, pins, now); err != nil {
		t.Fatal(err)
	}
	if err = saveStageEvidence(ctx, db, root, expected, receipts, pins, now.Add(time.Second)); err != nil {
		t.Fatalf("identical retry: %v", err)
	}
	got, err := loadStageEvidence(ctx, db, root, expected, pins)
	if err != nil || got.AcceptedUnix != now.Unix() || len(got.Receipts) != 3 {
		t.Fatalf("load: %+v %v", got, err)
	}
	wrongPins := map[string]ed25519.PublicKey{}
	for k, v := range pins {
		wrongPins[k] = v
	}
	wrongPins["relay"] = pins["direct"]
	if _, err = loadStageEvidence(ctx, db, root, expected, wrongPins); err == nil {
		t.Fatal("changed owner pin accepted")
	}
	if _, err = loadStageEvidence(ctx, db, bytes.Repeat([]byte{43}, 32), expected, pins); err == nil {
		t.Fatal("wrong root accepted")
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{expected["master"].Items[0].StageID, expected["direct"].Challenge, expected["relay"].OwnerID} {
		if bytes.Contains(disk, []byte(s)) {
			t.Fatal("stage identity in database plaintext")
		}
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = loadStageEvidence(ctx, db, root, expected, pins); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if _, err = db.Exec(`UPDATE preprod_stage_evidence SET cipher=zeroblob(length(cipher))`); err != nil {
		t.Fatal(err)
	}
	if _, err = loadStageEvidence(ctx, db, root, expected, pins); err == nil {
		t.Fatal("tampered evidence accepted")
	}
}
