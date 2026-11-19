package preprodimport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signedFixture(t *testing.T) (Snapshot, []byte, string, []SignedReceipt, map[string]ed25519.PublicKey) {
	t.Helper()
	s, key, stage, _ := fixture(t)
	challenge := testID("a", 64)
	reqs, err := ReceiptRequests(s, key, challenge)
	if err != nil {
		t.Fatal(err)
	}
	receipts := []SignedReceipt{}
	keys := map[string]ed25519.PublicKey{}
	for _, r := range reqs {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "music/album") || strings.Contains(string(raw), "lyrics/") {
			t.Fatal("request exposed logical path")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := SignStaged(context.Background(), stage, r, priv, testOptions())
		if err != nil {
			t.Fatal(err)
		}
		keys[r.TargetID] = pub
		receipts = append(receipts, receipt)
	}
	return s, key, challenge, receipts, keys
}
func TestSignedReceiptsBindEveryRoleButNeverGrantActivation(t *testing.T) {
	s, key, challenge, receipts, keys := signedFixture(t)
	r, err := VerifyReceiptSet(s, key, challenge, receipts, keys, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !r.ValidSignatures || !r.CompleteDeclaredSet || r.SourceAuthenticated || r.SnapshotConsistent || r.RuntimeReady {
		t.Fatalf("receipt overclaimed authority: %+v", r)
	}
}
func TestSignedReceiptsRejectTamperingReplayAndIncompleteSets(t *testing.T) {
	for _, name := range []string{"signature", "challenge", "missing role", "duplicate role", "duplicate signer", "expired", "changed item"} {
		t.Run(name, func(t *testing.T) {
			s, key, challenge, receipts, keys := signedFixture(t)
			now := time.Now()
			switch name {
			case "signature":
				receipts[0].Signature[0] ^= 1
			case "challenge":
				challenge = testID("b", 64)
			case "missing role":
				receipts = receipts[:2]
			case "duplicate role":
				receipts[1] = receipts[0]
			case "duplicate signer":
				keys[receipts[1].Body.Request.TargetID] = keys[receipts[0].Body.Request.TargetID]
			case "expired":
				now = now.Add(6 * time.Minute)
			case "changed item":
				receipts[0].Body.Request.Items[0].Size++
			}
			if _, err := VerifyReceiptSet(s, key, challenge, receipts, keys, now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted %s: %v", name, err)
			}
		})
	}
}
func TestReceiptRejectsExtraStageBytesAndBusyLock(t *testing.T) {
	s, key, stage, _ := fixture(t)
	reqs, err := ReceiptRequests(s, key, testID("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(stage, "master", "objects", testID("f", 64)+".blob")
	if err = os.WriteFile(extra, []byte("unowned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = SignStaged(context.Background(), stage, reqs[0], priv, testOptions()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted extra file: %v", err)
	}
	if err = os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(stage, "master", "partial", "leftover.part")
	if err = os.WriteFile(part, []byte("unfinished"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = SignStaged(context.Background(), stage, reqs[0], priv, testOptions()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted partial stage: %v", err)
	}
	if err = os.Remove(part); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(stage, "master", ".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = lockStage(f); err != nil {
		t.Fatal(err)
	}
	if _, err = SignStaged(context.Background(), stage, reqs[0], priv, testOptions()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted active stage writer: %v", err)
	}
}

func TestEmptyRoleStillRejectsSymlinkedObjectsDirectory(t *testing.T) {
	s, key, stage, _ := fixture(t)
	reqs, err := ReceiptRequests(s, key, testID("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	roleDir := filepath.Join(stage, "relay")
	original := filepath.Join(roleDir, "objects")
	renamed := filepath.Join(roleDir, "empty")
	if err = os.Rename(original, renamed); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("empty", original); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = SignStaged(context.Background(), stage, reqs[2], priv, testOptions()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty symlinked role accepted: %v", err)
	}
}
