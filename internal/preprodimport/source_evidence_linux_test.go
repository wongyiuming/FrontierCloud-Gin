//go:build linux

package preprodimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSourceEvidenceEncryptedRecoveryAndFreshRenewal(t *testing.T) {
	ctx := context.Background()
	projection, _, _, _ := fixture(t)
	complete := completeSourceFixture(projection)
	generation, err := completeSnapshotDigest(complete)
	if err != nil {
		t.Fatal(err)
	}
	seed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	receiver, err := receiverFromMasterSeed(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "ssh-collector-v1", SourceSSHHostKeySHA256: strings.Repeat("a", 64), SourceTLSOrigin: "https://source.test", SourceTLSSPKISHA256: strings.Repeat("b", 64), SourceNode: projection.Mappings[0].SourceID, SourceKeyID: projection.PremasterKeyID, SourcePublic: seed.Public().(ed25519.PublicKey), TargetNode: projection.Mappings[0].TargetID, TargetMasterPublic: bytes.Repeat([]byte{6}, 32), TargetX25519: receiver.PublicKey().Bytes(), Generation: generation}
	pin.ImportScope = syntheticImportScope(projection)
	for _, m := range projection.Mappings {
		pin.SourceOwners = append(pin.SourceOwners, sourceOwnerPin{NodeID: m.SourceID, SSHHostKeySHA256: pin.SourceSSHHostKeySHA256})
	}
	base := time.Now().UTC().Truncate(time.Second)
	makeEnvelope := func(challenge string, issued time.Time, change bool) store.EncryptedMediaSourceSnapshot {
		source := syntheticSourceForComplete(complete)
		source.Version = 1
		source.AuthorityKind = pin.AuthorityKind
		source.SourceSSHHostKeySHA256 = pin.SourceSSHHostKeySHA256
		source.SourceNode = pin.SourceNode
		source.SourcePublic = protocol.Encode(pin.SourcePublic)
		source.TargetNode = pin.TargetNode
		source.TargetReceiver = pin.TargetX25519
		source.Challenge = challenge
		source.IssuedUnix = issued.Unix()
		source.ExpiresUnix = issued.Add(3 * time.Minute).Unix()
		if change {
			*source.Sections[6].Rows[0][9] = "offline"
		}
		raw, e := json.Marshal(source)
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(raw)
		sig, e := protocol.Sign(protocol.Encode(seed.Seed()), map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hex.EncodeToString(h[:]), "source_node": source.SourceNode, "target_node": source.TargetNode, "challenge": challenge})
		if e != nil {
			t.Fatal(e)
		}
		envelope, e := snapshotcrypt.Seal(store.SignedMediaSourceSnapshot{Snapshot: source, Signature: sig}, receiver.PublicKey().Bytes())
		if e != nil {
			t.Fatal(e)
		}
		return envelope
	}
	dbDir := t.TempDir()
	if err = os.Chmod(dbDir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dbDir, "evidence.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE preprod_source_evidence(evidence_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,challenge_tag TEXT NOT NULL UNIQUE)`); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA synchronous=FULL"); err != nil {
		t.Fatal(err)
	}

	root := bytes.Repeat([]byte{4}, 32)
	if _, err = db.Exec("CREATE TABLE legacy_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO legacy_key_vault_meta VALUES(1,?)", legacyVaultTag(root, "verifier", pin.TargetNode)); err != nil {
		t.Fatal(err)
	}
	if _, err = saveSourceEvidence(ctx, db, bytes.Repeat([]byte{5}, 32), receiver, pin, store.EncryptedMediaSourceSnapshot{}, strings.Repeat("1", 64), complete, base, func(context.Context) error { return nil }); err == nil {
		t.Fatal("invalid source accepted")
	}

	guard := func(ctx context.Context) error { return ctx.Err() }
	challenge := strings.Repeat("1", 64)
	original := makeEnvelope(challenge, base, false)
	if _, err = saveSourceEvidence(ctx, db, bytes.Repeat([]byte{5}, 32), receiver, pin, original, challenge, complete, base, guard); err == nil {
		t.Fatal("wrong vault root created evidence")
	}
	if _, err = db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		t.Fatal(err)
	}
	if _, err = saveSourceEvidence(ctx, db, root, receiver, pin, original, challenge, complete, base, guard); err == nil {
		t.Fatal("weak durability accepted")
	}
	if _, err = db.Exec("PRAGMA synchronous=FULL"); err != nil {
		t.Fatal(err)
	}
	ref, err := saveSourceEvidence(ctx, db, root, receiver, pin, original, challenge, complete, base, guard)
	if err != nil {
		t.Fatal(err)
	}
	again, err := saveSourceEvidence(ctx, db, root, receiver, pin, original, challenge, complete, base, guard)
	if err != nil || again != ref {
		t.Fatal("idempotent save", err)
	}
	var ciphertext []byte
	if err = db.QueryRow("SELECT cipher FROM preprod_source_evidence").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(projection.Media[0].Path)) {
		t.Fatal("plaintext source path persisted")
	}
	ok, err := recoverSourceEvidence(ctx, db, root, receiver, pin, ref, guard)
	if err != nil || !ok {
		t.Fatal("historical recovery", err)
	}
	wrong := pin
	wrong.SourcePublic = bytes.Repeat([]byte{9}, 32)
	if _, err = recoverSourceEvidence(ctx, db, root, receiver, wrong, ref, guard); err == nil {
		t.Fatal("wrong external pin accepted")
	}
	later := base.Add(4 * time.Minute)
	newChallenge := strings.Repeat("2", 64)
	fresh := makeEnvelope(newChallenge, later, false)
	next, err := renewSourceEvidence(ctx, db, root, receiver, pin, ref, fresh, newChallenge, complete, later, guard)
	if err != nil || next == ref {
		t.Fatal("fresh renewal", err)
	}
	nextRetry, err := renewSourceEvidence(ctx, db, root, receiver, pin, ref, fresh, newChallenge, complete, later, guard)
	if err != nil || nextRetry != next {
		t.Fatal("renewal retry", err)
	}
	originalDigest, err := verifyFreshSourceEvidence(ctx, db, root, receiver, pin, next, later, guard)
	if err != nil || originalDigest != ref.Digest {
		t.Fatal("fresh chain did not bind original", err)
	}
	if _, err = verifyFreshSourceEvidence(ctx, db, root, receiver, pin, next, later.Add(4*time.Minute), guard); err == nil {
		t.Fatal("expired latest source authorized")
	}
	if _, err = renewSourceEvidence(ctx, db, root, receiver, pin, ref, original, challenge, complete, later, guard); err == nil {
		t.Fatal("expired source renewed")
	}
	if _, err = renewSourceEvidence(ctx, db, root, receiver, pin, ref, makeEnvelope(challenge, later, false), challenge, complete, later, guard); err == nil {
		t.Fatal("source challenge reused")
	}
	changedChallenge := strings.Repeat("3", 64)
	changed := makeEnvelope(changedChallenge, later, true)
	if _, err = renewSourceEvidence(ctx, db, root, receiver, pin, ref, changed, changedChallenge, complete, later, guard); err == nil {
		t.Fatal("changed complete source facts accepted")
	}
	calls := 0
	failingGuard := func(context.Context) error {
		calls++
		if calls > 1 {
			return context.Canceled
		}
		return nil
	}
	guardChallenge := strings.Repeat("4", 64)
	candidate := makeEnvelope(guardChallenge, later, false)
	if _, err = renewSourceEvidence(ctx, db, root, receiver, pin, ref, candidate, guardChallenge, complete, later, failingGuard); err == nil {
		t.Fatal("lost guard committed")
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_source_evidence").Scan(&count); err != nil || count != 2 {
		t.Fatal("guard rollback", count, err)
	}
	// The renewed receipt cannot stand alone after its original is lost.
	originalTag := mustSourceEvidenceTag(t, root, ref.Digest)
	var oldSalt, oldNonce, oldCipher []byte
	var oldChallengeTag string
	if err = db.QueryRow("SELECT salt,nonce,cipher,challenge_tag FROM preprod_source_evidence WHERE evidence_tag=?", originalTag).Scan(&oldSalt, &oldNonce, &oldCipher, &oldChallengeTag); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DELETE FROM preprod_source_evidence WHERE evidence_tag=?", originalTag); err != nil {
		t.Fatal(err)
	}
	if _, err = recoverSourceEvidence(ctx, db, root, receiver, pin, next, guard); err == nil {
		t.Fatal("missing original accepted")
	}
	if _, err = db.Exec("INSERT INTO preprod_source_evidence(evidence_tag,salt,nonce,cipher,challenge_tag) VALUES(?,?,?,?,?)", originalTag, oldSalt, oldNonce, oldCipher, oldChallengeTag); err != nil {
		t.Fatal(err)
	}
	// Repeated valid renewals keep linking to the original rather than
	// creating an ever-growing chain that eventually blocks long imports.
	latest := next
	for i := 0; i < 40; i++ {
		at := later.Add(time.Duration(i+1) * 4 * time.Minute)
		c := fmt.Sprintf("%064x", 100+i)
		latest, err = renewSourceEvidence(ctx, db, root, receiver, pin, latest, makeEnvelope(c, at, false), c, complete, at, guard)
		if err != nil {
			t.Fatalf("renewal %d: %v", i, err)
		}
		originalDigest, err = verifyFreshSourceEvidence(ctx, db, root, receiver, pin, latest, at, guard)
		if err != nil || originalDigest != ref.Digest {
			t.Fatalf("renewal origin %d: %v", i, err)
		}
	}
	if _, err = db.Exec("UPDATE preprod_source_evidence SET cipher=zeroblob(length(cipher)) WHERE evidence_tag=?", mustSourceEvidenceTag(t, root, ref.Digest)); err != nil {
		t.Fatal(err)
	}
	if _, err = recoverSourceEvidence(ctx, db, root, receiver, pin, ref, guard); err == nil {
		t.Fatal("tampered evidence accepted")
	}
}
func mustSourceEvidenceTag(t *testing.T, root []byte, digest string) string {
	t.Helper()
	v, err := sourceEvidenceTag(root, digest)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
