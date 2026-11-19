package preprodimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func saveLegacyAuthorizedRequest(ctx context.Context, db *sql.DB, root []byte, scope legacyObservationScope, now time.Time) error {
	_, err := ensureLegacyAuthorizedRequest(ctx, db, root, scope, now, func(context.Context) error { return nil })
	return err
}

func TestLegacyExpiredCommitStatusDoesNotRenew(t *testing.T) {
	base, _, _, _, _, _ := keyGrantFixture(t)
	past := time.Now().Add(-10 * time.Minute)
	base.IssuedUnix, base.ExpiresUnix = past.Unix(), past.Add(3*time.Minute).Unix()
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := legacyObservationScope{Key: base, Kind: "audio", SourceSnapshotDigest: strings.Repeat("d", 64), SourceHostPin: strings.Repeat("a", 64), SourceTLSPin: strings.Repeat("b", 64), TargetSigningKey: pub}
	root := bytes.Repeat([]byte{8}, 32)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "CREATE TABLE legacy_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)", "CREATE TABLE legacy_key_requests(request_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,consumed INTEGER NOT NULL CHECK(consumed IN (0,1)))", "CREATE TABLE legacy_key_vault(object_tag TEXT PRIMARY KEY,file_tag TEXT NOT NULL UNIQUE,challenge_tag TEXT NOT NULL UNIQUE,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)"} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec("INSERT INTO legacy_key_vault_meta VALUES(1,?)", legacyVaultTag(root, "verifier", base.TargetNode)); err != nil {
		t.Fatal(err)
	}
	// Construct an already committed synthetic record without waiting for wall
	// clock time. The target signature is an observation, never a source proof.
	fileKey := bytes.Repeat([]byte{7}, 32)
	commit, err := legacyCommitment(scope, fileKey)
	if err != nil {
		t.Fatal(err)
	}
	body := legacyObservationBody{Scope: scope, Commitment: commit}
	signed, err := legacyObservationBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	row, err := sealLegacyVault(root, legacyVaultPayload{Observation: legacyObservation{Body: body, Signature: ed25519.Sign(signer, signed)}, Key: fileKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO legacy_key_vault(object_tag,file_tag,challenge_tag,salt,nonce,cipher) VALUES(?,?,?,?,?,?)", row.ObjectTag, row.FileTag, row.ChallengeTag, row.Salt, row.Nonce, row.Cipher); err != nil {
		t.Fatal(err)
	}
	tag := legacyVaultTag(root, "request", base.Challenge)
	salt := bytes.Repeat([]byte{3}, 32)
	derived, err := legacyRequestCipher(root, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(derived)
	aead, err := gcm(derived)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{4}, aead.NonceSize())
	raw, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO legacy_key_requests(request_tag,salt,nonce,cipher,consumed) VALUES(?,?,?,?,1)", tag, salt, nonce, aead.Seal(nil, nonce, raw, []byte(tag))); err != nil {
		t.Fatal(err)
	}
	guard := func(context.Context) error { return nil }
	ctx := context.Background()
	if committed, e := recoverLegacyCommitStatus(ctx, db, root, scope, guard); e != nil || !committed {
		t.Fatal("expired committed status", e)
	}
	if _, err = ensureLegacyAuthorizedRequest(ctx, db, root, scope, time.Now(), guard); err == nil {
		t.Fatal("expired scope renewed")
	}
}
func observeLegacyKeyAndStore(ctx context.Context, db *sql.DB, root []byte, scope legacyObservationScope, receiver *legacyReceiver, grant mediacrypto.SessionGrant, response mediacrypto.Metadata, envelope mediacrypto.KeyEnvelope, signer ed25519.PrivateKey, now time.Time) (bool, error) {
	return observeLegacyKeyAndStoreGuarded(ctx, db, root, scope, receiver, grant, response, envelope, signer, now, func(context.Context) error { return nil })
}

func TestLegacyObservationVaultBindsTargetAndRejectsLyrics(t *testing.T) {
	base, _, _, _, _, _ := keyGrantFixture(t)
	now := time.Now()
	base.IssuedUnix = now.Unix()
	base.ExpiresUnix = now.Add(3 * time.Minute).Unix()
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := legacyObservationScope{Key: base, Kind: "audio", SourceSnapshotDigest: strings.Repeat("d", 64), SourceHostPin: strings.Repeat("a", 64), SourceTLSPin: strings.Repeat("b", 64), TargetSigningKey: pub}
	root := bytes.Repeat([]byte{8}, 32)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "CREATE TABLE legacy_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)", "CREATE TABLE legacy_key_requests(request_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,consumed INTEGER NOT NULL CHECK(consumed IN (0,1)))", "CREATE TABLE legacy_key_vault(object_tag TEXT PRIMARY KEY,file_tag TEXT NOT NULL UNIQUE,challenge_tag TEXT NOT NULL UNIQUE,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)"} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec("INSERT INTO legacy_key_vault_meta VALUES(1,?)", legacyVaultTag(root, "verifier", base.TargetNode)); err != nil {
		t.Fatal(err)
	}
	receiver, public, err := newLegacyReceiver()
	if err != nil {
		t.Fatal(err)
	}
	source, err := mediacrypto.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := source.NewSession("admin:fixture", public)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := source.Wrap("admin:fixture", grant.SessionID, base.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	// The source creates its grant after database setup; validate it against
	// the response time, not a potentially earlier second-boundary timestamp.
	now = time.Now()
	ctx := context.Background()
	lyrics := scope
	lyrics.Kind = "lyric"
	if _, err = observeLegacyKeyAndStore(ctx, db, root, lyrics, receiver, grant, base.Descriptor, envelope, signer, now); err == nil {
		t.Fatal("lyrics accepted")
	}
	if _, err = observeLegacyKeyAndStore(ctx, db, root, scope, receiver, grant, base.Descriptor, envelope, signer, now); err == nil {
		t.Fatal("missing authorized request accepted")
	}
	if err = saveLegacyAuthorizedRequest(ctx, db, root, scope, now); err != nil {
		t.Fatal(err)
	}
	if err = saveLegacyAuthorizedRequest(ctx, db, root, scope, now); err != nil {
		t.Fatal("request retry", err)
	}
	if committed, e := recoverLegacyCommitStatus(ctx, db, root, scope, func(context.Context) error { return nil }); e != nil || committed {
		t.Fatal("pending request recovery", e)
	}
	if _, err = db.Exec("UPDATE legacy_key_requests SET consumed=1"); err != nil {
		t.Fatal(err)
	}
	if _, err = ensureLegacyAuthorizedRequest(ctx, db, root, scope, now, func(context.Context) error { return nil }); err == nil {
		t.Fatal("consumed request without vault accepted")
	}
	if _, err = db.Exec("UPDATE legacy_key_requests SET consumed=0"); err != nil {
		t.Fatal(err)
	}
	checks := 0
	if _, err = observeLegacyKeyAndStoreGuarded(ctx, db, root, scope, receiver, grant, base.Descriptor, envelope, signer, now, func(context.Context) error {
		checks++
		if checks > 1 {
			return errors.New("fence lost")
		}
		return nil
	}); err == nil {
		t.Fatal("lost fence committed")
	}
	var guardRows int
	if err = db.QueryRow("SELECT COUNT(*) FROM legacy_key_vault").Scan(&guardRows); err != nil || guardRows != 0 {
		t.Fatal("lost fence left vault row", err)
	}
	if _, err = db.Exec("CREATE TRIGGER fail_legacy BEFORE INSERT ON legacy_key_vault BEGIN SELECT RAISE(ABORT,'fixture'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err = observeLegacyKeyAndStore(ctx, db, root, scope, receiver, grant, base.Descriptor, envelope, signer, now); err == nil {
		t.Fatal("failed insert reported success")
	}
	var consumed int
	if err = db.QueryRow("SELECT consumed FROM legacy_key_requests").Scan(&consumed); err != nil || consumed != 0 {
		t.Fatal("failed write consumed request", err)
	}
	if _, err = db.Exec("DROP TRIGGER fail_legacy"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TRIGGER fail_legacy_consume BEFORE UPDATE ON legacy_key_requests BEGIN SELECT RAISE(ABORT,'fixture'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err = observeLegacyKeyAndStore(ctx, db, root, scope, receiver, grant, base.Descriptor, envelope, signer, now); err == nil {
		t.Fatal("failed consume reported success")
	}
	var rows int
	if err = db.QueryRow("SELECT COUNT(*) FROM legacy_key_vault").Scan(&rows); err != nil || rows != 0 {
		t.Fatal("failed consume left a vault row", err)
	}
	if _, err = db.Exec("DROP TRIGGER fail_legacy_consume"); err != nil {
		t.Fatal(err)
	}
	if already, e := observeLegacyKeyAndStore(ctx, db, root, scope, receiver, grant, base.Descriptor, envelope, signer, now); e != nil || already {
		t.Fatal("initial import", e)
	}
	if already, e := observeLegacyKeyAndStore(ctx, db, root, scope, receiver, grant, base.Descriptor, envelope, signer, now); e != nil || !already {
		t.Fatal("idempotent retry", e)
	}
	if consumed, e := ensureLegacyAuthorizedRequest(ctx, db, root, scope, now, func(context.Context) error { return nil }); e != nil || !consumed {
		t.Fatal("consumed request recovery", e)
	}
	if committed, e := recoverLegacyCommitStatus(ctx, db, root, scope, func(context.Context) error { return nil }); e != nil || !committed {
		t.Fatal("committed request recovery", e)
	}
	if _, err = db.Exec("UPDATE legacy_key_requests SET consumed=0"); err != nil {
		t.Fatal(err)
	}
	if _, err = ensureLegacyAuthorizedRequest(ctx, db, root, scope, now, func(context.Context) error { return nil }); err == nil {
		t.Fatal("unconsumed request with vault accepted")
	}
	if _, err = db.Exec("UPDATE legacy_key_requests SET consumed=1"); err != nil {
		t.Fatal(err)
	}
	other := scope
	other.Key.MediaID = strings.Repeat("f", 64)
	other.Key.Descriptor, err = mediacrypto.NewMetadata(4096)
	if err != nil {
		t.Fatal(err)
	}
	other.Key.StoredBytes = other.Key.Descriptor.CiphertextSize
	otherEnvelope, err := source.Wrap("admin:fixture", grant.SessionID, other.Key.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveLegacyAuthorizedRequest(ctx, db, root, other, now); err == nil {
		t.Fatal("challenge rebound")
	}
	if _, err = observeLegacyKeyAndStore(ctx, db, root, other, receiver, grant, other.Key.Descriptor, otherEnvelope, signer, now); err == nil {
		t.Fatal("challenge reused for another object")
	}
	var row legacyVaultRow
	if err = db.QueryRow("SELECT object_tag,file_tag,challenge_tag,salt,nonce,cipher FROM legacy_key_vault").Scan(&row.ObjectTag, &row.FileTag, &row.ChallengeTag, &row.Salt, &row.Nonce, &row.Cipher); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{base.MediaID, base.SourceObjectID, base.TargetBlobID, base.Descriptor.FileID, base.Snapshot, scope.SourceSnapshotDigest, scope.SourceHostPin, scope.SourceTLSPin} {
		if bytes.Contains(row.Cipher, []byte(v)) || row.ObjectTag == v || row.FileTag == v {
			t.Fatal("plaintext scope leaked")
		}
	}
	opened, err := openLegacyVault(root, row, scope, pub)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened.Key)
	want, err := source.FileKey(base.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	if !bytes.Equal(opened.Key, want) {
		t.Fatal("key mismatch")
	}
	// Even a holder of the vault encryption root cannot substitute a key while
	// retaining the original target-signed observation and its commitment.
	forged := opened
	forged.Key = bytes.Repeat([]byte{0x55}, 32)
	forgedRow, err := sealLegacyVault(root, forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = openLegacyVault(root, forgedRow, scope, pub); err == nil {
		t.Fatal("substituted key accepted")
	}
	changed := scope
	changed.SourceTLSPin = strings.Repeat("c", 64)
	if _, err = openLegacyVault(root, row, changed, pub); err == nil {
		t.Fatal("changed pin accepted")
	}
	changed = scope
	changed.SourceSnapshotDigest = strings.Repeat("e", 64)
	if _, err = openLegacyVault(root, row, changed, pub); err == nil {
		t.Fatal("changed source snapshot accepted")
	}
	row.Cipher[len(row.Cipher)-1] ^= 1
	if _, err = openLegacyVault(root, row, scope, pub); err == nil {
		t.Fatal("tampered record accepted")
	}
}
