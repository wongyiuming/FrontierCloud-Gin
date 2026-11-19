package preprodimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSyntheticAuthorizedRequestAtomicConsume(t *testing.T) {
	s, fileKey, target, signer, source, now := keyGrantFixture(t)
	grant, err := sealFileKey(s, fileKey, target.PublicKey(), source, now)
	if err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{0x82}, 32)
	path := filepath.Join(t.TempDir(), "request.sqlite")
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
	} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec("INSERT INTO preprod_key_vault_meta VALUES(1,?)", vaultTag(root, "verifier", s.TargetNode)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = importAuthorizedFileKeyGrant(ctx, db, root, s, target, signer, grant, now); err == nil {
		t.Fatal("unrequested grant accepted")
	}
	if err = saveAuthorizedRequest(ctx, db, root, s, signer, target.PublicKey().Bytes(), now); err != nil {
		t.Fatal(err)
	}
	if recovered, found, consumed, err := recoverAuthorizedRequest(ctx, db, root, s.TargetNode, s.Challenge, signer, target.PublicKey().Bytes()); err != nil || !found || consumed || recovered != s {
		t.Fatalf("pending recovery: %v", err)
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherGrant, err := sealFileKey(s, fileKey, target.PublicKey(), otherPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = importAuthorizedFileKeyGrant(ctx, db, root, s, target, otherPublic, otherGrant, now); err == nil {
		t.Fatal("request with a different signer was accepted")
	}
	if err = saveAuthorizedRequest(ctx, db, root, s, signer, target.PublicKey().Bytes(), now); err != nil {
		t.Fatal("identical request retry failed")
	}
	changed := s
	changed.Snapshot = changed.ContentSHA256
	if err = saveAuthorizedRequest(ctx, db, root, changed, signer, target.PublicKey().Bytes(), now); err == nil {
		t.Fatal("challenge was rebound to a different scope")
	}
	var savedCipher []byte
	if err = db.QueryRow("SELECT cipher FROM preprod_key_requests").Scan(&savedCipher); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), savedCipher...)
	corrupt[0] ^= 1
	if _, err = db.Exec("UPDATE preprod_key_requests SET cipher=?", corrupt); err != nil {
		t.Fatal(err)
	}
	if _, err = importAuthorizedFileKeyGrant(ctx, db, root, s, target, signer, grant, now); err == nil {
		t.Fatal("tampered request accepted")
	}
	if _, err = db.Exec("UPDATE preprod_key_requests SET cipher=?", savedCipher); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TRIGGER block_consumption BEFORE INSERT ON preprod_key_request_consumed BEGIN SELECT RAISE(ABORT,'fixture'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err = importAuthorizedFileKeyGrant(ctx, db, root, s, target, signer, grant, now); err == nil {
		t.Fatal("failed receipt reported success")
	}
	var n int
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_key_vault").Scan(&n); err != nil || n != 0 {
		t.Fatal("key survived failed consume")
	}
	if _, err = db.Exec("DROP TRIGGER block_consumption"); err != nil {
		t.Fatal(err)
	}
	if _, err = importAuthorizedFileKeyGrant(ctx, db, root, s, target, signer, grant, now.Add(time.Hour)); err == nil {
		t.Fatal("expired request accepted")
	}
	if already, err := importAuthorizedFileKeyGrant(ctx, db, root, s, target, signer, grant, now); err != nil || already {
		t.Fatalf("first import: %v", err)
	}
	if already, err := importAuthorizedFileKeyGrant(ctx, db, root, s, target, signer, grant, now); err != nil || !already {
		t.Fatalf("retry: %v", err)
	}
	if recovered, found, consumed, err := recoverAuthorizedRequest(ctx, db, root, s.TargetNode, s.Challenge, signer, target.PublicKey().Bytes()); err != nil || !found || !consumed || recovered != s {
		t.Fatalf("committed recovery: %v", err)
	}
	if _, err = db.Exec("UPDATE preprod_key_request_consumed SET receipt = zeroblob(32)"); err != nil {
		t.Fatal(err)
	}
	if _, err = importAuthorizedFileKeyGrant(ctx, db, root, s, target, signer, grant, now); err == nil {
		t.Fatal("tampered receipt accepted")
	}
	if _, _, _, err = recoverAuthorizedRequest(ctx, db, root, s.TargetNode, s.Challenge, signer, target.PublicKey().Bytes()); err == nil {
		t.Fatal("tampered recovery receipt accepted")
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(path + suffix)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		for _, secret := range [][]byte{fileKey, []byte(s.Challenge), []byte(s.MediaID), []byte(s.Snapshot), []byte(s.Descriptor.FileID)} {
			if bytes.Contains(data, secret) {
				t.Fatal("request fixture leaked plaintext")
			}
		}
	}
}
