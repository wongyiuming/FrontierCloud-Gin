package preprodimport

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"golang.org/x/crypto/hkdf"
)

func keyGrantFixture(t *testing.T) (keyScope, []byte, *ecdh.PrivateKey, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	meta, err := mediacrypto.NewMetadata(123456)
	if err != nil {
		t.Fatal(err)
	}
	target, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000000000, 0)
	s := keyScope{Version: 1, SourceNode: strings.Repeat("1", 32), SourceKeyID: strings.Repeat("8", 64), TargetNode: strings.Repeat("2", 32), Snapshot: strings.Repeat("3", 64), MediaID: strings.Repeat("4", 64), SourceObjectID: strings.Repeat("5", 64), TargetOwnerID: strings.Repeat("9", 32), TargetBlobID: strings.Repeat("a", 64), TargetReadAlias: strings.Repeat("b", 64), ContentSHA256: strings.Repeat("6", 64), StoredBytes: meta.CiphertextSize, Challenge: strings.Repeat("7", 64), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(3 * time.Minute).Unix(), Descriptor: meta}
	return s, bytes.Repeat([]byte{0x91}, 32), target, pub, priv, now
}

func TestSyntheticFileKeyGrantBindsExactSnapshotTargetAndDescriptor(t *testing.T) {
	s, fileKey, target, signer, source, now := keyGrantFixture(t)
	g, err := sealFileKey(s, fileKey, target.PublicKey(), source, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openFileKey(g, s, target, signer, now)
	if err != nil || !bytes.Equal(got, fileKey) {
		t.Fatalf("grant round trip: %v", err)
	}
	clear(got)
	encoded, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range [][]byte{fileKey, []byte(s.SourceNode), []byte(s.SourceKeyID), []byte(s.TargetNode), []byte(s.MediaID), []byte(s.SourceObjectID), []byte(s.TargetOwnerID), []byte(s.TargetBlobID), []byte(s.TargetReadAlias), []byte(s.ContentSHA256), []byte(s.Challenge), []byte(s.Descriptor.FileID), []byte(s.Snapshot)} {
		if bytes.Contains(encoded, sensitive) {
			t.Fatal("grant exposed a protected value")
		}
	}
	for name, mutate := range map[string]func(*keyScope){
		"source":     func(v *keyScope) { v.SourceNode = strings.Repeat("8", 32) },
		"source key": func(v *keyScope) { v.SourceKeyID = strings.Repeat("9", 64) },
		"target":     func(v *keyScope) { v.TargetNode = strings.Repeat("9", 32) },
		"snapshot":   func(v *keyScope) { v.Snapshot = strings.Repeat("8", 64) },
		"media":      func(v *keyScope) { v.MediaID = strings.Repeat("8", 64) },
		"object":     func(v *keyScope) { v.SourceObjectID = strings.Repeat("8", 64) },
		"owner":      func(v *keyScope) { v.TargetOwnerID = strings.Repeat("8", 32) },
		"blob":       func(v *keyScope) { v.TargetBlobID = strings.Repeat("b", 64) },
		"alias":      func(v *keyScope) { v.TargetReadAlias = strings.Repeat("f", 64) },
		"content":    func(v *keyScope) { v.ContentSHA256 = strings.Repeat("8", 64) },
		"size":       func(v *keyScope) { v.StoredBytes++ },
		"challenge":  func(v *keyScope) { v.Challenge = strings.Repeat("8", 64) },
		"descriptor": func(v *keyScope) { v.Descriptor.FileID = strings.Repeat("8", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			mutate(&changed)
			if key, err := openFileKey(g, changed, target, signer, now); err == nil {
				clear(key)
				t.Fatal("changed scope accepted")
			}
		})
	}
	if key, err := openFileKey(g, s, target, signer, now.Add(4*time.Minute)); err == nil {
		clear(key)
		t.Fatal("expired grant accepted")
	}
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := openFileKey(g, s, other, signer, now); err == nil {
		clear(key)
		t.Fatal("wrong target accepted")
	}
	wrongSigner, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := openFileKey(g, s, target, wrongSigner, now); err == nil {
		clear(key)
		t.Fatal("wrong source accepted")
	}
	tampered := g
	tampered.Cipher = append([]byte(nil), g.Cipher...)
	tampered.Cipher[0] ^= 1
	if key, err := openFileKey(tampered, s, target, signer, now); err == nil {
		clear(key)
		t.Fatal("tampered grant accepted")
	}
	tampered = g
	tampered.KeyCommitment = append([]byte(nil), g.KeyCommitment...)
	tampered.KeyCommitment[0] ^= 1
	if key, err := openFileKey(tampered, s, target, signer, now); err == nil {
		clear(key)
		t.Fatal("tampered signed key commitment accepted")
	}
}

func TestSyntheticVaultProtectsAndBindsPerObjectKey(t *testing.T) {
	s, fileKey, target, signer, source, now := keyGrantFixture(t)
	grant, err := sealFileKey(s, fileKey, target.PublicKey(), source, now)
	if err != nil {
		t.Fatal(err)
	}
	proof := keyProof{Grant: grant, SourcePublic: signer, TargetPublic: target.PublicKey().Bytes()}
	root := bytes.Repeat([]byte{0x82}, 32)
	row, err := sealVaultKey(root, s, fileKey, proof)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range [][]byte{fileKey, []byte(s.SourceNode), []byte(s.SourceKeyID), []byte(s.TargetNode), []byte(s.MediaID), []byte(s.SourceObjectID), []byte(s.TargetOwnerID), []byte(s.TargetBlobID), []byte(s.TargetReadAlias), []byte(s.ContentSHA256), []byte(s.Challenge), []byte(s.Descriptor.FileID), []byte(s.Snapshot)} {
		if bytes.Contains(encoded, sensitive) {
			t.Fatal("plaintext key identity appeared in the protected row")
		}
	}
	got, err := openVaultKey(root, row, s, signer, target.PublicKey().Bytes())
	if err != nil || !bytes.Equal(got, fileKey) {
		t.Fatalf("vault round trip: %v", err)
	}
	clear(got)
	changed := s
	changed.Descriptor.FileID = strings.Repeat("8", 32)
	if key, err := openVaultKey(root, row, changed, signer, target.PublicKey().Bytes()); err == nil {
		clear(key)
		t.Fatal("changed descriptor accepted")
	}
	tampered := row
	tampered.Cipher = append([]byte(nil), row.Cipher...)
	tampered.Cipher[0] ^= 1
	if key, err := openVaultKey(root, tampered, s, signer, target.PublicKey().Bytes()); err == nil {
		clear(key)
		t.Fatal("tampered row accepted")
	}
	if key, err := openVaultKey(bytes.Repeat([]byte{0x83}, 32), row, s, signer, target.PublicKey().Bytes()); err == nil {
		clear(key)
		t.Fatal("wrong vault root accepted")
	}
	otherSigner, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := openVaultKey(root, row, s, otherSigner, target.PublicKey().Bytes()); err == nil {
		clear(key)
		t.Fatal("wrong pinned source accepted during recovery")
	}
	otherTarget, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := openVaultKey(root, row, s, signer, otherTarget.PublicKey().Bytes()); err == nil {
		clear(key)
		t.Fatal("wrong pinned target accepted during recovery")
	}
	if _, err := sealVaultKey(make([]byte, 32), s, fileKey, proof); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero vault root accepted")
	}
	// Simulate an attacker with the vault root who re-encrypts a different
	// file key while retaining the valid source-signed proof and scope.
	wrong := append([]byte(nil), fileKey...)
	wrong[0] ^= 1
	if _, err := sealVaultKey(root, s, wrong, proof); err == nil {
		t.Fatal("source proof accepted a different file key")
	}
	encodedAttack, err := json.Marshal(vaultPayload{Scope: s, Key: wrong, Proof: proof})
	if err != nil || len(encodedAttack) > vaultPayloadBytes-2 {
		t.Fatalf("attack fixture: %v", err)
	}
	plaintextAttack := make([]byte, vaultPayloadBytes)
	binary.BigEndian.PutUint16(plaintextAttack[:2], uint16(len(encodedAttack)))
	copy(plaintextAttack[2:], encodedAttack)
	attackKey := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, root, row.Salt, []byte("frontiercloud:preprod-key-vault:row:v1")), attackKey); err != nil {
		t.Fatal(err)
	}
	attackAEAD, err := gcm(attackKey)
	if err != nil {
		t.Fatal(err)
	}
	forged := row
	forged.Cipher = attackAEAD.Seal(nil, row.Nonce, plaintextAttack, []byte(row.ObjectTag+row.GrantTag+row.FileTag))
	clear(attackKey)
	clear(plaintextAttack)
	clear(encodedAttack)
	clear(wrong)
	if key, err := openVaultKey(root, forged, s, signer, target.PublicKey().Bytes()); err == nil {
		clear(key)
		t.Fatal("vault-root attacker substituted a file key under old proof")
	}
}

func TestSyntheticVaultRootsAreIndependent(t *testing.T) {
	first, err := newVaultRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first)
	second, err := newVaultRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second)
	if len(first) != 32 || len(second) != 32 || bytes.Equal(first, second) {
		t.Fatal("vault roots are not independent")
	}
}

func TestSyntheticDerivedFileKeyPreservesSourceCiphertext(t *testing.T) {
	s, _, target, signer, source, now := keyGrantFixture(t)
	productionRoot := bytes.Repeat([]byte{0x49}, 32)
	manager, err := mediacrypto.New(productionRoot)
	if err != nil {
		t.Fatal(err)
	}
	s.SourceKeyID = manager.KeyID()
	derived, err := manager.FileKey(s.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(derived)
	plaintext := bytes.Repeat([]byte("a"), int(s.Descriptor.PlaintextSize))
	block, err := gcm(derived)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := s.Descriptor.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := block.Seal(nil, nonce, plaintext, s.Descriptor.ChunkAAD(0))
	digest := sha256.Sum256(ciphertext)
	s.ContentSHA256 = hex.EncodeToString(digest[:])
	grant, err := sealDerivedFileKey(s, manager, target.PublicKey(), source, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openFileKey(grant, s, target, signer, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	block, err = gcm(got)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := block.Open(nil, nonce, ciphertext, s.Descriptor.ChunkAAD(0))
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatalf("original synthetic ciphertext is not readable: %v", err)
	}
	newManager, err := mediacrypto.New(bytes.Repeat([]byte{0x50}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sealDerivedFileKey(s, newManager, target.PublicKey(), source, now); err == nil {
		t.Fatal("wrong source media key identity was accepted")
	}
	newKey, err := newManager.FileKey(s.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(newKey)
	if bytes.Equal(newKey, got) {
		t.Fatal("independent media premaster unexpectedly derived the source key")
	}
}

func TestSyntheticVaultTransactionRejectsReplayAndRecoversCommit(t *testing.T) {
	s, fileKey, target, signer, source, now := keyGrantFixture(t)
	grant, err := sealFileKey(s, fileKey, target.PublicKey(), source, now)
	if err != nil {
		t.Fatal(err)
	}
	proof := keyProof{Grant: grant, SourcePublic: signer, TargetPublic: target.PublicKey().Bytes()}
	opened, err := openFileKey(grant, s, target, signer, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened)
	root := bytes.Repeat([]byte{0x82}, 32)
	path := filepath.Join(t.TempDir(), "fixture.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"CREATE TABLE preprod_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)",
		"CREATE TABLE preprod_key_vault(object_tag TEXT PRIMARY KEY,grant_tag TEXT NOT NULL UNIQUE,file_tag TEXT NOT NULL UNIQUE,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)",
	} {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec("INSERT INTO preprod_key_vault_meta VALUES(1,?)", vaultTag(root, "verifier", s.TargetNode)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TRIGGER fail_fixture BEFORE INSERT ON preprod_key_vault BEGIN SELECT RAISE(ABORT,'fixture failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err = importFileKeyGrant(context.Background(), db, root, s, target, signer, grant, now); err == nil {
		t.Fatal("failed transaction reported success")
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_key_vault").Scan(&count); err != nil || count != 0 {
		t.Fatal("failed transaction left a key row")
	}
	if _, err = db.Exec("DROP TRIGGER fail_fixture"); err != nil {
		t.Fatal(err)
	}
	tamperedGrant := grant
	tamperedGrant.Signature = append([]byte(nil), grant.Signature...)
	tamperedGrant.Signature[0] ^= 1
	if _, err = importFileKeyGrant(context.Background(), db, root, s, target, signer, tamperedGrant, now); err == nil {
		t.Fatal("invalid source signature reached the vault")
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_key_vault").Scan(&count); err != nil || count != 0 {
		t.Fatal("unauthenticated grant left a key row")
	}
	if already, err := importFileKeyGrant(context.Background(), db, root, s, target, signer, grant, now); err != nil || already {
		t.Fatalf("initial install failed: %v", err)
	}
	if already, err := importFileKeyGrant(context.Background(), db, root, s, target, signer, grant, now); err != nil || !already {
		t.Fatalf("identical retry did not recover: %v", err)
	}
	if _, err = importFileKeyGrant(context.Background(), db, root, s, target, signer, grant, now.Add(time.Hour)); err == nil {
		t.Fatal("expired grant was accepted for installation")
	}
	if committed, err := recoverVaultCommit(context.Background(), db, root, s, signer, target.PublicKey().Bytes()); err != nil || !committed {
		t.Fatalf("lost commit response could not be reconciled: %v", err)
	}
	if recovered, found, err := recoverVaultScope(context.Background(), db, root, s.TargetNode, s.MediaID, signer, target.PublicKey().Bytes()); err != nil || !found || recovered != s {
		t.Fatalf("committed encrypted scope could not be recovered: %v", err)
	}
	wrongSigner, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = recoverVaultScope(context.Background(), db, root, s.TargetNode, s.MediaID, wrongSigner, target.PublicKey().Bytes()); err == nil {
		t.Fatal("scope recovery accepted an unpinned source")
	}
	changed := s
	changed.ContentSHA256 = strings.Repeat("8", 64)
	if _, err = installVaultKey(context.Background(), db, root, changed, opened, proof, signer, target, now); err == nil {
		t.Fatal("different content reused an object key")
	}
	if _, err = recoverVaultCommit(context.Background(), db, root, changed, signer, target.PublicKey().Bytes()); err == nil {
		t.Fatal("recovery accepted a changed binding")
	}
	duplicateFile := s
	duplicateFile.MediaID = strings.Repeat("c", 64)
	duplicateFile.SourceObjectID = strings.Repeat("d", 64)
	duplicateGrant, err := sealFileKey(duplicateFile, opened, target.PublicKey(), source, now)
	if err != nil {
		t.Fatal(err)
	}
	duplicateProof := keyProof{Grant: duplicateGrant, SourcePublic: signer, TargetPublic: target.PublicKey().Bytes()}
	if _, err = installVaultKey(context.Background(), db, root, duplicateFile, opened, duplicateProof, signer, target, now); err == nil {
		t.Fatal("same FileID accepted for a different object")
	}
	otherKey := append([]byte(nil), opened...)
	otherKey[0] ^= 1
	if _, err = installVaultKey(context.Background(), db, root, s, otherKey, proof, signer, target, now); err == nil {
		t.Fatal("same object accepted a different file key")
	}
	if _, err = installVaultKey(context.Background(), db, bytes.Repeat([]byte{0x83}, 32), s, opened, proof, signer, target, now); err == nil {
		t.Fatal("wrong root opened the vault")
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, readErr := os.ReadFile(path + suffix)
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, secret := range [][]byte{fileKey, []byte(s.SourceNode), []byte(s.SourceKeyID), []byte(s.TargetNode), []byte(s.MediaID), []byte(s.SourceObjectID), []byte(s.TargetOwnerID), []byte(s.TargetBlobID), []byte(s.TargetReadAlias), []byte(s.ContentSHA256), []byte(s.Challenge), []byte(s.Descriptor.FileID), []byte(s.Snapshot)} {
			if bytes.Contains(data, secret) {
				t.Fatalf("plaintext key or identity in fixture database%s", suffix)
			}
		}
	}
}

func TestSyntheticVaultRejectsMissingUniquenessConstraint(t *testing.T) {
	s, fileKey, target, signer, source, now := keyGrantFixture(t)
	grant, err := sealFileKey(s, fileKey, target.PublicKey(), source, now)
	if err != nil {
		t.Fatal(err)
	}
	proof := keyProof{Grant: grant, SourcePublic: signer, TargetPublic: target.PublicKey().Bytes()}
	root := bytes.Repeat([]byte{0x82}, 32)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "fixture.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"CREATE TABLE preprod_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)",
		"CREATE TABLE preprod_key_vault(object_tag TEXT PRIMARY KEY,grant_tag TEXT NOT NULL UNIQUE,file_tag TEXT NOT NULL,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL)",
	} {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec("INSERT INTO preprod_key_vault_meta VALUES(1,?)", vaultTag(root, "verifier", s.TargetNode)); err != nil {
		t.Fatal(err)
	}
	if _, err = installVaultKey(context.Background(), db, root, s, fileKey, proof, signer, target, now); err == nil {
		t.Fatal("schema without FileID uniqueness was accepted")
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM preprod_key_vault").Scan(&count); err != nil || count != 0 {
		t.Fatal("failed schema check left a row")
	}
}
