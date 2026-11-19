package sealedtree

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func legacyFactsFixture(t *testing.T, tree *Tree, facts Facts, revision int64) FactsRecord {
	t.Helper()
	raw, err := json.Marshal(facts)
	if err != nil || len(raw) > legacyFactsPayloadBytes-2 {
		t.Fatal("legacy fixture", err)
	}
	index, err := tree.ObjectIndex(facts.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, legacyFactsPayloadBytes)
	binary.BigEndian.PutUint16(plain[:2], uint16(len(raw)))
	copy(plain[2:], raw)
	random := make([]byte, recordSaltBytes+nonceBytes)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		t.Fatal(err)
	}
	aead, err := tree.recordCipher(random[:recordSaltBytes], "facts")
	if err != nil {
		t.Fatal(err)
	}
	sealed := append([]byte{recordVersion}, random...)
	sealed = aead.Seal(sealed, random[recordSaltBytes:], plain, factsAAD(index, revision, recordVersion))
	clear(raw)
	clear(plain)
	return FactsRecord{ObjectIndex: index, Revision: revision, Sealed: sealed}
}

func TestOpenFactsScratchIsWipedAndValuesDoNotAlias(t *testing.T) {
	tree := fixture(t)
	facts := Facts{ObjectID: strings.Repeat("b", 64), Object: &ObjectFact{CreatedAt: "sensitive-created", UpdatedAt: "sensitive-updated"}}
	record, err := tree.SealFacts(facts, 1)
	if err != nil {
		t.Fatal(err)
	}
	scratch := bytes.Repeat([]byte{0x7f}, factsPayloadBytes)
	got, err := tree.openFactsWithScratch(record, scratch[:0])
	if err != nil || !reflect.DeepEqual(got, facts) || !bytes.Equal(scratch, make([]byte, len(scratch))) {
		t.Fatal("scratch open or wipe failed", err)
	}
	for i := range scratch {
		scratch[i] = 0x55
	}
	if !reflect.DeepEqual(got, facts) {
		t.Fatal("returned facts alias scratch")
	}
	bad := record
	bad.Sealed = append([]byte(nil), record.Sealed...)
	bad.Sealed[len(bad.Sealed)-1] ^= 1
	if _, err = tree.openFactsWithScratch(bad, scratch); !errors.Is(err, ErrInvalid) || !bytes.Equal(scratch, make([]byte, len(scratch))) {
		t.Fatal("bad tag or wipe failed", err)
	}
	legacy := legacyFactsFixture(t, tree, facts, 1)
	got, err = tree.openFactsWithScratch(legacy, scratch)
	if err != nil || !reflect.DeepEqual(got, facts) || !bytes.Equal(scratch, make([]byte, len(scratch))) {
		t.Fatal("legacy scratch open failed", err)
	}
}

func TestFactsV2FitsMaximumEscapedLegacyFieldsAndProof(t *testing.T) {
	tree := fixture(t)
	id := strings.Repeat("b", 64)
	control := strings.Repeat("\x01", 128)
	controlSignature := strings.Repeat("\x01", 256)
	long := strings.Repeat("\x01", 1024)
	proof := RevocationIntent{OperationID: strings.Repeat("1", 32), MasterID: strings.Repeat("2", 32), MasterBinding: strings.Repeat("3", 64), OwnerID: strings.Repeat("4", 32), RelationshipID: strings.Repeat("5", 32), RelationshipBinding: strings.Repeat("6", 64), Alias: strings.Repeat("7", 64), BlobID: strings.Repeat("8", 64), Revision: strings.Repeat("9", 64), Action: "delete", OwnerPublicKey: control, OwnerSignature: controlSignature, DeletionPublicKey: control, DeletionSignature: controlSignature}
	f := Facts{ObjectID: id, Object: &ObjectFact{CreatedAt: control, UpdatedAt: control}, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: control}, Playback: &PlaybackFact{LegacyMediaPath: long, PlayScore: 9223372036854775807, Preference: 500000, CreatedAt: control, UpdatedAt: control}, Lyric: &LyricFact{LegacyMediaPath: long, LyricID: strings.Repeat("f", 64), LegacyLyricPath: long, CreatedAt: control, UpdatedAt: control}, Revocation: &proof}
	f.LyricResolution = &LyricResolutionFact{State: "explicit", Evidence: strings.Repeat("a", 64), Origin: "native", OperationID: strings.Repeat("b", 64), PreviousEvidence: strings.Repeat("c", 64), PreviousRevision: 9223372036854775807, RelationCreatedAt: control, RelationUpdatedAt: control}
	record, err := tree.SealFacts(f, 1)
	if err != nil {
		t.Fatal("legal maximum facts do not fit", err)
	}
	if record.Sealed[0] != factsRecordVersion || len(record.Sealed) != 1+recordSaltBytes+nonceBytes+factsPayloadBytes+16 {
		t.Fatal("wrong v2 envelope")
	}
	got, err := tree.OpenFacts(record)
	if err != nil || !reflect.DeepEqual(got, f) {
		t.Fatal("maximum facts changed", err)
	}
	base := f
	base.Revocation = nil
	proof.Action = "hide"
	proof.DeletionPublicKey = ""
	proof.DeletionSignature = ""
	if err = preflightRevocationFacts(base, proof); err != nil {
		t.Fatal("legal maximum hide proof rejected", err)
	}
}

func TestFactsV1ReadAndExplicitV2UpgradeAreAtomic(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "album"}
	facts := Facts{ObjectID: entry.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}
	if err := s.CreateDirectoryWithFacts(ctx, entry, facts); err != nil {
		t.Fatal(err)
	}
	old := legacyFactsFixture(t, s.tree, facts, 1)
	oldID, err := FactsEncryptionID(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO sealed_tree_encryption_ids(encryption_id) VALUES(?)`, oldID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_facts SET encryption_id=?,sealed=? WHERE object_index=?`, oldID, old.Sealed, old.ObjectIndex); err != nil {
		t.Fatal(err)
	}
	got, rev, err := s.GetFacts(ctx, entry.ObjectID)
	if err != nil || rev != 1 || !reflect.DeepEqual(got, facts) {
		t.Fatal("legacy read", err)
	}
	bad := old
	bad.Sealed = append([]byte(nil), old.Sealed...)
	bad.Sealed[0] = factsRecordVersion
	if _, err = s.tree.OpenFacts(bad); !errors.Is(err, ErrInvalid) {
		t.Fatal("version substitution accepted", err)
	}
	if _, err = db.Exec(`CREATE TRIGGER reject_facts_upgrade BEFORE UPDATE ON sealed_tree_facts BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.UpgradeFactsToV2(ctx, entry.ObjectID, 1); err == nil {
		t.Fatal("failed upgrade committed")
	}
	if _, err = db.Exec(`DROP TRIGGER reject_facts_upgrade`); err != nil {
		t.Fatal(err)
	}
	got, rev, err = s.GetFacts(ctx, entry.ObjectID)
	if err != nil || rev != 1 || !reflect.DeepEqual(got, facts) {
		t.Fatal("failed upgrade changed legacy facts", err)
	}
	newRev, already, err := s.UpgradeFactsToV2(ctx, entry.ObjectID, 1)
	if err != nil || already || newRev != 2 {
		t.Fatal("upgrade", err)
	}
	if newRev, already, err = s.UpgradeFactsToV2(ctx, entry.ObjectID, 2); err != nil || !already || newRev != 2 {
		t.Fatal("v2 status", err)
	}
	if _, _, err = s.UpgradeFactsToV2(ctx, entry.ObjectID, 1); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision accepted", err)
	}
	var current []byte
	var oldCount int
	if err = db.QueryRow(`SELECT sealed FROM sealed_tree_facts WHERE object_index=?`, old.ObjectIndex).Scan(&current); err != nil || len(current) == 0 || current[0] != factsRecordVersion {
		t.Fatal("v2 row absent", err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, oldID).Scan(&oldCount); err != nil || oldCount != 1 {
		t.Fatal("legacy nonce reservation lost", err)
	}
	got, rev, err = s.GetFacts(ctx, entry.ObjectID)
	if err != nil || rev != 2 || !reflect.DeepEqual(got, facts) {
		t.Fatal("upgraded facts changed", err)
	}
	if bytes.Contains(current, []byte("album")) {
		t.Fatal("plaintext leaked")
	}
}
