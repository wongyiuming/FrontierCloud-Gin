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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestHistoricalSourceLyricChecksSignedProjection(t *testing.T) {
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
	source := syntheticSourceForComplete(complete)
	now := time.Now().UTC().Truncate(time.Second)
	source.Version, source.AuthorityKind, source.SourceSSHHostKeySHA256 = 1, pin.AuthorityKind, pin.SourceSSHHostKeySHA256
	source.SourceNode, source.SourcePublic, source.TargetNode, source.TargetReceiver = pin.SourceNode, protocol.Encode(pin.SourcePublic), pin.TargetNode, pin.TargetX25519
	source.Challenge, source.IssuedUnix, source.ExpiresUnix = strings.Repeat("1", 64), now.Unix(), now.Add(3*time.Minute).Unix()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	signature, err := protocol.Sign(protocol.Encode(seed.Seed()), map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hex.EncodeToString(hash[:]), "source_node": source.SourceNode, "target_node": source.TargetNode, "challenge": source.Challenge})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshotcrypt.Seal(store.SignedMediaSourceSnapshot{Snapshot: source, Signature: signature}, receiver.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "evidence.sqlite")
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
	ref, err := saveSourceEvidence(ctx, db, root, receiver, pin, envelope, source.Challenge, complete, now, func(c context.Context) error { return c.Err() })
	if err != nil {
		t.Fatal(err)
	}
	var track Media
	for _, candidate := range complete.Projection.Media {
		if candidate.Kind == "audio" {
			track = candidate
			break
		}
	}
	if track.MediaID == "" {
		t.Fatal("fixture has no audio")
	}
	resolution, err := sourceLyricResolution(complete, track, ref.Digest, generation)
	if err != nil {
		t.Fatal(err)
	}
	selected := sealedtree.LyricSelection{BuiltinFallback: resolution.State != "explicit", Evidence: resolution.Evidence, SourceDigest: ref.Digest, SourceGeneration: generation}
	if resolution.State == "explicit" {
		for _, link := range complete.Facts.LyricLinks {
			if link.MediaID == track.MediaID {
				selected.ExplicitLyricID = link.LyricID
			}
		}
	}
	capability, err := prepareCompleteSourceLyric(envelope, receiver, pin, source.Challenge, complete, 1)
	if err != nil || capability.check(pin, envelope, 1, track.MediaID, selected) != nil {
		t.Fatal("verified complete capability rejected", err)
	}
	if capability.check(pin, envelope, 2, track.MediaID, selected) == nil {
		t.Fatal("changed source row version accepted")
	}
	changedPin := pin
	changedPin.TargetNode = strings.Repeat("9", 32)
	if capability.check(changedPin, envelope, 1, track.MediaID, selected) == nil {
		t.Fatal("changed target pin accepted")
	}
	changedSelection := selected
	changedSelection.Evidence = strings.Repeat("e", 64)
	if capability.check(pin, envelope, 1, track.MediaID, changedSelection) == nil {
		t.Fatal("changed tree resolution accepted")
	}
	changedComplete := complete
	changedComplete.Facts.LyricLinks = append([]sourceLyricLinkFact(nil), complete.Facts.LyricLinks...)
	if len(changedComplete.Facts.LyricLinks) == 0 {
		t.Fatal("fixture missing lyric association")
	}
	changedComplete.Facts.LyricLinks[0].LyricID = strings.Repeat("f", 64)
	if _, e := prepareCompleteSourceLyric(envelope, receiver, pin, source.Challenge, changedComplete, 1); e == nil {
		t.Fatal("source projection mismatch accepted")
	}
	if err = verifyHistoricalSourceLyric(ctx, db, root, receiver, pin, track.MediaID, selected); err != nil {
		t.Fatal("signed source rejected", err)
	}
	wrong := selected
	wrong.SourceGeneration = strings.Repeat("f", 64)
	if err = verifyHistoricalSourceLyric(ctx, db, root, receiver, pin, track.MediaID, wrong); err == nil {
		t.Fatal("wrong generation accepted")
	}
	wrong = selected
	wrong.Evidence = strings.Repeat("e", 64)
	if err = verifyHistoricalSourceLyric(ctx, db, root, receiver, pin, track.MediaID, wrong); err == nil {
		t.Fatal("wrong relation accepted")
	}
	if err = verifyHistoricalSourceLyric(ctx, db, bytes.Repeat([]byte{9}, 32), receiver, pin, track.MediaID, selected); err == nil {
		t.Fatal("wrong vault accepted")
	}
	// A historical observation may be inspected after source expiry; it is
	// not a current capability and the synthetic save time is not a commit.
	old := source
	old.Challenge, old.IssuedUnix, old.ExpiresUnix = strings.Repeat("2", 64), now.Add(-4*time.Minute).Unix(), now.Add(-time.Minute).Unix()
	oldRaw, e := json.Marshal(old)
	if e != nil {
		t.Fatal(e)
	}
	oldHash := sha256.Sum256(oldRaw)
	oldSignature, e := protocol.Sign(protocol.Encode(seed.Seed()), map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hex.EncodeToString(oldHash[:]), "source_node": old.SourceNode, "target_node": old.TargetNode, "challenge": old.Challenge})
	if e != nil {
		t.Fatal(e)
	}
	oldEnvelope, e := snapshotcrypt.Seal(store.SignedMediaSourceSnapshot{Snapshot: old, Signature: oldSignature}, receiver.PublicKey().Bytes())
	if e != nil {
		t.Fatal(e)
	}
	oldRef, e := saveSourceEvidence(ctx, db, root, receiver, pin, oldEnvelope, old.Challenge, complete, now.Add(-4*time.Minute), func(c context.Context) error { return c.Err() })
	if e != nil {
		t.Fatal(e)
	}
	oldResolution, e := sourceLyricResolution(complete, track, oldRef.Digest, generation)
	if e != nil {
		t.Fatal(e)
	}
	oldSelected := selected
	oldSelected.SourceDigest, oldSelected.Evidence = oldRef.Digest, oldResolution.Evidence
	if e = verifyHistoricalSourceLyric(ctx, db, root, receiver, pin, track.MediaID, oldSelected); e != nil {
		t.Fatal("historical source inspection failed", e)
	}
	if _, e = prepareCompleteSourceLyric(oldEnvelope, receiver, pin, old.Challenge, complete, 1); e == nil {
		t.Fatal("expired observation became current capability")
	}
	if _, err = db.Exec("UPDATE preprod_source_evidence SET cipher=zeroblob(length(cipher))"); err != nil {
		t.Fatal(err)
	}
	if err = verifyHistoricalSourceLyric(ctx, db, root, receiver, pin, track.MediaID, selected); err == nil {
		t.Fatal("tampered evidence accepted")
	}
}
