package preprodimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// This proves the indexed decisions are populated by a real signed source
// observation. It is not a product import, target-vault proof or commit fence.
func TestCompleteSourceLyricCapabilitySignedProjection(t *testing.T) {
	// This is a pure in-memory synthetic source: unlike the filesystem
	// importer fixture, it needs no OS ACL support and runs on Windows too.
	defaultLyric := []byte("[00:00.00]建设中，暂无歌词\n")
	projection := Snapshot{
		Version: 1, SourceProjectionSHA256: testID("f", 64), PremasterKeyID: testID("9", 64),
		DeclaredSections:  []string{"media", "lyrics", "directories", "links", "visibility", "preferences", "encryption_nonces"},
		Mappings:          []Mapping{{SourceID: testID("1", 32), TargetID: testID("4", 32), Role: "master", Capacity: 1000}, {SourceID: testID("2", 32), TargetID: testID("5", 32), Role: "direct", Capacity: 1000}, {SourceID: testID("3", 32), TargetID: testID("6", 32), Role: "relay", Capacity: 1000}},
		ExcludedSourceIDs: []string{testID("7", 32)},
		Media: []Media{
			{MediaID: testID("a", 64), ObjectID: testID("b", 64), SourceID: testID("1", 32), Path: "music/album/song.mp3", Kind: "audio", Size: 5, SHA256: digest([]byte("audio"))},
			{MediaID: testID("c", 64), ObjectID: testID("f", 64), SourceID: testID("1", 32), Path: "music/album/unlinked.mp3", Kind: "audio", Size: 5, SHA256: digest([]byte("audio"))},
			{MediaID: testID("d", 64), ObjectID: testID("0", 64), SourceID: testID("1", 32), Path: "music/album/default.mp3", Kind: "audio", Size: 5, SHA256: digest([]byte("audio"))},
		},
		Lyrics: []Lyric{{ID: testID("e", 64), Path: "lyrics/a/song.lrc", Size: 5, SHA256: digest([]byte("lyric"))}, {ID: testID("8", 64), Path: "lyrics/default.lrc", Size: int64(len(defaultLyric)), SHA256: digest(defaultLyric), Builtin: true}},
		Links:  []Link{{MediaID: testID("a", 64), LyricID: testID("e", 64)}, {MediaID: testID("d", 64), LyricID: testID("8", 64)}},
	}
	complete := completeSourceFixture(projection)
	for i := range complete.Facts.LyricLinks {
		if complete.Facts.LyricLinks[i].MediaID == testID("d", 64) {
			complete.Facts.LyricLinks[i].MediaPath = "music/album/default.mp3"
			complete.Facts.LyricLinks[i].LyricPath = "lyrics/default.lrc"
		}
	}
	generation, err := completeSnapshotDigest(complete)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	receiver, err := receiverFromMasterSeed(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	masterSeed := bytes.Repeat([]byte{8}, 32)
	masterSigning := ed25519.NewKeyFromSeed(masterSeed)
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "ssh-collector-v1", SourceSSHHostKeySHA256: strings.Repeat("a", 64), SourceTLSOrigin: "https://source.test", SourceTLSSPKISHA256: strings.Repeat("b", 64), SourceNode: projection.Mappings[0].SourceID, SourceKeyID: projection.PremasterKeyID, SourcePublic: key.Public().(ed25519.PublicKey), TargetNode: projection.Mappings[0].TargetID, TargetMasterPublic: masterSigning.Public().(ed25519.PublicKey), TargetX25519: receiver.PublicKey().Bytes(), Generation: generation}
	pin.ImportScope = syntheticImportScope(projection)
	for _, mapping := range projection.Mappings {
		pin.SourceOwners = append(pin.SourceOwners, sourceOwnerPin{NodeID: mapping.SourceID, SSHHostKeySHA256: pin.SourceSSHHostKeySHA256})
	}
	source := syntheticSourceForComplete(complete)
	now := time.Now().Unix()
	source.Version, source.AuthorityKind, source.SourceSSHHostKeySHA256 = 1, pin.AuthorityKind, pin.SourceSSHHostKeySHA256
	source.SourceNode, source.SourcePublic, source.TargetNode, source.TargetReceiver = pin.SourceNode, protocol.Encode(pin.SourcePublic), pin.TargetNode, pin.TargetX25519
	source.Challenge, source.IssuedUnix, source.ExpiresUnix = strings.Repeat("1", 64), now, now+120
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	signature, err := protocol.Sign(protocol.Encode(key.Seed()), map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hex.EncodeToString(hash[:]), "source_node": source.SourceNode, "target_node": source.TargetNode, "challenge": source.Challenge})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshotcrypt.Seal(store.SignedMediaSourceSnapshot{Snapshot: source, Signature: signature}, receiver.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	capability, err := prepareCompleteSourceLyric(envelope, receiver, pin, source.Challenge, complete, 1)
	if err != nil {
		t.Fatal("valid signed projection rejected", err)
	}
	var audioIDs []string
	for _, track := range complete.Projection.Media {
		if track.Kind != "audio" {
			continue
		}
		audioIDs = append(audioIDs, track.MediaID)
		resolution, err := sourceLyricResolution(complete, track, capability.verified.Digest(), generation)
		if err != nil {
			t.Fatal(err)
		}
		selected := sealedtree.LyricSelection{BuiltinFallback: resolution.State != "explicit", Evidence: resolution.Evidence, SourceDigest: capability.verified.Digest(), SourceGeneration: generation}
		for _, link := range complete.Facts.LyricLinks {
			if link.MediaID == track.MediaID && resolution.State == "explicit" {
				selected.ExplicitLyricID = link.LyricID
			}
		}
		if err = capability.check(pin, envelope, 1, track.MediaID, selected); err != nil {
			t.Fatal("valid indexed decision rejected", err)
		}
		if capability.check(pin, envelope, 2, track.MediaID, selected) == nil {
			t.Fatal("changed evidence version accepted")
		}
		changed := selected
		changed.Evidence = strings.Repeat("e", 64)
		if capability.check(pin, envelope, 1, track.MediaID, changed) == nil {
			t.Fatal("changed lyric evidence accepted")
		}
	}
	if len(audioIDs) == 0 {
		t.Fatal("fixture must exercise audio")
	}
	batch, err := capability.verified.PrepareDecisionBatch(pin, envelope, 1, audioIDs)
	if err != nil || batch.CheckForCommit(pin, envelope, 1) != nil {
		t.Fatal("valid signed batch rejected", err)
	}
	for _, id := range audioIDs {
		state, lyricID, err := batch.Decision(id)
		if err != nil || capability.verified.CheckDecision(pin, envelope, 1, id, state, lyricID) != nil {
			t.Fatal("batch differs from individual decision", id, err)
		}
	}
	if batch.CheckForCommit(pin, envelope, 2) == nil {
		t.Fatal("changed evidence version accepted at commit")
	}
	changedPin := pin
	changedPin.TargetNode = strings.Repeat("f", 32)
	if batch.CheckForCommit(changedPin, envelope, 1) == nil {
		t.Fatal("changed target accepted at commit")
	}
	changedEnvelope := envelope
	changedEnvelope.Cipher = append([]byte(nil), envelope.Cipher...)
	changedEnvelope.Cipher[len(changedEnvelope.Cipher)-1] ^= 1
	if batch.CheckForCommit(pin, changedEnvelope, 1) == nil {
		t.Fatal("changed encrypted source accepted at commit")
	}
	if _, err = capability.verified.PrepareDecisionBatch(pin, envelope, 1, []string{audioIDs[0], audioIDs[0]}); err == nil {
		t.Fatal("duplicate batch track accepted")
	}
	if _, err = capability.verified.PrepareDecisionBatch(pin, envelope, 1, []string{"unknown"}); err == nil {
		t.Fatal("unknown batch track accepted")
	}

	// Authenticate the pending row from an actual SQLite transaction, then
	// compare the signed source's complete lyric relation. The fixture does
	// not claim an owner fence, runtime admission or a production commit.
	track := complete.Projection.Media[0]
	resolution, err := sourceLyricResolution(complete, track, capability.verified.Digest(), generation)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := sourceObjectTreeFacts(complete, track, resolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		mutate    func(*sealedtree.Facts)
		path      string
		wantError bool
	}{
		{name: "exact source"},
		{name: "changed relation time", mutate: func(f *sealedtree.Facts) { f.Lyric.CreatedAt = "forged" }, wantError: true},
		{name: "changed relation path", mutate: func(f *sealedtree.Facts) { f.Lyric.LegacyLyricPath = "lyrics/wrong.lrc" }, wantError: true},
		{name: "changed pending tree path", path: "music/album/other.mp3", wantError: true},
		{name: "changed lyric id with internally valid digest", mutate: func(f *sealedtree.Facts) {
			f.Lyric.LyricID = strings.Repeat("d", 64)
			f.LyricResolution.Evidence, err = sealedtree.LyricResolutionEvidence(f.LyricResolution.SourceDigest, f.LyricResolution.SourceGeneration, f.ObjectID, "explicit", f.Lyric.LyricID)
			if err != nil {
				t.Fatal(err)
			}
		}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := facts
			copyLyric := *facts.Lyric
			copyResolution := *facts.LyricResolution
			candidate.Lyric, candidate.LyricResolution = &copyLyric, &copyResolution
			if tc.mutate != nil {
				tc.mutate(&candidate)
			}
			path := track.Path
			if tc.path != "" {
				path = tc.path
			}
			db, tree, op := syntheticPendingTree(t, candidate, path)
			nodeVault, e := vault.Open(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			private, e := nodeVault.Seal(protocol.Encode(masterSeed))
			if e != nil {
				t.Fatal(e)
			}
			pinJSON, e := json.Marshal(pin)
			if e != nil {
				t.Fatal(e)
			}
			sealedPin, e := nodeVault.Seal(string(pinJSON))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec(`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,endpoint TEXT,private_key TEXT,created_at INTEGER)`); e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master','https://target.test',?,1)`, pin.TargetNode, private); e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec(`INSERT INTO sealed_tree_source_pin VALUES(1,?)`, []byte(sealedPin)); e != nil {
				t.Fatal(e)
			}
			if _, e := db.Exec(`CREATE TABLE test_mutation (value TEXT NOT NULL)`); e != nil {
				t.Fatal(e)
			}
			tx, e := db.BeginTx(context.Background(), nil)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = tx.Exec(`INSERT INTO test_mutation(value) VALUES('pending')`); e != nil {
				t.Fatal(e)
			}
			e = validatePinnedSourceLyricsTx(context.Background(), tx, nodeVault, tree, batch, pin, envelope, 1, []string{op})
			if (e != nil) != tc.wantError {
				t.Fatalf("unexpected pending validation result: %v", e)
			}
			if !tc.wantError {
				wrongPin := pin
				wrongPin.Generation = strings.Repeat("f", 64)
				if validatePinnedSourceLyricsTx(context.Background(), tx, nodeVault, tree, batch, wrongPin, envelope, 1, []string{op}) == nil {
					t.Fatal("caller-supplied wrong independent pin accepted")
				}
				wrongVault, err := vault.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if validatePinnedSourceLyricsTx(context.Background(), tx, wrongVault, tree, batch, pin, envelope, 1, []string{op}) == nil {
					t.Fatal("foreign target vault accepted")
				}
				if validatePinnedSourceLyricsTx(context.Background(), tx, nodeVault, tree, batch, pin, changedEnvelope, 1, []string{op}) == nil {
					t.Fatal("changed signed source accepted")
				}
			}
			if e = tx.Rollback(); e != nil {
				t.Fatal(e)
			}
			var count int
			if e = db.QueryRow(`SELECT COUNT(*) FROM test_mutation`).Scan(&count); e != nil || count != 0 {
				t.Fatalf("rollback: %d %v", count, e)
			}
		})
	}
	for _, otherTrack := range complete.Projection.Media[1:] {
		track := otherTrack
		t.Run("pending_"+track.Path, func(t *testing.T) {
			resolution, e := sourceLyricResolution(complete, track, capability.verified.Digest(), generation)
			if e != nil {
				t.Fatal(e)
			}
			facts, e := sourceObjectTreeFacts(complete, track, resolution)
			if e != nil {
				t.Fatal(e)
			}
			db, tree, op := syntheticPendingTree(t, facts, track.Path)
			tx, e := db.BeginTx(context.Background(), nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if e = tree.ValidatePendingSourceLyricsTx(context.Background(), tx, batch, pin, envelope, 1, []string{op}); e != nil {
				t.Fatal("valid pending decision rejected", e)
			}
			if e = tree.ValidatePendingSourceLyricsTx(context.Background(), tx, batch, pin, envelope, 1, []string{op, op}); e == nil {
				t.Fatal("duplicate operation accepted")
			}
			if e = tree.ValidatePendingSourceLyricsTx(context.Background(), tx, batch, pin, changedEnvelope, 1, []string{op}); e == nil {
				t.Fatal("changed source accepted")
			}
		})
	}
	// Mutating the caller's input list cannot change the private batch.
	first := audioIDs[0]
	audioIDs[0] = "unknown"
	if _, _, err = batch.Decision(first); err != nil {
		t.Fatal("batch changed with caller list", err)
	}
}
