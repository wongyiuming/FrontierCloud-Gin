package preprodimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func sourceRows(values ...string) []*string {
	out := make([]*string, len(values))
	for i := range values {
		value := values[i]
		out[i] = &value
	}
	return out
}

func completeSourceFixture(s Snapshot) completeSnapshot {
	facts := syntheticCompleteFacts(s)
	for _, lyric := range s.Lyrics {
		facts.Objects = append(facts.Objects, sourceObjectFact{ID: lyric.ID, Kind: "lyric", Path: lyric.Path, CreatedAt: "1", UpdatedAt: "2"})
	}
	return completeSnapshot{Projection: s, Facts: facts}
}

func syntheticSourceForComplete(c completeSnapshot) store.MediaSourceSnapshot {
	s := store.MediaSourceSnapshot{Sections: make([]store.MediaSourceSection, len(sourceSnapshotColumns))}
	for i, section := range sourceSnapshotColumns {
		s.Sections[i] = store.MediaSourceSection{Name: section.name, Columns: append([]string(nil), section.columns...), Rows: [][]*string{}}
	}
	for _, f := range c.Facts.Objects {
		hash := sha256.Sum256([]byte(f.Path))
		s.Sections[0].Rows = append(s.Sections[0].Rows, sourceRows(f.ID, f.Kind, f.Path, hex.EncodeToString(hash[:]), f.CreatedAt, f.UpdatedAt))
	}
	for _, m := range c.Projection.Media {
		for _, f := range c.Facts.Placements {
			if f.MediaID == m.MediaID {
				s.Sections[1].Rows = append(s.Sections[1].Rows, sourceRows(m.MediaID, m.SourceID, m.ObjectID, m.Path, m.Kind, strconv.FormatInt(m.Size, 10), f.ETag, f.State, strconv.FormatInt(f.CreatedAt, 10), strconv.FormatInt(f.UpdatedAt, 10)))
			}
		}
	}
	for _, f := range c.Facts.Visibility {
		s.Sections[2].Rows = append(s.Sections[2].Rows, sourceRows(f.Path, strconv.FormatInt(f.Hidden, 10), f.UpdatedAt))
	}
	for _, f := range c.Facts.Playback {
		s.Sections[3].Rows = append(s.Sections[3].Rows, sourceRows(f.MediaID, f.Path, strconv.Itoa(f.Preference), strconv.FormatInt(f.PlayScore, 10), f.CreatedAt, f.UpdatedAt))
	}
	for _, f := range c.Facts.LyricLinks {
		s.Sections[4].Rows = append(s.Sections[4].Rows, sourceRows(f.MediaID, f.MediaPath, f.LyricID, f.LyricPath, f.CreatedAt, f.UpdatedAt))
	}
	for _, f := range c.Facts.Encryption {
		value := ""
		for _, m := range c.Projection.Media {
			if m.MediaID == f.ObjectID && m.Encryption != nil {
				b, _ := json.Marshal(m.Encryption)
				value = string(b)
			}
		}
		r := sourceRows(f.Kind, f.ObjectID, f.FileID, value, strconv.FormatInt(f.CreatedAt, 10))
		if value == "" {
			r[3] = nil
		}
		s.Sections[5].Rows = append(s.Sections[5].Rows, r)
	}
	for i, mapping := range c.Projection.Mappings {
		id := testID(strconv.Itoa(i+4), 32)
		row := sourceRows(mapping.SourceID, id, "Follower", "Direct", "1", "0", "0", "0", "0", "online", "1", "1")
		if mapping.Role == "master" {
			row[1] = nil
			*row[2], *row[3] = "MasterLocal", "Local"
		} else {
			s.Sections[7].Rows = append(s.Sections[7].Rows, sourceRows(id, mapping.SourceID, "https://source.test", protocol.Encode(bytes.Repeat([]byte{byte(i + 1)}, 32)), "downstream", "Direct", "active", "1"))
		}
		s.Sections[6].Rows = append(s.Sections[6].Rows, row)
	}
	s.SourceNode = c.Projection.Mappings[0].SourceID
	s.Sections[8].Rows = [][]*string{sourceRows("1", c.Projection.PremasterKeyID, "1")}
	return s
}

func TestCompleteSourceFactsRequireExactCoverage(t *testing.T) {
	s, _, _, _ := fixture(t)
	complete := completeSourceFixture(s)
	source := syntheticSourceForComplete(complete)
	if err := compareCompleteSourceFacts(source, complete); err != nil {
		t.Fatal(err)
	}
	// The user explicitly excluded this owner; its media cannot be resurrected.
	source.Sections[1].Rows = append(source.Sections[1].Rows, sourceRows(testID("9", 64), s.ExcludedSourceIDs[0], testID("8", 64), "music/excluded/song.mp3", "audio", "1", "old", "active", "1", "2"))
	if err := compareCompleteSourceFacts(source, complete); err != nil {
		t.Fatal("excluded owner", err)
	}
	for _, tc := range []struct {
		name                 string
		section, row, column int
		value                string
	}{
		{"object path", 0, 0, 2, "music/wrong/song.mp3"}, {"object locator", 0, 0, 3, testID("a", 64)}, {"media owner", 1, 0, 1, testID("2", 32)},
		{"media size", 1, 0, 5, "0"}, {"inactive media", 1, 0, 7, "pending_delete"},
		{"visibility", 2, 0, 1, "2"}, {"playback", 3, 0, 2, "999"},
		{"lyric relation", 4, 0, 3, "lyrics/wrong.lrc"}, {"encryption descriptor", 5, 0, 3, "{}"},
		{"follower member", 6, 1, 0, testID("9", 32)}, {"follower relationship", 7, 0, 1, testID("9", 32)},
		{"follower public key", 7, 0, 3, "invalid"}, {"source key id", 8, 0, 1, testID("9", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := syntheticSourceForComplete(complete)
			value := tc.value
			copy.Sections[tc.section].Rows[tc.row][tc.column] = &value
			if err := compareCompleteSourceFacts(copy, complete); err == nil {
				t.Fatal("mismatch accepted")
			}
		})
	}
	missing := syntheticSourceForComplete(complete)
	missing.Sections[4].Rows = nil
	if err := compareCompleteSourceFacts(missing, complete); err == nil {
		t.Fatal("missing lyric relation accepted")
	}
	duplicate := syntheticSourceForComplete(complete)
	duplicate.Sections[2].Rows = append(duplicate.Sections[2].Rows, duplicate.Sections[2].Rows[0])
	if err := compareCompleteSourceFacts(duplicate, complete); err == nil {
		t.Fatal("duplicate visibility accepted")
	}
	tombstone := syntheticSourceForComplete(complete)
	empty := ""
	tombstone.Sections[5].Rows[len(tombstone.Sections[5].Rows)-1][3] = &empty
	if err := compareCompleteSourceFacts(tombstone, complete); err == nil {
		t.Fatal("empty descriptor accepted as NULL tombstone")
	}
}

func TestCompleteSourcePreservesLongUnicodePaths(t *testing.T) {
	s, _, _, _ := fixture(t)
	longDir := "music/" + strings.Repeat("🧪", 300) + "/" + strings.Repeat("中", 200)
	name := longDir + "/song.mp3"
	if len(name) <= 1024 {
		t.Fatal("fixture is not a long UTF-8 path")
	}
	s.Media[0].Path = name
	s.Visibility = append(s.Visibility, Visibility{Path: longDir, Hidden: true})
	complete := completeSourceFixture(s)
	complete.Facts.LyricLinks[0].MediaPath = name
	complete.Facts.Playback[0].Path = longDir
	if _, err := completeSnapshotDigest(complete); err != nil {
		t.Fatalf("long path projection: %v", err)
	}
	if err := compareCompleteSourceFacts(syntheticSourceForComplete(complete), complete); err != nil {
		t.Fatalf("long path source: %v", err)
	}
	if validPath("music/"+strings.Repeat("🧪", 1025)+"/song.mp3", "audio") {
		t.Fatal("overlong path accepted")
	}
}

func TestCompleteSourceRequiresSignatureAndMatchesAllFacts(t *testing.T) {
	s, _, _, _ := fixture(t)
	complete := completeSourceFixture(s)
	generation, err := completeSnapshotDigest(complete)
	if err != nil {
		t.Fatal(err)
	}
	private := protocol.Encode(bytes.Repeat([]byte{7}, 32))
	public, err := protocol.PublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicRaw, err := protocol.Decode(public)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := receiverFromMasterSeed(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	challenge := testID("9", 64)
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "ssh-collector-v1", SourceSSHHostKeySHA256: testID("a", 64), SourceTLSOrigin: "https://source.test", SourceTLSSPKISHA256: testID("b", 64), SourceNode: s.Mappings[0].SourceID, SourceKeyID: s.PremasterKeyID, SourcePublic: publicRaw, TargetNode: s.Mappings[0].TargetID, TargetMasterPublic: bytes.Repeat([]byte{6}, 32), TargetX25519: receiver.PublicKey().Bytes(), Generation: generation}
	pin.ImportScope = syntheticImportScope(s)
	for _, mapping := range s.Mappings {
		pin.SourceOwners = append(pin.SourceOwners, sourceOwnerPin{NodeID: mapping.SourceID, SSHHostKeySHA256: pin.SourceSSHHostKeySHA256})
	}
	source := syntheticSourceForComplete(complete)
	source.Version, source.AuthorityKind, source.SourceNode, source.SourcePublic = 1, pin.AuthorityKind, pin.SourceNode, public
	source.SourceSSHHostKeySHA256 = pin.SourceSSHHostKeySHA256
	source.TargetNode, source.TargetReceiver, source.Challenge = pin.TargetNode, pin.TargetX25519, challenge
	source.IssuedUnix, source.ExpiresUnix = now.Unix(), now.Add(3*time.Minute).Unix()
	source.Sections[8].Rows = [][]*string{sourceRows("1", pin.SourceKeyID, "1")}
	seal := func(s store.MediaSourceSnapshot) store.EncryptedMediaSourceSnapshot {
		b, e := json.Marshal(s)
		if e != nil {
			t.Fatal(e)
		}
		hash := sha256.Sum256(b)
		signature, e := protocol.Sign(private, map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hex.EncodeToString(hash[:]), "source_node": s.SourceNode, "target_node": s.TargetNode, "challenge": s.Challenge})
		if e != nil {
			t.Fatal(e)
		}
		envelope, e := snapshotcrypt.Seal(store.SignedMediaSourceSnapshot{Snapshot: s, Signature: signature}, receiver.PublicKey().Bytes())
		if e != nil {
			t.Fatal(e)
		}
		return envelope
	}
	envelope := seal(source)
	if _, _, err = authenticateCompleteSource(envelope, receiver, pin, challenge, now, complete); err != nil {
		t.Fatal(err)
	}
	changed := source
	changed.Sections = append([]store.MediaSourceSection(nil), source.Sections...)
	changed.Sections[2].Rows = append([][]*string(nil), source.Sections[2].Rows...)
	row := append([]*string(nil), changed.Sections[2].Rows[0]...)
	hidden := "0"
	if *row[1] == hidden {
		hidden = "1"
	}
	row[1] = &hidden
	changed.Sections[2].Rows[0] = row
	if _, _, err = authenticateCompleteSource(seal(changed), receiver, pin, challenge, now, complete); err == nil {
		t.Fatal("validly signed but mismatched source facts accepted")
	}
	wrong := pin
	wrong.SourcePublic = bytes.Repeat([]byte{9}, 32)
	if _, _, err = authenticateCompleteSource(envelope, receiver, wrong, challenge, now, complete); err == nil {
		t.Fatal("untrusted signer accepted")
	}
	wrong = pin
	wrong.ImportScope = nil
	if _, _, err = authenticateCompleteSource(envelope, receiver, wrong, challenge, now, complete); err == nil {
		t.Fatal("unapproved import scope accepted")
	}
	wrong = pin
	changedScope := *pin.ImportScope
	changedScope.ExcludedTencentSourceID = testID("8", 32)
	wrong.ImportScope = &changedScope
	if _, _, err = authenticateCompleteSource(envelope, receiver, wrong, challenge, now, complete); err == nil {
		t.Fatal("unapproved excluded owner accepted")
	}
	wrong = pin
	changedScope = *pin.ImportScope
	changedScope.Mappings = append([]Mapping(nil), pin.ImportScope.Mappings...)
	changedScope.Mappings[1].TargetID = testID("8", 32)
	wrong.ImportScope = &changedScope
	if _, _, err = authenticateCompleteSource(envelope, receiver, wrong, challenge, now, complete); err == nil {
		t.Fatal("unapproved owner mapping accepted")
	}
	wrong = pin
	wrong.SourceOwners = append([]sourceOwnerPin(nil), pin.SourceOwners[:2]...)
	if _, _, err = authenticateCompleteSource(envelope, receiver, wrong, challenge, now, complete); err == nil {
		t.Fatal("missing mapped owner SSH pin accepted")
	}
}

// Only object-scoped facts identified through an explicitly excluded source
// owner are dropped. Shared path-based security facts and retained tombstones
// remain part of the authenticated complete snapshot.
func TestExcludedOwnerDependentFactsCannotResurrectOrHideRetainedData(t *testing.T) {
	s, _, _, _ := fixture(t)
	complete := completeSourceFixture(s)
	excludedID := testID("9", 64)
	makeSource := func() store.MediaSourceSnapshot {
		src := syntheticSourceForComplete(complete)
		src.Sections[1].Rows = append(src.Sections[1].Rows, sourceRows(excludedID, s.ExcludedSourceIDs[0], testID("7", 64), "music/excluded/song.mp3", "audio", "1", "old", "active", "1", "2"))
		src.Sections[3].Rows = append(src.Sections[3].Rows, sourceRows(excludedID, "music/excluded/song.mp3", "2", "3", "1", "2"))
		src.Sections[4].Rows = append(src.Sections[4].Rows, sourceRows(excludedID, "music/excluded/song.mp3", s.Lyrics[0].ID, s.Lyrics[0].Path, "1", "2"))
		descriptor, _ := json.Marshal(s.Media[0].Encryption)
		src.Sections[5].Rows = append(src.Sections[5].Rows, sourceRows("media", excludedID, s.Media[0].Encryption.FileID, string(descriptor), "1"))
		return src
	}
	if err := compareCompleteSourceFacts(makeSource(), complete); err != nil {
		t.Fatalf("explicit excluded media: %v", err)
	}
	t.Run("duplicate placement", func(t *testing.T) {
		src := makeSource()
		src.Sections[1].Rows = append(src.Sections[1].Rows, src.Sections[1].Rows[len(src.Sections[1].Rows)-1])
		if compareCompleteSourceFacts(src, complete) == nil {
			t.Fatal("duplicate accepted")
		}
	})
	t.Run("included ID collision", func(t *testing.T) {
		src := makeSource()
		*src.Sections[1].Rows[len(src.Sections[1].Rows)-1][0] = s.Media[0].MediaID
		if compareCompleteSourceFacts(src, complete) == nil {
			t.Fatal("included object collision accepted")
		}
	})
	t.Run("duplicate excluded dependent fact", func(t *testing.T) {
		src := makeSource()
		src.Sections[3].Rows = append(src.Sections[3].Rows, src.Sections[3].Rows[len(src.Sections[3].Rows)-1])
		if compareCompleteSourceFacts(src, complete) == nil {
			t.Fatal("duplicate excluded fact accepted")
		}
	})
	t.Run("excluded tombstone ambiguity", func(t *testing.T) {
		src := makeSource()
		src.Sections[5].Rows[len(src.Sections[5].Rows)-1][3] = nil
		if compareCompleteSourceFacts(src, complete) == nil {
			t.Fatal("excluded tombstone accepted")
		}
	})
	t.Run("retained tombstone collision", func(t *testing.T) {
		src := makeSource()
		*src.Sections[1].Rows[len(src.Sections[1].Rows)-1][0] = s.RetiredNonces[0].ObjectID
		*src.Sections[5].Rows[len(src.Sections[5].Rows)-1][1] = s.RetiredNonces[0].ObjectID
		if compareCompleteSourceFacts(src, complete) == nil {
			t.Fatal("retained tombstone collision accepted")
		}
	})
	t.Run("excluded S3 owner is not Tencent", func(t *testing.T) {
		src := makeSource()
		src.Sections[6].Rows = append(src.Sections[6].Rows, sourceRows(s.ExcludedSourceIDs[0], testID("6", 32), "S3", "S3", "1", "0", "0", "0", "0", "online", "1", "1"))
		if compareCompleteSourceFacts(src, complete) == nil {
			t.Fatal("S3 owner silently excluded")
		}
	})
	t.Run("shared visibility not discarded", func(t *testing.T) {
		src := makeSource()
		src.Sections[2].Rows = src.Sections[2].Rows[1:]
		if compareCompleteSourceFacts(src, complete) == nil {
			t.Fatal("missing visibility accepted")
		}
	})
}
