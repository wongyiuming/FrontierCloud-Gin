package preprodimport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestWeakETagRequiresPinnedCollectorObjectProof(t *testing.T) {
	seed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	receiver, err := receiverFromMasterSeed(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	source, target, id, object, blob, alias, digest := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64), strings.Repeat("7", 64)
	host, challenge, snapshotDigest := strings.Repeat("8", 64), strings.Repeat("9", 64), strings.Repeat("a", 64)
	name, kind, size, etag, state, created, updated := "music/专辑/歌曲.mp3", "audio", "32", "W/\"old\"", "active", "1", "2"
	fileID, descriptor, ekind, local, memberKind, zero := strings.Repeat("b", 32), "{}", "media", "Local", "MasterLocal", "0"
	media := Media{MediaID: id, ObjectID: object, SourceID: source, Path: name, Kind: kind, Size: 32, SHA256: digest, Encryption: &mediacrypto.Metadata{}}
	s := store.MediaSourceSnapshot{SourceNode: source, ExpiresUnix: now.Add(4 * time.Minute).Unix(), Sections: []store.MediaSourceSection{
		{Name: "placements", Rows: [][]*string{{&id, &source, &object, &name, &kind, &size, &etag, &state, &created, &updated}}},
		{Name: "encryption", Rows: [][]*string{{&ekind, &id, &fileID, &descriptor, &created}}},
		{Name: "members", Rows: [][]*string{{&source, nil, &memberKind, &local, &zero, &zero, &zero, &zero, &zero, &state, &zero, &updated}}},
	}}
	facts, err := sourceObjectFactsDigest(s, media)
	if err != nil {
		t.Fatal(err)
	}
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "ssh-collector-v1", SourceSSHHostKeySHA256: host, SourceTLSOrigin: "https://source.test", SourceTLSSPKISHA256: strings.Repeat("c", 64), SourceOwners: []sourceOwnerPin{{NodeID: source, SSHHostKeySHA256: host}}, SourceNode: source, SourceKeyID: strings.Repeat("d", 64), SourcePublic: seed.Public().(ed25519.PublicKey), TargetNode: target, TargetMasterPublic: bytes.Repeat([]byte{9}, 32), TargetX25519: receiver.PublicKey().Bytes(), Generation: strings.Repeat("e", 64)}
	scope := objectProofScope{TargetOwnerID: target, TargetBlobID: blob, TargetReadAlias: alias, Challenge: challenge}
	p := sshObjectProof{Version: 1, SourceNode: source, SourceOwnerID: source, OwnerSSHHostKeySHA256: host, SourceSnapshotDigest: snapshotDigest, BeforeFactsSHA256: facts, AfterFactsSHA256: facts, MediaID: id, SourceObjectID: object, Path: name, SHA256: digest, Size: 32, Device: 1, Inode: 2, MtimeNS: 3, CtimeNS: 4, TargetNode: target, TargetOwnerID: target, TargetBlobID: blob, TargetReadAlias: alias, Challenge: challenge, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(3 * time.Minute).Unix()}
	raw, _ := json.Marshal(p)
	h := sha256.Sum256(raw)
	signature, err := protocol.Sign(protocol.Encode(seed.Seed()), map[string]any{"kind": "frontiercloud-preprod-ssh-object-proof-v1", "sha256": hex.EncodeToString(h[:])})
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(signedSSHObjectProof{Proof: p, Signature: signature})
	envelope, err := snapshotcrypt.SealObjectProof(plain, receiver.PublicKey().Bytes())
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifySSHObjectProof(envelope, receiver, pin, s, snapshotDigest, media, scope, now); err != nil {
		t.Fatal(err)
	}
	wrong := pin
	wrong.SourceOwners = []sourceOwnerPin{{NodeID: source, SSHHostKeySHA256: strings.Repeat("f", 64)}}
	if verifySSHObjectProof(envelope, receiver, wrong, s, snapshotDigest, media, scope, now) == nil {
		t.Fatal("wrong owner pin accepted")
	}
	changed := scope
	changed.TargetBlobID = strings.Repeat("f", 64)
	if verifySSHObjectProof(envelope, receiver, pin, s, snapshotDigest, media, changed, now) == nil {
		t.Fatal("changed target locator accepted")
	}
	if verifySSHObjectProof(envelope, receiver, pin, s, snapshotDigest, media, scope, now.Add(3*time.Minute)) == nil {
		t.Fatal("expired proof accepted")
	}
	if _, err = snapshotcrypt.Open(envelope, receiver); err == nil {
		t.Fatal("object proof accepted as snapshot envelope")
	}
	t.Run("empty source requires the real empty digest", func(t *testing.T) {
		size = "0"
		media.Size = 0
		media.Encryption = nil
		s.Sections[1].Rows = nil
		emptyDigest := sha256.Sum256(nil)
		media.SHA256 = hex.EncodeToString(emptyDigest[:])
		facts, err := sourceObjectFactsDigest(s, media)
		if err != nil {
			t.Fatal(err)
		}
		p.Size, p.SHA256, p.BeforeFactsSHA256, p.AfterFactsSHA256 = 0, media.SHA256, facts, facts
		makeEnvelope := func(proof sshObjectProof) store.EncryptedMediaSourceSnapshot {
			body, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(body)
			sig, err := protocol.Sign(protocol.Encode(seed.Seed()), map[string]any{"kind": "frontiercloud-preprod-ssh-object-proof-v1", "sha256": hex.EncodeToString(hash[:])})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(signedSSHObjectProof{Proof: proof, Signature: sig})
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := snapshotcrypt.SealObjectProof(encoded, receiver.PublicKey().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			return sealed
		}
		if err := verifySSHObjectProof(makeEnvelope(p), receiver, pin, s, snapshotDigest, media, scope, now); err != nil {
			t.Fatal(err)
		}
		p.SHA256 = strings.Repeat("a", 64)
		media.SHA256 = p.SHA256
		if err := verifySSHObjectProof(makeEnvelope(p), receiver, pin, s, snapshotDigest, media, scope, now); err == nil {
			t.Fatal("empty object with wrong digest accepted")
		}
	})
}

func TestPlainMediaAndLyricFactsRemainOwnerBound(t *testing.T) {
	source, id, object := strings.Repeat("1", 32), strings.Repeat("2", 64), strings.Repeat("3", 64)
	name, kind, size, etag, state, created, updated := "music/专辑/歌曲.mp3", "audio", "5", "W/\"legacy\"", "active", "1", "2"
	zero, local, memberKind := "0", "Local", "MasterLocal"
	m := Media{MediaID: id, ObjectID: object, SourceID: source, Path: name, Kind: kind, Size: 5, SHA256: strings.Repeat("4", 64)}
	s := store.MediaSourceSnapshot{SourceNode: source, Sections: []store.MediaSourceSection{
		{Name: "placements", Rows: [][]*string{{&id, &source, &object, &name, &kind, &size, &etag, &state, &created, &updated}}},
		{Name: "members", Rows: [][]*string{{&source, nil, &memberKind, &local, &zero, &zero, &zero, &zero, &zero, &state, &zero, &updated}}},
	}}
	if _, err := sourceObjectFactsDigest(s, m); err != nil {
		t.Fatal("plaintext native media rejected", err)
	}
	lyricID, lyricPath, lyricKind, locator := strings.Repeat("5", 64), "lyrics/专辑/歌词.lrc", "lyric", strings.Repeat("6", 64)
	lyric := Media{MediaID: lyricID, ObjectID: lyricID, SourceID: source, Path: lyricPath, Kind: lyricKind, Size: 5, SHA256: strings.Repeat("7", 64)}
	s.Sections = append(s.Sections, store.MediaSourceSection{Name: "objects", Rows: [][]*string{{&lyricID, &lyricKind, &lyricPath, &locator, &created, &updated}}})
	if _, err := sourceObjectFactsDigest(s, lyric); err != nil {
		t.Fatal("plaintext lyric rejected", err)
	}
	lyric.SourceID = strings.Repeat("8", 32)
	if _, err := sourceObjectFactsDigest(s, lyric); err == nil {
		t.Fatal("lyric assigned to unpinned owner")
	}
}
