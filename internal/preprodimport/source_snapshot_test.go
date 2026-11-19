package preprodimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSourceSnapshotRequiresIndependentIdentityAndExactFacts(t *testing.T) {
	seed := protocol.Encode(bytes.Repeat([]byte{8}, 32))
	public, err := protocol.PublicKey(seed)
	if err != nil { t.Fatal(err) }
	decoded, err := protocol.Decode(public)
	if err != nil { t.Fatal(err) }
	now := time.Now().UTC().Truncate(time.Second)
	challenge := strings.Repeat("6", 64)
	receiver, err := receiverFromMasterSeed(bytes.Repeat([]byte{5}, 32))
	if err != nil { t.Fatal(err) }
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "source-node-v1", SourceNode: strings.Repeat("1", 32), SourceKeyID: strings.Repeat("2", 64), SourcePublic: decoded, TargetNode: strings.Repeat("3", 32), TargetMasterPublic: bytes.Repeat([]byte{4}, 32), TargetX25519: receiver.PublicKey().Bytes(), Generation: strings.Repeat("7", 64)}
	s := store.MediaSourceSnapshot{Version: 1, AuthorityKind: "source-node-v1", SourceNode: pin.SourceNode, SourcePublic: public, TargetNode: pin.TargetNode, TargetReceiver: pin.TargetX25519, Challenge: challenge, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(5*time.Minute).Unix()}
	for _, section := range sourceSnapshotColumns {
		s.Sections = append(s.Sections, store.MediaSourceSection{Name: section.name, Columns: append([]string(nil), section.columns...), Rows: make([][]*string, 0)})
	}
	one, key, created := "1", pin.SourceKeyID, "123"
	s.Sections[len(s.Sections)-1].Rows = [][]*string{{&one, &key, &created}}
	raw, err := json.Marshal(s)
	if err != nil { t.Fatal(err) }
	digest := sha256.Sum256(raw)
	payload := map[string]any{"kind":"frontiercloud-preprod-media-source-v1", "sha256":hex.EncodeToString(digest[:]), "source_node":s.SourceNode, "target_node":s.TargetNode, "challenge":s.Challenge}
	signature, err := protocol.Sign(seed, payload)
	if err != nil { t.Fatal(err) }
	signed := store.SignedMediaSourceSnapshot{Snapshot:s, Signature:signature}
	if _, err = verifyMediaSourceSnapshot(signed, pin, challenge, now); err != nil { t.Fatal(err) }
	envelope, err := snapshotcrypt.Seal(signed, receiver.PublicKey().Bytes())
	if err != nil { t.Fatal(err) }
	if _, _, err = openMediaSourceSnapshot(envelope, receiver, pin, challenge, now); err != nil { t.Fatal(err) }
	wrongReceiver, err := receiverFromMasterSeed(bytes.Repeat([]byte{6}, 32))
	if err != nil { t.Fatal(err) }
	if _, _, err = openMediaSourceSnapshot(envelope, wrongReceiver, pin, challenge, now); err == nil { t.Fatal("wrong receiver opened snapshot") }
	damaged := envelope
	damaged.Cipher = append([]byte(nil), envelope.Cipher...)
	damaged.Cipher[0] ^= 1
	if _, _, err = openMediaSourceSnapshot(damaged, receiver, pin, challenge, now); err == nil { t.Fatal("tampered ciphertext opened") }
	if _, err = verifyMediaSourceSnapshot(signed, pin, strings.Repeat("9", 64), now); err == nil { t.Fatal("wrong challenge accepted") }
	other := pin
	other.SourcePublic = bytes.Repeat([]byte{9}, 32)
	if _, err = verifyMediaSourceSnapshot(signed, other, challenge, now); err == nil { t.Fatal("untrusted source accepted") }
	if _, err = verifyMediaSourceSnapshot(signed, pin, challenge, now.Add(5*time.Minute)); err == nil { t.Fatal("expired snapshot accepted") }
	signed.Snapshot.Sections[0].Rows = [][]*string{{&one, &one, &one, &one, &one, &one}}
	if _, err = verifyMediaSourceSnapshot(signed, pin, challenge, now); err == nil { t.Fatal("modified facts accepted") }
}
