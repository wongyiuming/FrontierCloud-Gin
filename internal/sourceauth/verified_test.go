package sourceauth

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
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

func TestVerifiedSnapshotBindsEncryptedSourceAndCurrentAuthority(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin := Pin{SourceNode: strings.Repeat("a", 32), TargetNode: strings.Repeat("b", 32), SourceKeyID: "key-id", HostKeyDigest: strings.Repeat("c", 64), AuthorityKind: "ssh-collector-v1", SourcePublic: pub, TargetReceiver: receiver.PublicKey().Bytes(), Generation: strings.Repeat("d", 64)}
	challenge := strings.Repeat("e", 64)
	now := time.Now().Unix()
	snapshot := store.MediaSourceSnapshot{Version: 1, AuthorityKind: pin.AuthorityKind, SourceSSHHostKeySHA256: pin.HostKeyDigest, SourceNode: pin.SourceNode, SourcePublic: protocol.Encode(pub), TargetNode: pin.TargetNode, TargetReceiver: pin.TargetReceiver, Challenge: challenge, IssuedUnix: now, ExpiresUnix: now + 120}
	for _, section := range columns {
		snapshot.Sections = append(snapshot.Sections, store.MediaSourceSection{Name: section.name, Columns: append([]string(nil), section.fields...), Rows: [][]*string{}})
	}
	one, key, created := "1", pin.SourceKeyID, "today"
	snapshot.Sections[8].Rows = [][]*string{{&one, &key, &created}}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	signature, err := protocol.Sign(protocol.Encode(private.Seed()), map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hex.EncodeToString(hash[:]), "source_node": pin.SourceNode, "target_node": pin.TargetNode, "challenge": challenge})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshotcrypt.Seal(store.SignedMediaSourceSnapshot{Snapshot: snapshot, Signature: signature}, receiver.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(envelope, receiver, pin, challenge, 1)
	if err != nil || verified.Digest() != hex.EncodeToString(hash[:]) || verified.Check(pin, challenge, envelope, 1) != nil {
		t.Fatal("valid observation rejected", err)
	}
	if (&Verified{}).Check(pin, challenge, envelope, 1) == nil {
		t.Fatal("zero capability accepted")
	}
	if verified.Check(pin, challenge, envelope, 2) == nil || verified.Check(pin, strings.Repeat("f", 64), envelope, 1) == nil {
		t.Fatal("changed version/challenge accepted")
	}
	other := pin
	other.TargetNode = strings.Repeat("f", 32)
	if verified.Check(other, challenge, envelope, 1) == nil {
		t.Fatal("changed target accepted")
	}
	mutated := envelope
	mutated.Cipher = append([]byte(nil), envelope.Cipher...)
	mutated.Cipher[len(mutated.Cipher)-1] ^= 1
	if verified.Check(pin, challenge, mutated, 1) == nil {
		t.Fatal("changed ciphertext accepted")
	}
	if _, err = Verify(mutated, receiver, pin, challenge, 1); err == nil {
		t.Fatal("corrupted source accepted")
	}
	oversized := envelope
	oversized.Cipher = make([]byte, 3*1024*1024)
	if verified.Check(pin, challenge, oversized, 1) == nil {
		t.Fatal("oversized envelope accepted")
	}
	if _, err = Verify(oversized, receiver, pin, challenge, 1); err == nil {
		t.Fatal("oversized source accepted")
	}
	other = pin
	other.SourcePublic = make([]byte, 32)
	if _, err = Verify(envelope, receiver, other, challenge, 1); err == nil {
		t.Fatal("foreign source accepted")
	}
	verified.expiresAt = time.Now().Unix()
	if verified.Check(pin, challenge, envelope, 1) == nil {
		t.Fatal("expired capability accepted")
	}
}
