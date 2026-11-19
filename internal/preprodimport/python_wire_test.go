package preprodimport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPythonCollectorEnvelopeInteroperatesWithGo(t *testing.T) {
	python := os.Getenv("FRONTIERCLOUD_TEST_PYTHON_BINARY")
	var raw []byte
	var err error
	if python != "" {
		cmd := exec.Command(python, "-B", "../../tests/preprod_collector_wire_fixture.py")
		raw, err = cmd.Output()
	} else if fixture := os.Getenv("FRONTIERCLOUD_TEST_PYTHON_WIRE_FIXTURE"); fixture != "" {
		raw, err = os.ReadFile(fixture)
	} else {
		t.Skip("synthetic Python cryptography runtime not configured")
	}
	if err != nil {
		t.Fatal("synthetic collector failed", err)
	}
	var fixture struct {
		Envelope     store.EncryptedMediaSourceSnapshot `json:"envelope"`
		Digest, Host string
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	receiver, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey)
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "ssh-collector-v1", SourceSSHHostKeySHA256: fixture.Host, SourceTLSOrigin: "https://source.test", SourceTLSSPKISHA256: strings.Repeat("4", 64), SourceOwners: []sourceOwnerPin{{NodeID: strings.Repeat("1", 32), SSHHostKeySHA256: fixture.Host}}, SourceNode: strings.Repeat("1", 32), SourceKeyID: strings.Repeat("c", 64), SourcePublic: public, TargetNode: strings.Repeat("2", 32), TargetMasterPublic: bytes.Repeat([]byte{9}, 32), TargetX25519: receiver.PublicKey().Bytes(), Generation: strings.Repeat("5", 64)}
	signed, digest, err := openMediaSourceSnapshot(fixture.Envelope, receiver, pin, strings.Repeat("3", 64), time.Now())
	if err != nil || digest != fixture.Digest || len(signed.Snapshot.Sections[0].Rows) != 1 {
		t.Fatalf("collector signature, digest or encryption: %v", err)
	}
	if *signed.Snapshot.Sections[0].Rows[0][2] != "music/专辑/<歌曲>&.mp3" {
		t.Fatal("synthetic Unicode path changed")
	}
	wrong := pin
	wrong.SourcePublic = bytes.Repeat([]byte{6}, 32)
	if _, _, err := openMediaSourceSnapshot(fixture.Envelope, receiver, wrong, strings.Repeat("3", 64), time.Now()); err == nil {
		t.Fatal("wrong collector pin accepted")
	}
	fixture.Envelope.Cipher[0] ^= 1
	if _, _, err := openMediaSourceSnapshot(fixture.Envelope, receiver, pin, strings.Repeat("3", 64), time.Now()); err == nil {
		t.Fatal("modified ciphertext accepted")
	}
}
