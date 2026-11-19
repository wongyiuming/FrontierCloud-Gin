//go:build linux

package preprodimport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestSourceAuthorityRequiresAuthenticatedCompletePin(t *testing.T) {
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	p := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "source-node-v1", SourceNode: strings.Repeat("1", 32), SourceKeyID: strings.Repeat("2", 64), SourcePublic: bytes.Repeat([]byte{3}, 32), TargetNode: strings.Repeat("4", 32), TargetMasterPublic: bytes.Repeat([]byte{5}, 32), TargetX25519: bytes.Repeat([]byte{6}, 32), Generation: strings.Repeat("7", 64)}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := v.Seal(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeSourceAuthority(v, sealed)
	if err != nil || got.SourceNode != p.SourceNode || got.Generation != p.Generation || !bytes.Equal(got.SourcePublic, p.SourcePublic) {
		t.Fatalf("pin: %+v %v", got, err)
	}
	other, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeSourceAuthority(other, sealed); err == nil {
		t.Fatal("wrong vault accepted")
	}
	if _, err = decodeSourceAuthority(v, sealed[:len(sealed)-1]+"!"); err == nil {
		t.Fatal("tampered pin accepted")
	}
	p.SourcePublic = make([]byte, 32)
	if validSourceAuthority(p) {
		t.Fatal("zero source public key accepted")
	}
}
