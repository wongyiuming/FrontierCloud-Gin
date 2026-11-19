package protocol

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestOpaqueAdminDownloadCannotBeUsedAsPublicIngressGrant(t *testing.T) {
	meta, err := mediacrypto.NewMetadata(32)
	if err != nil {
		t.Fatal(err)
	}
	credential := Encode(bytes.Repeat([]byte{9}, 48))
	for _, mode := range []string{"Direct", "Relay"} {
		t.Run(mode, func(t *testing.T) {
			origin := ""
			if mode == "Direct" {
				origin = "https://owner.example"
			}
			token, err := OpaqueAdminDownloadToken(credential, strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32), strings.Repeat("a", 64),
				"https://admin.example", strings.Repeat("4", 32), strings.Repeat("b", 64), mode, origin, 7, 1000, 1100, meta.CiphertextSize, strings.Repeat("c", 64), &meta)
			if err != nil {
				t.Fatal(err)
			}
			claim, err := VerifyOpaqueAdminDownloadToken(credential, token, 1000)
			if err != nil || claim["transport"] != mode || claim["origin"] != "https://admin.example" || claim["target_origin"] != origin {
				t.Fatal("Admin placement scope rejected", err)
			}
			if _, err := VerifyOpaqueIngressMediaToken(credential, token, 1000); err == nil {
				t.Fatal("Admin bearer became a public-ingress bearer")
			}
			if _, err := VerifyOpaqueAdminDownloadToken(credential, token, 1100); err == nil {
				t.Fatal("expired Admin bearer accepted")
			}
		})
	}
}
