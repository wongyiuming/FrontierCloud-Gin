package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

func TestHistoricalGeneration6ReleaseVectorPreservedWithoutGrantingCurrentAdmission(t *testing.T) {
	raw, e := os.ReadFile("../../protocol/v2/vectors/release-manifest-generation6.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors struct {
		Cases []struct {
			Name     string          `json:"name"`
			Manifest json.RawMessage `json:"manifest"`
		} `json:"cases"`
	}
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors.Cases {
		if v.Name == "distinct-private-artifacts" {
			if _, e = ParseManifest(v.Manifest); e == nil {
				t.Fatal("old release admitted as a current schema release")
			}
			value, e := protocol.ParseStrictJSON(v.Manifest, MaxManifestBytes)
			if e != nil {
				t.Fatal(e)
			}
			canonical, e := protocol.Canonical(value)
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(canonical)
			if hex.EncodeToString(sum[:]) != "0f5747ea8a068d058e28a40cb6430f83d02930a49be0aef152396e324dfb7663" {
				t.Fatal("historical generation-6 release bytes changed")
			}
			return
		}
	}
	t.Fatal("retained historical release vector missing")
}
