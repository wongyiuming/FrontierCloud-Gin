package media

import (
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestOpaqueRevisionExcludesHistoricalIdentity(t *testing.T) {
	placement := sealedtree.Placement{ObjectID: strings.Repeat("a", 64), NativeObjectID: strings.Repeat("b", 64), OwnerID: strings.Repeat("c", 32), ReadAlias: strings.Repeat("d", 64), BlobID: strings.Repeat("e", 64), SHA256: strings.Repeat("f", 64), Bytes: 123, ETag: "historical-etag"}
	baseline, err := opaqueSourceRevision(placement)
	if err != nil {
		t.Fatal(err)
	}
	changed := placement
	changed.ObjectID, changed.NativeObjectID, changed.OwnerID, changed.ETag = strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 32), "other-old-version"
	if got, err := opaqueSourceRevision(changed); err != nil || got != baseline {
		t.Fatal("historical identity entered opaque revision")
	}
	for _, mutate := range []func(*sealedtree.Placement){func(p *sealedtree.Placement) { p.ReadAlias = strings.Repeat("4", 64) }, func(p *sealedtree.Placement) { p.BlobID = strings.Repeat("5", 64) }, func(p *sealedtree.Placement) { p.SHA256 = strings.Repeat("6", 64) }, func(p *sealedtree.Placement) { p.Bytes++ }} {
		changed := placement
		mutate(&changed)
		if got, err := opaqueSourceRevision(changed); err != nil || got == baseline {
			t.Fatal("opaque version did not bind placement")
		}
	}
}
