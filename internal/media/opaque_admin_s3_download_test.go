package media

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestOpaqueAdminS3DownloadPlanPinsProviderPlacement(t *testing.T) {
	meta, err := mediacrypto.NewMetadata(1024)
	if err != nil {
		t.Fatal(err)
	}
	const name = "music/category/song.mp3"
	resource, object := strings.Repeat("a", 64), strings.Repeat("b", 64)
	pl := sealedtree.S3Placement{ObjectID: resource, Encryption: &meta, Proof: store.S3ObjectProof{
		ObjectID: object, Bytes: meta.CiphertextSize, Key: "provider-opaque-key", ETag: "previous"}}
	first, err := opaqueAdminS3DownloadEntry(resource, name, "audio", pl, 1)
	if err != nil || first.Transport != "S3" || first.ObjectID != object || first.ResourceID != resource {
		t.Fatal("unexpected Admin descriptor", err)
	}
	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), pl.Proof.Key) || strings.Contains(string(encoded), pl.Proof.ETag) {
		t.Fatal("Admin plan exposed provider proof", err)
	}
	pl.Proof.ETag = "different"
	changed, err := opaqueAdminS3DownloadEntry(resource, name, "audio", pl, 1)
	if err != nil || changed.Snapshot == first.Snapshot {
		t.Fatal("changed provider object identity reused old Admin snapshot", err)
	}
}
