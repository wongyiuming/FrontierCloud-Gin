package preprodimport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// This demonstrates only synthetic namespace compatibility. It neither
// persists a real tree nor authorizes/imports/activates a production snapshot.
func TestSyntheticTreeRecordsKeepNamesOutOfSerializedRows(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, 32)
	salt, err := sealedtree.NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.New(key, salt)
	if err != nil {
		t.Fatal(err)
	}
	root := strings.Repeat("1", 64)
	dir := strings.Repeat("2", 64)
	media := strings.Repeat("3", 64)
	directory, err := tree.Seal(root, dir, "directory", "synthetic-folder", 1)
	if err != nil {
		t.Fatal(err)
	}
	song, err := tree.Seal(dir, media, "audio", "synthetic-song.mp3", 1)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := sealedtree.NewBlobID()
	if err != nil || blob == media {
		t.Fatalf("invalid independent blob ID: %v", err)
	}
	path, err := sealedtree.BlobPath(blob)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := json.Marshal(struct {
		Directory sealedtree.Record
		Song      sealedtree.Record
		BlobPath  string
	}{directory, song, path})
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"synthetic-folder", "synthetic-song.mp3", "audio", root, dir, media} {
		if bytes.Contains(rows, []byte(private)) {
			t.Fatalf("unexpected plaintext in serialized synthetic tree")
		}
	}
	entry, err := tree.Open(dir, song)
	if err != nil || entry.Kind != "audio" || entry.Name != "synthetic-song.mp3" || entry.ObjectID != media {
		t.Fatalf("synthetic tree round trip failed: %v", err)
	}
	if _, err = tree.Open(root, song); err == nil {
		t.Fatal("record opened under an unrelated parent")
	}
}
