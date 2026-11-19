//go:build linux

package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/search"
	_ "modernc.org/sqlite"
)

func TestOpaquePriorityCatalogAuthenticatedHierarchy(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, musicID, videoID, albumID, subID := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, db, codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = sealedtree.InitializeFence(ctx, tree, root, dir); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []sealedtree.Entry{{ParentID: rootID, ObjectID: musicID, Kind: "directory", Name: "music"}, {ParentID: rootID, ObjectID: videoID, Kind: "directory", Name: "vido"}, {ParentID: musicID, ObjectID: albumID, Kind: "directory", Name: "album"}, {ParentID: albumID, ObjectID: subID, Kind: "directory", Name: "hidden"}} {
		facts := sealedtree.Facts{ObjectID: entry.ObjectID}
		if entry.ObjectID == subID {
			facts.Visibility = &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}
		}
		if err = tree.CreateDirectoryWithFacts(ctx, entry, facts); err != nil {
			t.Fatal(err)
		}
	}
	pub, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(nil)
	for i, v := range []struct {
		parent, name, kind string
		preference         int64
	}{{albumID, "z.mp3", "audio", 7}, {albumID, "a.mp3", "audio", 0}, {subID, "中文.mp3", "audio", 3}, {videoID, "bad.mp4", "video", 0}} {
		// Files directly below video root are intentionally ignored by the old view.
		id := fmt.Sprintf("%064x", i+16)
		entry := sealedtree.Entry{ParentID: v.parent, ObjectID: id, Kind: v.kind, Name: v.name}
		facts := sealedtree.Facts{ObjectID: id, Playback: &sealedtree.PlaybackFact{Preference: v.preference, CreatedAt: "2026-01-01", UpdatedAt: "2026-01-01"}}
		placement := sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: strings.Repeat("f", 32), Bytes: 0, ETag: `"fixture"`, SHA256: hex.EncodeToString(hash[:]), State: "active"}
		prepared, e := tree.PrepareFileWithFreshLocators(ctx, entry, placement, facts)
		if e != nil {
			t.Fatal(e)
		}
		if e = tree.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(nil)); e != nil {
			t.Fatal(e)
		}
	}
	engine, err := search.New()
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{search: engine}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	got, err := service.OpaquePriorities(ctx, tree, lease, "music/album", "", "audio", 1, 100)
	if err != nil || got.CatalogTotal != 3 || len(got.Items) != 2 || got.Items[0].Title != "z" || len(got.Directories) != 1 || got.Directories[0].Count != 1 {
		t.Fatalf("direct: %+v %v", got, err)
	}
	got, err = service.OpaquePriorities(ctx, tree, lease, "music", "zhongwen", "audio", 4, 1)
	if err != nil || got.Pagination.Total != 1 || got.Pagination.Page != 1 || len(got.Items) != 1 || !got.Items[0].Hidden || got.Items[0].Title != "中文" {
		t.Fatalf("search/hidden: %+v %v", got, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = service.OpaquePriorities(cancelled, tree, lease, "music", "", "audio", 1, 100); err == nil {
		t.Fatal("cancelled scan accepted")
	}
	if _, err = service.OpaquePriorities(ctx, tree, lease, "lyrics", "", "", 1, 100); err == nil {
		t.Fatal("lyric scope accepted")
	}
}
