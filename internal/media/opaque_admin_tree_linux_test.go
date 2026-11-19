//go:build linux

package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/search"
	_ "modernc.org/sqlite"
)

func TestOpaqueAdminTreeBrowseSearchAndHidden(t *testing.T) {
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
	rootID, musicID, albumID, hiddenID := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
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
	for _, entry := range []sealedtree.Entry{{ParentID: rootID, ObjectID: musicID, Kind: "directory", Name: "music"}, {ParentID: musicID, ObjectID: albumID, Kind: "directory", Name: "album"}, {ParentID: albumID, ObjectID: hiddenID, Kind: "directory", Name: "hidden"}} {
		facts := sealedtree.Facts{ObjectID: entry.ObjectID}
		if entry.ObjectID == hiddenID {
			facts.Visibility = &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}
		}
		if err = tree.CreateDirectoryWithFacts(ctx, entry, facts); err != nil {
			t.Fatal(err)
		}
	}
	publisher, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range []struct{ parent, name, id string }{{albumID, "visible-song.mp3", strings.Repeat("e", 64)}, {hiddenID, "hidden-song.mp3", strings.Repeat("f", 64)}} {
		content := []byte{byte(i + 1)}
		digest := sha256.Sum256(content)
		entry := sealedtree.Entry{ParentID: v.parent, ObjectID: v.id, Kind: "audio", Name: v.name}
		placement := sealedtree.Placement{ObjectID: v.id, NativeObjectID: v.id, OwnerID: strings.Repeat("1", 32), Bytes: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), State: "active"}
		pending, e := tree.PrepareFileWithFreshLocators(ctx, entry, placement, sealedtree.Facts{ObjectID: v.id})
		if e != nil {
			t.Fatal(e)
		}
		if e = tree.PublishPending(ctx, pending.OperationID, publisher, bytes.NewReader(content)); e != nil {
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
	view, err := service.OpaqueAdminTree(ctx, tree, lease, "music/album")
	if err != nil || len(view.Items) != 2 || view.Items[0].Kind != "directory" || !view.Items[0].Hideable || !view.Items[0].Hidden || !view.Items[0].HiddenDirect || view.Items[1].Name != "visible-song.mp3" || view.Items[1].Hideable || view.Items[1].Hidden || view.Items[1].MemberID != strings.Repeat("1", 32) || view.Items[1].ObjectID != strings.Repeat("e", 64) || view.Items[1].StorageAddress != nil || view.Items[1].Transport != "" {
		t.Fatal("Admin tree projection or unverified owner fields", err)
	}
	view, err = service.OpaqueAdminTree(ctx, tree, lease, "music/album/hidden")
	if err != nil || len(view.Items) != 1 || !view.Items[0].Hidden || view.Items[0].HiddenDirect {
		t.Fatal("inherited hidden state", err)
	}
	result, err := service.OpaqueAdminTreeSearch(ctx, tree, lease, "music", "song")
	if err != nil || len(result.Items) != 2 || result.Truncated {
		t.Fatal("Admin search", err)
	}
	hiddenCount := 0
	for _, item := range result.Items {
		if item.Hidden && !item.HiddenDirect {
			hiddenCount++
		}
	}
	if hiddenCount != 1 {
		t.Fatal("Admin search lost inherited hidden state")
	}
	if _, err = service.OpaqueAdminTree(ctx, tree, lease, "music/missing"); !errors.Is(err, ErrCategory) {
		t.Fatal("missing directory accepted", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = service.OpaqueAdminTreeSearch(cancelled, tree, lease, "music", "song"); err == nil {
		t.Fatal("cancelled scan accepted")
	}
}
