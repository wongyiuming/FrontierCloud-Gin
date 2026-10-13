package media

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"testing"
)

func TestNativeMediaInventoryRetainsOnlyExactBuiltinsAndIdleLocks(t *testing.T) {
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if e = root.Mkdir("lyrics", 0700); e != nil {
		t.Fatal(e)
	}
	put := func(name, content string) resourceinventory.Entry {
		file, err := root.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.WriteString(content); err != nil {
			t.Fatal(err)
		}
		file.Close()
		info, err := root.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		return resourceinventory.Entry{Path: name, Kind: "regular", LogicalBytes: info.Size(), ModifiedNS: info.ModTime().UnixNano()}
	}
	original := store.PhysicalInventoryFact{Category: "unmanaged_file", Blocking: true}
	fact, handled := InventoryState(context.Background(), root, put(defaultLyric, defaultContent), original)
	if !handled || fact.Blocking || fact.Category != "retained_native_state" {
		t.Fatal(fact, handled)
	}
	fact, handled = InventoryState(context.Background(), root, put(defaultLyric, "unknown"), original)
	if !handled || !fact.Blocking {
		t.Fatal("unknown content retained", fact, handled)
	}
	fact, handled = InventoryState(context.Background(), root, put(".media-mutation.lock", ""), original)
	if !handled || fact.Blocking {
		t.Fatal(fact, handled)
	}
	protected := store.PhysicalInventoryFact{Category: "managed_media", Blocking: true, ObjectID: "legacy"}
	fact, handled = InventoryState(context.Background(), root, put(".media-mutation.lock", ""), protected)
	if handled || fact != protected {
		t.Fatal("managed metadata exception", fact, handled)
	}
	fact, handled = InventoryState(context.Background(), root, put(".node-control.lock", "nonempty"), original)
	if !handled || !fact.Blocking {
		t.Fatal("nonempty lock retained", fact, handled)
	}
	fact, handled = InventoryState(context.Background(), root, put("lyrics/ordinary.lrc", defaultContent), original)
	if handled || fact != original {
		t.Fatal("user lyric retained", fact, handled)
	}
}
