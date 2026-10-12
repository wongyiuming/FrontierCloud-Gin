package business_test

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
)

func TestPeerExpectedPhysicalInventoryPagesIncludeHiddenAndAbsentObjects(t *testing.T) {
	db, raw, _, rel, h, _, v := peerMigrationFixture(t, true)
	ctx := context.Background()
	names := []string{}
	for i := 0; i < 35; i++ {
		name := "music/" + t.Name() + "/" + strings.Repeat(string(rune('a'+i%26)), i+1) + ".mp3"
		names = append(names, name)
	}
	objects := []store.MediaObject{}
	for _, name := range names {
		objects = append(objects, store.MediaObject{Path: name, Kind: "audio"})
	}
	ids, e := db.Media().EnsureObjects(ctx, objects)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			raw.Exec("DELETE FROM media_objects WHERE media_id=?", id)
		}
	})
	if e = db.Media().SetHidden(ctx, []string{names[0]}, true, store.AdminAudit{}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Exec("DELETE FROM media_visibility WHERE relative_path=?", names[0]) })
	repo := db.Pool().(store.ExpectedPhysicalRepository)
	after := ""
	seen := map[string]bool{}
	pages := 0
	for {
		page, e := repo.ExpectedPhysicalInventory(ctx, rel, h.SourceID, h.MasterID, "media", after)
		if e != nil {
			t.Fatal(e)
		}
		if len(page.Items) > 16 || page.After != after {
			t.Fatal("unbounded or wrong cursor", page)
		}
		for _, item := range page.Items {
			if seen[item.ObjectID] || item.ObjectID <= after || len(item.MetadataSHA256) != 64 {
				t.Fatal("invalid expected item", item)
			}
			seen[item.ObjectID] = true
		}
		pages++
		if page.Complete {
			break
		}
		if page.Next == after {
			t.Fatal("cursor did not advance")
		}
		after = page.Next
	}
	if pages < 3 || !seen[v.Object.ID] {
		t.Fatal("incomplete manifest", pages, seen)
	}
	for _, id := range ids {
		if !seen[id] {
			t.Fatal("hidden/absent object omitted", id)
		}
	}
}
