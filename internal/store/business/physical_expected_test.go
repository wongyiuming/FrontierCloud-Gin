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

func TestPeerExpectedPhysicalInventoryExactManagedLookup(t *testing.T) {
	db, raw, _, rel, h, _, v := peerMigrationFixture(t, true)
	ctx := context.Background()
	repo := db.Pool().(store.ManagedPhysicalRepository)
	media, e := repo.ExpectedPhysicalObject(ctx, rel, h.SourceID, h.MasterID, "media", v.Object.ObjectID)
	if e != nil || media.Path != "media/"+v.Object.Path || media.ObjectID != v.Object.ObjectID || len(media.MetadataSHA256) != 64 {
		t.Fatal("managed media lookup", media, e)
	}
	id, user := hashPath(t.Name() + "record")[:32], hashPath(t.Name() + "user")[:32]
	if _, e = raw.Exec("INSERT INTO karaoke_recordings(recording_id,user_id,storage_member_id,filename,content_type,size_bytes,sha256,state,title,lyrics,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'ready','','{}',1,1)", id, user, h.SourceID, "voice.webm", "audio/webm", 7, strings.Repeat("f", 64)); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Exec("DELETE FROM karaoke_recordings WHERE recording_id=?", id) })
	recording, e := repo.ExpectedPhysicalObject(ctx, rel, h.SourceID, h.MasterID, "recording", id)
	if e != nil || recording.Path != "recordings/"+rel+"/"+user+"/"+id+".bin" || recording.ExpectedBytes == nil || *recording.ExpectedBytes != 7 {
		t.Fatal("recording mapping", recording, e)
	}
	for _, request := range [][5]string{
		{rel, h.TargetID, h.MasterID, "media", v.Object.ObjectID},
		{rel, h.SourceID, h.SourceID, "media", v.Object.ObjectID},
		{strings.Repeat("d", 32), h.SourceID, h.MasterID, "media", v.Object.ObjectID},
		{rel, h.SourceID, h.MasterID, "backup", v.Object.ObjectID},
		{rel, h.SourceID, h.MasterID, "media", "../../secrets"},
		{rel, h.SourceID, h.MasterID, "media", strings.Repeat("f", 64)},
	} {
		if _, e = repo.ExpectedPhysicalObject(ctx, request[0], request[1], request[2], request[3], request[4]); e == nil {
			t.Fatal("unbound or unmanaged lookup", request)
		}
	}
	if _, e = raw.Exec("UPDATE karaoke_recordings SET state='pending' WHERE recording_id=?", id); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ExpectedPhysicalObject(ctx, rel, h.SourceID, h.MasterID, "recording", id); e == nil {
		t.Fatal("pending recording observed as ready")
	}
	var tasks int
	if e = raw.QueryRow("SELECT COUNT(*) FROM migration_tasks WHERE source_id=?", h.SourceID).Scan(&tasks); e != nil || tasks != 0 {
		t.Fatal("lookup wrote migration facts", tasks, e)
	}
}
