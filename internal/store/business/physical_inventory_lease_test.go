package business_test

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
)

func TestPeerPhysicalInventoryDeletedRecordingLeaseRequiresExactTombstone(t *testing.T) {
	db, raw, _, rel, h, _, _ := peerMigrationFixture(t, true)
	id, user := hashPath(t.Name() + "record")[:32], hashPath(t.Name() + "user")[:32]
	if _, e := raw.Exec("INSERT INTO karaoke_recordings(recording_id,user_id,storage_member_id,filename,content_type,size_bytes,state,title,lyrics,created_at,updated_at) VALUES (?,?,?,?,?,0,'deleted','','{}',1,2)", id, user, h.SourceID, "voice.webm", "audio/webm"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Exec("DELETE FROM karaoke_recordings WHERE recording_id=?", id) })
	repo := db.Pool().(store.PhysicalInventoryRepository)
	entry := store.PhysicalInventoryEntry{Path: "recordings/.recording-" + id + ".lease", Kind: "regular"}
	inspect := func() store.PhysicalInventoryFact {
		facts, e := repo.ClassifyPhysicalInventory(context.Background(), rel, h.SourceID, h.MasterID, []store.PhysicalInventoryEntry{entry})
		if e != nil || len(facts) != 1 {
			t.Fatal(facts, e)
		}
		return facts[0]
	}
	fact := inspect()
	if fact.Category != "deleted_recording_lease" || !fact.Blocking || fact.State != "deleted" || len(fact.MetadataSHA256) != 64 {
		t.Fatal("SQL alone granted idle lease", fact)
	}
	first := fact.MetadataSHA256
	if _, e := raw.Exec("UPDATE karaoke_recordings SET updated_at=3 WHERE recording_id=?", id); e != nil {
		t.Fatal(e)
	}
	if inspect().MetadataSHA256 == first {
		t.Fatal("version unchanged")
	}
	entry.LogicalBytes = 1
	if inspect().Category == "deleted_recording_lease" {
		t.Fatal("nonempty")
	}
	entry.LogicalBytes = 0
	for _, change := range []struct{ field, value string }{{"state", "pending"}, {"state", "ready"}, {"storage_member_id", strings.Repeat("f", 32)}} {
		if _, e := raw.Exec("UPDATE karaoke_recordings SET state='deleted',storage_member_id=? WHERE recording_id=?", h.SourceID, id); e != nil {
			t.Fatal(e)
		}
		if _, e := raw.Exec("UPDATE karaoke_recordings SET "+change.field+"=? WHERE recording_id=?", change.value, id); e != nil {
			t.Fatal(e)
		}
		if inspect().Category == "deleted_recording_lease" {
			t.Fatal("unproved tombstone", change)
		}
	}
	entry.Path = "recordings/.recording-" + strings.Repeat("e", 32) + ".lease"
	if inspect().Category == "deleted_recording_lease" {
		t.Fatal("unknown lease")
	}
}
