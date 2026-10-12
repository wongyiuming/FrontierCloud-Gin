package business_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
)

func TestPeerPhysicalInventoryClassifiesMetadataWithoutMutatingAuthority(t *testing.T) {
	db, raw, _, rel, h, _, v := peerMigrationFixture(t, true)
	repo := db.Pool().(store.PhysicalInventoryRepository)
	ctx := context.Background()
	id, user := hashPath(t.Name() + "record")[:32], hashPath(t.Name() + "user")[:32]
	sha := strings.Repeat("6", 64)
	if _, e := raw.Exec("INSERT INTO karaoke_recordings(recording_id,user_id,storage_member_id,filename,content_type,size_bytes,sha256,state,title,lyrics,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'ready','','{}',1,1)", id, user, h.SourceID, "voice.webm", "audio/webm", 7, sha); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Exec("DELETE FROM karaoke_recordings WHERE recording_id=?", id) })
	gen := int64(987654)
	checksum := strings.Repeat("7", 64)
	if _, e := raw.Exec("INSERT INTO cluster_business_backups(master_id,generation,checksum,size_bytes,chunk_count,state,created_at,updated_at) VALUES (?,?,?,?,1,'ready',1,1)", h.MasterID, gen, checksum, 7); e != nil {
		t.Fatal(e)
	}
	marker := append([]byte("FC-COLD-FILE-V1\x00"), make([]byte, 32)...)
	marker = binary.BigEndian.AppendUint32(marker, 7)
	if _, e := raw.Exec("INSERT INTO cluster_business_backup_chunks(master_id,generation,chunk_index,payload,created_at) VALUES (?,?,0,?,1)", h.MasterID, gen, marker); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		raw.Exec("DELETE FROM cluster_business_backup_chunks WHERE master_id=? AND generation=?", h.MasterID, gen)
		raw.Exec("DELETE FROM cluster_business_backups WHERE master_id=? AND generation=?", h.MasterID, gen)
	})
	entries := []store.PhysicalInventoryEntry{
		{Path: "media/" + v.Object.Path, Kind: "regular", LogicalBytes: 7},
		{Path: "recordings/" + rel + "/" + user + "/" + id + ".bin", Kind: "regular", LogicalBytes: 7},
		{Path: ".cold-backups/artifact." + h.MasterID + ".987654." + checksum, Kind: "regular", LogicalBytes: 7},
		{Path: ".cold-backups/chunk." + h.MasterID + ".987654.0." + hex.EncodeToString(make([]byte, 32)), Kind: "regular", LogicalBytes: 7},
		{Path: "media/.delete-" + strings.Repeat("8", 32) + "/0", Kind: "regular", LogicalBytes: 7},
		{Path: "media/.migration-data-" + strings.Repeat("8", 32) + "-" + strings.Repeat("9", 64) + ".part", Kind: "regular", LogicalBytes: 7},
		{Path: "unmanaged.txt", Kind: "regular", LogicalBytes: 7},
		{Path: "outside", Kind: "symlink"},
	}
	facts, e := repo.ClassifyPhysicalInventory(ctx, rel, h.SourceID, h.MasterID, entries)
	if e != nil {
		t.Fatal(e)
	}
	categories := []string{"managed_media", "managed_recording", "managed_backup", "managed_backup", "transaction_material", "migration_material", "unmanaged_file", "unsupported_entry"}
	for i, fact := range facts {
		if fact.Category != categories[i] || !fact.Blocking {
			t.Fatal(i, fact)
		}
	}
	if len(facts[0].MetadataSHA256) != 64 || facts[1].ObjectID != id || facts[2].Generation != gen {
		t.Fatal("missing metadata facts", facts)
	}
	entries[1].LogicalBytes++
	entries[2].LogicalBytes++
	facts, e = repo.ClassifyPhysicalInventory(ctx, rel, h.SourceID, h.MasterID, entries)
	if e != nil || facts[1].Category != "metadata_mismatch" || facts[2].Category != "metadata_mismatch" {
		t.Fatal("wrong lengths accepted", facts, e)
	}
	if _, e = repo.ClassifyPhysicalInventory(ctx, rel, h.TargetID, h.MasterID, entries); !errors.Is(e, store.ErrNodeState) {
		t.Fatal("foreign member", e)
	}
	if _, e = repo.ClassifyPhysicalInventory(ctx, rel, h.SourceID, h.MasterID, []store.PhysicalInventoryEntry{{Path: "../escape", Kind: "regular"}}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("path traversal", e)
	}
	var used, reserved, tasks int64
	if e = raw.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.SourceID).Scan(&used, &reserved); e != nil || used != 7 || reserved != 0 {
		t.Fatal("classification changed quota", used, reserved, e)
	}
	if e = raw.QueryRow("SELECT COUNT(*) FROM migration_tasks WHERE source_id=?", h.SourceID).Scan(&tasks); e != nil || tasks != 0 {
		t.Fatal("classification created task", tasks, e)
	}
}
