package business_test

import (
	"context"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPeerExpectedPhysicalInventoryBackupsIncludeLegacyAndForeignGenerations(t *testing.T) {
	db, raw, _, rel, h, _, _ := peerMigrationFixture(t, false)
	ctx := context.Background()
	foreign := strings.Repeat("8", 32)
	for i := int64(1); i <= 35; i++ {
		owner := h.MasterID
		if i == 1 {
			owner = foreign
		}
		if _, e := raw.Exec("INSERT INTO cluster_business_backups(master_id,generation,checksum,size_bytes,chunk_count,state,created_at,updated_at) VALUES (?,?,?,7,1,'ready',1,1)", owner, 800000+i, strings.Repeat("7", 64)); e != nil {
			t.Fatal(e)
		}
		if _, e := raw.Exec("INSERT INTO cluster_business_backup_chunks(master_id,generation,chunk_index,payload,created_at) VALUES (?,?,0,?,1)", owner, 800000+i, []byte("fixture")); e != nil {
			t.Fatal(e)
		}
		ownerCopy, gen := owner, 800000+i
		t.Cleanup(func() {
			raw.Exec("DELETE FROM cluster_business_backup_chunks WHERE master_id=? AND generation=?", ownerCopy, gen)
			raw.Exec("DELETE FROM cluster_business_backups WHERE master_id=? AND generation=?", ownerCopy, gen)
		})
	}
	repo := db.Pool().(store.ExpectedPhysicalRepository)
	for _, resource := range []string{"backup", "backup_chunk"} {
		after := ""
		seen := map[string]bool{}
		foreignSeen := false
		pages := 0
		for {
			page, e := repo.ExpectedPhysicalInventory(ctx, rel, h.TargetID, h.MasterID, resource, after)
			if e != nil {
				t.Fatal(e)
			}
			if len(page.Items) > 16 {
				t.Fatal("unbounded backup page")
			}
			for _, item := range page.Items {
				if seen[item.Cursor] || item.Cursor <= after || item.Backing != "database" || item.Path != "" || item.ExpectedBytes == nil || *item.ExpectedBytes != 7 {
					t.Fatal("invalid legacy backing", item)
				}
				seen[item.Cursor] = true
				if item.MasterID == foreign {
					foreignSeen = true
				}
			}
			pages++
			if page.Complete {
				break
			}
			if after == page.Next {
				t.Fatal("backup cursor stalled")
			}
			after = page.Next
		}
		if pages < 3 || !foreignSeen || len(seen) < 35 {
			t.Fatal("backup generations omitted", resource, pages, len(seen), foreignSeen)
		}
		if _, e := repo.ExpectedPhysicalInventory(ctx, rel, h.TargetID, h.MasterID, resource, "../bad"); e == nil {
			t.Fatal("invalid backup cursor")
		}
	}
}
func TestExpectedColdBackupFilesReportMissingArtifactAndChunk(t *testing.T) {
	db, _, rel := backupFixture(t)
	configured, ok := db.(interface{ ConfigureFileBackups(string) error })
	if !ok {
		t.Skip("native Storage is embedded SQLite")
	}
	dir := t.TempDir()
	if e := configured.ConfigureFileBackups(filepath.Join(dir, ".cold-backups")); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	payload := []byte("actual cold recovery bytes")
	if e := db.Backups().BeginBackup(ctx, rel.ID, 543210, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := db.Backups().AppendBackup(ctx, rel.ID, 543210, 0, payload); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Backups().CommitBackup(ctx, rel.ID, 543210, backupChecksum(payload), store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	// Committing cold files retires receiving chunk rows. Inspect a separate
	// still-receiving generation to test missing private chunk material.
	if e := db.Backups().BeginBackup(ctx, rel.ID, 543211, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := db.Backups().AppendBackup(ctx, rel.ID, 543211, 0, payload); e != nil {
		t.Fatal(e)
	}
	n, e := db.Nodes().ReadIdentity(ctx)
	if e != nil {
		t.Fatal(e)
	}
	repo := db.Pool().(store.ExpectedPhysicalRepository)
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	for _, resource := range []string{"backup", "backup_chunk"} {
		page, e := repo.ExpectedPhysicalInventory(ctx, rel.ID, n.ID, rel.PeerID, resource, "")
		if e != nil {
			t.Fatal(e)
		}
		if !page.Complete || len(page.Items) == 0 {
			t.Fatal("cold manifest", resource, page)
		}
		var item store.ExpectedPhysicalItem
		wanted := int64(543210)
		if resource == "backup_chunk" {
			wanted = 543211
		}
		for _, candidate := range page.Items {
			if candidate.Generation == wanted {
				item = candidate
			}
		}
		if item.Generation != wanted {
			t.Fatal("generation omitted", page)
		}
		if item.Backing != "cold_file" || item.ExpectedBytes == nil || *item.ExpectedBytes != int64(len(payload)) {
			t.Fatal("cold length", item)
		}
		present, e := resourceinventory.PresenceAt(ctx, root, item.Path)
		if e != nil || present.State != "present" || present.LogicalBytes != int64(len(payload)) {
			t.Fatal("cold presence", present, e)
		}
		if e = root.Remove(item.Path); e != nil {
			t.Fatal(e)
		}
		missing, e := resourceinventory.PresenceAt(ctx, root, item.Path)
		if e != nil || missing.State != "missing" {
			t.Fatal("lost recovery bytes hidden", missing, e)
		}
		repeated, e := repo.ExpectedPhysicalInventory(ctx, rel.ID, n.ID, rel.PeerID, resource, "")
		if e != nil || len(repeated.Items) == 0 {
			t.Fatal("metadata disappeared with file", fmt.Sprint(repeated), e)
		}
	}
}
