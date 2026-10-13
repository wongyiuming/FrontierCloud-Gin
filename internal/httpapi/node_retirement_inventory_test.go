package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertRetainedMigrationInventory(t *testing.T, master *node.Service, rel store.Relationship, directory string, spec migrationdata.Spec) {
	t.Helper()
	ctx := context.Background()
	sum := sha256.Sum256([]byte(spec.Resource + ":" + spec.LogicalID))
	base := ".migration-data-" + spec.TaskID + "-" + hex.EncodeToString(sum[:])
	scan := func(id string) map[string]store.PhysicalInventoryFact {
		t.Helper()
		req := map[string]any{"action": "open", "scope": "media", "member_id": rel.PeerID, "session_id": id}
		value, e := master.Call(ctx, rel, "/internal/v1/resource-inventory", req)
		if e != nil {
			t.Fatal(e)
		}
		var session resourceinventory.Session
		if e = decodeInventory(value, &session); e != nil {
			t.Fatal(e)
		}
		req["incarnation"] = session.Incarnation
		result := map[string]store.PhysicalInventoryFact{}
		for sequence := uint64(0); ; sequence++ {
			req["action"] = "page"
			req["sequence"] = sequence
			value, e = master.Call(ctx, rel, "/internal/v1/resource-inventory", req)
			if e != nil {
				t.Fatal(e)
			}
			var page struct {
				resourceinventory.SessionPage
				Facts []store.PhysicalInventoryFact `json:"facts"`
			}
			if e = decodeInventory(value, &page); e != nil {
				t.Fatal(e)
			}
			for i, entry := range page.Page.Entries {
				result[entry.Path] = page.Facts[i]
			}
			if page.Page.Complete {
				break
			}
		}
		req["action"] = "close"
		req["sequence"] = uint64(0)
		if _, e = master.Call(ctx, rel, "/internal/v1/resource-inventory", req); e != nil {
			t.Fatal(e)
		}
		return result
	}
	facts := scan(strings.Repeat("6", 32))
	for _, suffix := range []string{".json", ".lock"} {
		fact, ok := facts[base+suffix]
		if !ok || fact.Blocking || fact.Category != "retained_native_state" || fact.State != "aborted" || fact.ObjectID != spec.LogicalID {
			t.Fatal("terminal history did not reconcile", suffix, fact)
		}
	}
	orphan := filepath.Join(directory, "media", base+".part")
	if e := os.WriteFile(orphan, []byte("unaccounted private bytes"), 0600); e != nil {
		t.Fatal(e)
	}
	facts = scan(strings.Repeat("7", 32))
	for _, suffix := range []string{".json", ".lock", ".part"} {
		fact, ok := facts[base+suffix]
		if !ok || !fact.Blocking || fact.Category != "migration_material" {
			t.Fatal("private residual ignored", suffix, fact)
		}
	}
	if e := os.Remove(orphan); e != nil {
		t.Fatal(e)
	}
}
