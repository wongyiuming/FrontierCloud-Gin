package recording

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"regexp"
)

var inventoryLease = regexp.MustCompile(`^\.recording-[a-f0-9]{32}\.lease$`)

// Deleted recording lease retention requires an independently resolved SQL
// tombstone and an idle exact inode. Unknown/active leases remain blockers.
func InventoryState(ctx context.Context, root *os.Root, entry resourceinventory.Entry, fact store.PhysicalInventoryFact) (store.PhysicalInventoryFact, bool) {
	if entry.Kind != "regular" {
		return fact, false
	}
	if entry.Path != ".recordings-mutation.lock" && !(inventoryLease.MatchString(entry.Path) && fact.Category == "deleted_recording_lease" && fact.State == "deleted") {
		return fact, false
	}
	if e := resourceinventory.IdleLeaseAt(ctx, root, entry); e != nil {
		return store.PhysicalInventoryFact{Category: "native_lease_unverified", ObjectID: fact.ObjectID, Blocking: true, Reason: "retry_after_native_readers_and_writers_finish"}, true
	}
	fact.Category = "retained_native_state"
	fact.Blocking = false
	fact.Reason = "retain_native_coordination_inode"
	if fact.State == "" {
		fact.State = "idle"
	}
	return fact, true
}
