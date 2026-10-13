package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
)

// InventoryState only recognizes exact native coordination files and the
// immutable built-in lyric. Ordinary user files never receive this exception.
func InventoryState(ctx context.Context, root *os.Root, entry resourceinventory.Entry, fact store.PhysicalInventoryFact) (store.PhysicalInventoryFact, bool) {
	if entry.Kind != "regular" {
		return fact, false
	}
	if (entry.Path == ".media-mutation.lock" || entry.Path == ".node-control.lock") && fact.Category == "unmanaged_file" {
		if e := resourceinventory.IdleLeaseAt(ctx, root, entry); e != nil {
			return store.PhysicalInventoryFact{Category: "native_lease_unverified", Blocking: true, Reason: "retry_after_native_readers_and_writers_finish"}, true
		}
		return store.PhysicalInventoryFact{Category: "retained_native_state", State: "idle", Reason: "retain_native_coordination_inode"}, true
	}
	if entry.Path == defaultLyric && fact.Category == "unmanaged_file" {
		sum := sha256.Sum256([]byte(defaultContent))
		observed, e := resourceinventory.ContentAt(ctx, root, defaultLyric, int64(len(defaultContent)))
		if e != nil || entry.LogicalBytes != int64(len(defaultContent)) || observed.ModifiedNS != entry.ModifiedNS || observed.SHA256 != hex.EncodeToString(sum[:]) {
			return store.PhysicalInventoryFact{Category: "native_state_unverified", Blocking: true, Reason: "restore_builtin_default_lyric_or_resolve_unknown_bytes"}, true
		}
		return store.PhysicalInventoryFact{Category: "retained_native_state", State: "builtin", Reason: "retain_builtin_default_lyric"}, true
	}
	return fact, false
}
