package migrationdata

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"os"
	"regexp"
	"strings"
)

var terminalInventoryName = regexp.MustCompile(`^\.migration-data-[a-f0-9]{32}-[a-f0-9]{64}\.(json|lock)$`)

func sameInventoryFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
func (r *Receiver) inventoryOpen(name string) (*os.File, os.FileInfo, error) {
	before, e := r.root.Lstat(name)
	if e != nil {
		return nil, nil, e
	}
	if !before.Mode().IsRegular() {
		return nil, nil, ErrState
	}
	f, e := openInventoryFile(r.root, name)
	if e != nil {
		return nil, nil, e
	}
	actual, e := f.Stat()
	named, ne := r.root.Lstat(name)
	if e != nil || ne != nil || !sameInventoryFile(actual, before) || !sameInventoryFile(named, before) {
		f.Close()
		return nil, nil, ErrState
	}
	return f, before, nil
}

// InventoryTerminal verifies a retained checkpoint under its existing native
// lease. It never creates a lease, deletes bytes, or adopts an incomplete job.
// Admission must independently check the archived SQL binding and terminal
// task/unit/journal receipts; it runs before and after the native observations.
func (r *Receiver) InventoryTerminal(ctx context.Context, entry resourceinventory.Entry, admission func(Spec, string) error) (store.PhysicalInventoryFact, bool) {
	if !terminalInventoryName.MatchString(entry.Path) || entry.Kind != "regular" {
		return store.PhysicalInventoryFact{}, false
	}
	blocked := store.PhysicalInventoryFact{Category: "migration_material", Blocking: true, Reason: "reconcile_terminal_checkpoint_and_binding"}
	if admission == nil || ctx.Err() != nil {
		return blocked, true
	}
	base := strings.TrimSuffix(strings.TrimSuffix(entry.Path, ".json"), ".lock")
	lease, leaseInfo, e := r.inventoryOpen(base + ".lock")
	if e != nil {
		return blocked, true
	}
	if leaseInfo.Size() != 0 {
		lease.Close()
		return blocked, true
	}
	release, e := filelease.Try(lease, true)
	if e != nil {
		return blocked, true
	}
	defer release()
	journal, info, e := r.inventoryOpen(base + ".json")
	if e != nil {
		return blocked, true
	}
	defer journal.Close()
	expected := info
	if strings.HasSuffix(entry.Path, ".lock") {
		expected = leaseInfo
	}
	if expected.Size() != entry.LogicalBytes || expected.ModTime().UnixNano() != entry.ModifiedNS || info.Size() > journalLimit {
		return blocked, true
	}
	raw, e := io.ReadAll(io.LimitReader(journal, journalLimit+1))
	if e != nil || len(raw) > journalLimit {
		return blocked, true
	}
	var saved journalRecord
	if json.Unmarshal(raw, &saved) != nil || !r.valid(saved.Spec) {
		return blocked, true
	}
	stage, name, lock := names(saved.Spec)
	if name != base+".json" || lock != base+".lock" {
		return blocked, true
	}
	c, e := decodeCheckpoint(saved.Spec, raw)
	if e != nil {
		return blocked, true
	}
	if _, e = resumeHash(c); e != nil {
		return blocked, true
	}
	if c.AnchorError != "" || c.RecheckError != "" || c.AnchorRetiring {
		return blocked, true
	}
	if c.State == "published" {
		if !c.AnchorRetired || c.Offset != c.Spec.Bytes || c.PrefixSHA != c.Spec.SHA256 {
			return blocked, true
		}
	} else if c.State != "aborted" || c.AnchorRetired {
		return blocked, true
	}
	if admission(c.Spec, c.State) != nil {
		return blocked, true
	}
	for _, absent := range []string{stage, name + ".tmp"} {
		if _, e = r.root.Lstat(absent); !errors.Is(e, os.ErrNotExist) {
			return blocked, true
		}
	}
	if ctx.Err() != nil || admission(c.Spec, c.State) != nil {
		return blocked, true
	}
	for name, before := range map[string]os.FileInfo{base + ".json": info, base + ".lock": leaseInfo} {
		now, e := r.root.Lstat(name)
		if e != nil || !sameInventoryFile(now, before) {
			return blocked, true
		}
	}
	digest, e := store.MigrationDigest(c.Spec)
	if e != nil {
		return blocked, true
	}
	return store.PhysicalInventoryFact{Category: "retained_native_state", ObjectID: c.Spec.LogicalID, State: c.State, MetadataSHA256: digest, Reason: "retain_terminal_migration_checkpoint"}, true
}
