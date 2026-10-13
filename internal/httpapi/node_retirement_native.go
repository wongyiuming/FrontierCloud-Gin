package httpapi

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"strings"
)

type retirementNativeFile struct {
	info os.FileInfo
	kind string
}
type retirementNativeInventory struct {
	root       *os.Root
	files      map[string]retirementNativeFile
	database   string
	secrets    string
	control    *node.Service
	encryption store.EncryptionRepository
	mediaKeys  string
	settings   config.Config
}

// Pins are taken from actual runtime paths at registration, never from a peer
// request or a filename whitelist over arbitrary files. Unknown siblings stay
// blocking. These files are retained in place, not recovery or wipe grants.
func newRetirementNativeInventory(ctx context.Context, root *os.Root, settings config.Config, repo store.PhysicalInventoryRepository, control *node.Service) (*retirementNativeInventory, error) {
	v := &retirementNativeInventory{root: root, files: map[string]retirementNativeFile{}, secrets: settings.SecretsDirectory, control: control, settings: settings}
	v.encryption, _ = repo.(store.EncryptionRepository)
	v.mediaKeys = filepath.Join(settings.DataRoot, "media-keys")
	base, e := filepath.Abs(settings.DataRoot)
	if e != nil {
		return nil, e
	}
	pin := func(absolute, kind string) error {
		absolute, e = filepath.Abs(absolute)
		if e != nil {
			return e
		}
		relative, e := filepath.Rel(base, absolute)
		if e != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return nil
		}
		name := filepath.ToSlash(relative)
		// Reject every symlink ancestor inside the scanned native namespace.
		parts := strings.Split(name, "/")
		for i := range parts {
			info, e := root.Lstat(strings.Join(parts[:i+1], "/"))
			if os.IsNotExist(e) {
				return nil
			}
			if e != nil {
				return e
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			if i < len(parts)-1 && !info.IsDir() {
				return nil
			}
		}
		info, e := root.Lstat(name)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		actual, e := os.Lstat(absolute)
		if e != nil || !os.SameFile(info, actual) {
			return resourceinventory.ErrChanged
		}
		if (kind == "coordination" || kind == "idle_coordination") && info.Size() != 0 {
			return nil
		}
		v.files[name] = retirementNativeFile{info: info, kind: kind}
		return nil
	}
	if native, ok := repo.(store.RetirementNativeRepository); ok {
		v.database, e = native.RetirementDatabasePath(ctx)
		if e != nil {
			return nil, e
		}
		if v.database != "" {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if e = pin(v.database+suffix, "database"); e != nil {
					return nil, e
				}
			}
		}
	}
	if settings.SecretsDirectory != "" {
		if e = pin(filepath.Join(settings.SecretsDirectory, "node-vault.key"), "identity"); e != nil {
			return nil, e
		}
	}
	if v.encryption != nil {
		if e = pin(filepath.Join(v.mediaKeys, "media-premaster.key"), "media_key"); e != nil {
			return nil, e
		}
	}
	for _, name := range []string{".native-runtime.lock", ".native-maintenance-control.lock", node.RetirementAdmissionFile} {
		if e = pin(filepath.Join(base, name), "coordination"); e != nil {
			return nil, e
		}
	}
	for _, name := range []string{".native-store", ".native-runtime"} {
		if e = pin(filepath.Join(base, name), "provenance"); e != nil {
			return nil, e
		}
	}
	for _, name := range []string{".native-store.lock", ".native-admission.lock"} {
		if e = pin(filepath.Join(base, name), "idle_coordination"); e != nil {
			return nil, e
		}
	}
	return v, nil
}

func (v *retirementNativeInventory) classify(ctx context.Context, entry resourceinventory.Entry, fact store.PhysicalInventoryFact) store.PhysicalInventoryFact {
	pin, ok := v.files[entry.Path]
	if !ok || entry.Kind != "regular" || fact.Category != "unmanaged_file" {
		return fact
	}
	blocked := store.PhysicalInventoryFact{Category: "native_state_unverified", Blocking: true, Reason: "reconcile_selected_runtime_state"}
	check := func() bool {
		info, e := v.root.Lstat(entry.Path)
		return e == nil && info.Mode().IsRegular() && os.SameFile(info, pin.info) && (pin.kind != "coordination" && pin.kind != "idle_coordination" || info.Size() == 0) && (pin.kind != "identity" && pin.kind != "provenance" || info.Size() == entry.LogicalBytes && info.ModTime().UnixNano() == entry.ModifiedNS)
	}
	if ctx.Err() != nil || !check() {
		return blocked
	}
	if pin.kind == "identity" && v.control.ValidateRetainedIdentity(ctx, v.secrets) != nil {
		return blocked
	}
	if pin.kind == "provenance" && v.control.ValidateRetainedRuntime(ctx, v.settings) != nil {
		return blocked
	}
	if pin.kind == "idle_coordination" && resourceinventory.IdleLeaseAt(ctx, v.root, entry) != nil {
		return blocked
	}
	if pin.kind == "media_key" {
		// true prohibits initialization or regeneration, including when the key
		// disappeared after this runtime pinned it. Compare with durable metadata;
		// a valid-size replacement key is not the retained business secret.
		key, e := mediacrypto.OpenForData(v.mediaKeys, true)
		if e != nil {
			return blocked
		}
		keyID, e := v.encryption.EncryptionKeyID(ctx)
		if e != nil || keyID == "" || key.KeyID() != keyID {
			return blocked
		}
	}
	if pin.kind == "database" {
		main, e := os.Lstat(v.database)
		if e != nil || !main.Mode().IsRegular() {
			return blocked
		}
		// A sidecar can only be retained while its selected database is still the
		// pinned native inode. Retired nodes keep their entire authoritative store.
		for _, candidate := range v.files {
			if candidate.kind == "database" && os.SameFile(candidate.info, main) {
				if check() {
					return store.PhysicalInventoryFact{Category: "retained_native_state", State: "database", Reason: "retain_identity_history_and_database_state"}
				}
				return blocked
			}
		}
		return blocked
	}
	if !check() {
		return blocked
	}
	return store.PhysicalInventoryFact{Category: "retained_native_state", State: pin.kind, Reason: "retain_native_identity_and_coordination_state"}
}

// A disappeared native file must fail closed even though it no longer appears
// in a directory walk. In particular, an open SQLite handle is not proof that
// its named database and retained key still survive on disk.
func (v *retirementNativeInventory) validate(ctx context.Context) error {
	if e := v.control.ValidateRetainedControlState(); e != nil {
		return e
	}
	for name := range v.files {
		info, e := v.root.Lstat(name)
		if e != nil {
			return resourceinventory.ErrChanged
		}
		entry := resourceinventory.Entry{Path: name, Kind: "regular", LogicalBytes: info.Size(), ModifiedNS: info.ModTime().UnixNano()}
		fact := v.classify(ctx, entry, store.PhysicalInventoryFact{Category: "unmanaged_file", Blocking: true})
		if fact.Blocking {
			return resourceinventory.ErrChanged
		}
	}
	return ctx.Err()
}

func (v *retirementNativeInventory) controlLease(root *os.Root, entry resourceinventory.Entry, fact store.PhysicalInventoryFact) (store.PhysicalInventoryFact, bool) {
	if entry.Path != ".node-control.lock" || entry.Kind != "regular" || fact.Category != "unmanaged_file" {
		return fact, false
	}
	info, e := root.Lstat(entry.Path)
	if e == nil && entry.LogicalBytes == 0 && info.ModTime().UnixNano() == entry.ModifiedNS && v.control.RetainsControlLease(info) {
		return store.PhysicalInventoryFact{Category: "retained_native_state", State: "owned_control_lease", Reason: "retain_native_control_runtime_inode"}, true
	}
	return fact, false
}
