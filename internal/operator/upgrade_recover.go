package operator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

// RecoverUpgradeState is an explicit pre-opening recovery, never an automatic
// DDL rollback or permission to overwrite writes made after public activation.
// Original business mounts are unchanged. Failed state is retained separately.
func (d *Deployment) RecoverUpgradeState(ctx context.Context, r Receipt, approval, node, backupSHA, directory string, external bool) (result UpgradeState, operationErr error) {
	return d.recoverState(ctx, r, approval, node, backupSHA, directory, external, false)
}
func (d *Deployment) recoverState(ctx context.Context, r Receipt, approval, node, backupSHA, directory string, external, ordinary bool) (result UpgradeState, operationErr error) {
	done, e := d.AcquireOperation()
	if e != nil {
		return result, e
	}
	defer func() { operationErr = errors.Join(operationErr, done()) }()
	state, e := d.upgradeState()
	if e != nil {
		return state, e
	}
	p := state.Plan
	continuing := state.Phase == "restoring_state"
	if (state.Phase != "failed_fenced" && !continuing) || p.StateRestore != ordinary || state.ManualOwned || state.ManualStaged || state.BusinessVerified || p.RecoveryScope != recovery.UpgradeStateScope || p.RecoveryOf != "" || approval != p.SHA256 || node != p.NodeID || backupSHA == "" || backupSHA != state.BackupSHA {
		return state, errors.New("state recovery requires a verified failed preparation before opening, approved plan, NodeID and original backup SHA")
	}
	if r.Database == "mysql" && !external {
		return state, errors.New("MySQL state recovery requires external-writers-stopped confirmation")
	}
	recoveredReceipt := state.Previous
	recoveredReceipt.State = "upgrade_fenced"
	if !ordinary && !reflect.DeepEqual(r, upgradeTargetReceipt(state)) && !reflect.DeepEqual(r, state.Previous) && !(continuing && reflect.DeepEqual(r, recoveredReceipt)) {
		return state, errors.New("receipt is outside the failed source/target upgrade")
	}
	cfg, e := d.Config(ctx, ordinary)
	if e != nil || cfg.Name != p.Project || selectionHash(cfg) != state.Previous.SelectionHash {
		return state, errors.New("retained deployment mounts or configuration changed")
	}
	if !ordinary {
		lockRaw, e := readRegular(filepath.Join(d.Directory, ImagesFile), 1<<20)
		if e != nil {
			return state, e
		}
		var lock struct {
			Services map[string]map[string]string `json:"services"`
		}
		lockValue, lockErr := protocol.ParseStrictJSON(lockRaw, 1<<20)
		lockObject, lockObjectOK := lockValue.(map[string]any)
		if lockErr != nil || !lockObjectOK || len(lockObject) != 1 || json.Unmarshal(lockRaw, &lock) != nil || len(lock.Services) != len(p.ServiceImages) {
			return state, errors.New("failed upgrade image lock changed")
		}
		for name, fields := range lock.Services {
			if len(fields) != 1 || fields["image"] == "" || fields["image"] != p.ServiceImages[name] && fields["image"] != state.Previous.ServiceImages[name] {
				return state, errors.New("unapproved image lock prevents retained-state recovery")
			}
		}
	} else if !continuing {
		if _, e = d.ValidateReceipt(ctx, r); e != nil {
			return state, e
		}
	}
	if r.Database == "mysql" {
		if _, ok := d.Runner.(InputRunner); !ok {
			return state, errors.New("bounded MySQL recovery input unavailable")
		}
		if !validSQLName(cfg.Services["mysql"].Environment["MYSQL_DATABASE"]) {
			return state, recovery.ErrUnsafe
		}
	}
	if e = d.localUpgradeEngine(ctx, p.Architecture); e != nil {
		return state, e
	}
	verified, e := recovery.Check(ctx, state.BackupFile, backupSHA)
	if e != nil || verified.Manifest.Scope != recovery.UpgradeStateScope || verified.Manifest.NodeID != node || verified.Manifest.Revision != state.Previous.Revision || verified.Manifest.SchemaGeneration != p.FromGeneration {
		return state, errors.New("original state recovery identity, generation or integrity mismatch")
	}
	roots, e := d.upgradeRecoveryRoots(ctx, cfg)
	if e != nil {
		return state, e
	}
	data := roots["data"]
	directory, e = safeRecoveryDirectory(directory, continuing)
	if e != nil || directory == "" {
		return state, errors.New("new private recovery directory required")
	}
	for _, root := range roots {
		realRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			return state, err
		}
		if directory == realRoot || strings.HasPrefix(directory, realRoot+string(os.PathSeparator)) {
			return state, errors.New("recovery material cannot be inside a retained deployment root")
		}
	}
	if continuing && state.RecoveryDirectory != directory {
		return state, errors.New("resume requires the recorded recovery directory")
	}
	gate, e := maintenance.Open(data)
	if e != nil {
		return state, e
	}
	defer gate.Close()
	e = gate.Inspect(ctx, func(ctx context.Context) error {
		root, err := os.OpenRoot(data)
		if err != nil {
			return err
		}
		defer root.Close()
		lease, err := sitecontrol.Lease(ctx, root, true)
		if err != nil {
			return err
		}
		defer lease()
		if err = d.stoppedWriters(ctx); err != nil {
			return err
		}
		mysqlPresent := true
		if r.Database == "mysql" {
			if err = checkMySQLRecoveryCredential(roots, verified.Manifest.Files); err != nil {
				return err
			}
			raw, err := d.Compose(ctx, true, "exec", "-T", "mysql", "sh", "-c", `MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysql -N -u root -e "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '$MYSQL_DATABASE'"`)
			if err != nil || strings.TrimSpace(string(raw)) != "0" && strings.TrimSpace(string(raw)) != "1" {
				return errors.New("recorded MySQL database presence cannot be verified")
			}
			mysqlPresent = strings.TrimSpace(string(raw)) == "1"
		}
		selection, err := upgradeStateSelection(cfg, state.Previous, false)
		if err != nil {
			return err
		}
		var entries []recovery.Entry
		for _, entry := range verified.Manifest.Files {
			class, relative, ok := strings.Cut(entry.Path, "/")
			if !ok {
				return recovery.ErrUnsafe
			}
			if class == "mysql_dump" {
				continue
			}
			if roots[class] == "" {
				return recovery.ErrUnsafe
			}
			if class == "data" {
				if !recovery.SelectedPath(selection, relative, false) {
					return recovery.ErrUnsafe
				}
				if relative == maintenance.Marker || relative == sitecontrol.Manual || relative == sitecontrol.ForceOpen || relative == ".native-runtime.lock" || relative == ".native-maintenance-control.lock" || relative == sitecontrol.Lock {
					continue
				}
			}
			if class == "deployment" && (relative == ReceiptFile || relative == ImagesFile) {
				continue
			}
			entries = append(entries, entry)
		}
		if !continuing {
			currentEntries, inventoryErr := inventoryState(ctx, roots, selection)
			if inventoryErr != nil {
				return inventoryErr
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Path, "deployment/") {
					currentEntries = append(currentEntries, entry)
				}
			}
			archived := map[string]bool{}
			for _, entry := range verified.Manifest.Files {
				archived[entry.Path] = true
			}
			for _, entry := range currentEntries {
				if !archived[entry.Path] {
					state.CreatedStatePaths = append(state.CreatedStatePaths, entry.Path)
				}
			}
			if _, err = os.Lstat(directory); !os.IsNotExist(err) {
				return errors.New("new recovery directory must not exist")
			}
			parent := filepath.Dir(directory)
			free, err := diskFree(parent)
			if err != nil {
				return err
			}
			required := uint64(verified.Manifest.Bytes)*3 + (512 << 20)
			for _, entry := range currentEntries {
				class, relative, _ := strings.Cut(entry.Path, "/")
				info, err := os.Lstat(filepath.Join(roots[class], relative))
				if err == nil {
					if !info.Mode().IsRegular() {
						return recovery.ErrUnsafe
					}
					required += uint64(info.Size())
				} else if !os.IsNotExist(err) {
					return err
				}
			}
			if r.Database == "mysql" && mysqlPresent {
				stream, ok := d.Runner.(StreamRunner)
				if !ok {
					return errors.New("MySQL failed-state retention unavailable")
				}
				count := &byteCounter{}
				if err = stream.RunTo(ctx, count, "docker", d.stateDumpArgs()...); err != nil {
					return errors.New("failed MySQL database cannot be retained; no restoration performed")
				}
				required += count.bytes
			}
			if free < required {
				return errors.New("insufficient space for database state recovery and retained failed state; media remains excluded")
			}
			if err = os.Mkdir(directory, 0700); err != nil {
				return err
			}
			if err = exclusiveJSON(filepath.Join(directory, "failed-upgrade.json"), state); err != nil {
				return err
			}
			if _, err = recovery.ExtractState(ctx, state.BackupFile, filepath.Join(directory, "material"), backupSHA, node); err != nil {
				return err
			}
			for _, entry := range currentEntries {
				class, relative, _ := strings.Cut(entry.Path, "/")
				if err = retainStateFile(ctx, roots[class], relative, filepath.Join(directory, "failed", class), relative); err != nil {
					return err
				}
			}
			if r.Database == "mysql" {
				if mysqlPresent {
					f, err := os.OpenFile(filepath.Join(directory, "failed-database.sql"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					if err != nil {
						return err
					}
					err = d.Runner.(StreamRunner).RunTo(ctx, f, "docker", d.stateDumpArgs()...)
					if err == nil {
						err = f.Sync()
					}
					err = errors.Join(err, f.Close())
					if err != nil {
						return errors.New("failed MySQL dump retention incomplete; no restoration performed")
					}
				} else {
					if err = exclusiveJSON(filepath.Join(directory, "failed-database-absent.json"), map[string]any{"database": cfg.Services["mysql"].Environment["MYSQL_DATABASE"], "absent_before_restore": true}); err != nil {
						return err
					}
				}
			}
			state.RecoveryDirectory = directory
			state.Phase = "restoring_state"
			if err = d.saveUpgrade(state); err != nil {
				return err
			}
		}
		if err = recovery.CheckMaterial(ctx, filepath.Join(directory, "material"), verified); err != nil {
			return err
		}
		if err = checkRestoreDestinationCapacity(roots, entries, diskFree); err != nil {
			return err
		}
		if r.Database == "mysql" {
			if err = d.checkMySQLRestoreCapacity(ctx, cfg, verified.Manifest.MySQLRestoreBytes, entries...); err != nil {
				return err
			}
		}
		for _, name := range state.CreatedStatePaths {
			class, relative, ok := strings.Cut(name, "/")
			if !ok || roots[class] == "" {
				return recovery.ErrUnsafe
			}
			live, err := os.OpenRoot(roots[class])
			if err != nil {
				return err
			}
			info, err := live.Lstat(relative)
			if err == nil && !info.Mode().IsRegular() {
				live.Close()
				return recovery.ErrUnsafe
			}
			if err == nil {
				err = live.Remove(relative)
				if err == nil {
					err = fsutil.SyncDirectory(live, path.Dir(relative))
				}
			}
			live.Close()
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if err = restoreStateDirectories(roots, verified.Manifest.Directories); err != nil {
			return err
		}
		for _, entry := range entries {
			class, relative, _ := strings.Cut(entry.Path, "/")
			if err = replaceStateFile(ctx, filepath.Join(directory, "material", class), relative, roots[class], relative, entry); err != nil {
				return err
			}
		}
		if r.Database == "sqlite" {
			db := strings.TrimPrefix(cfg.Services["web"].Environment["SQLITE_PATH"], path.Clean(cfg.Services["web"].Environment["DATA_ROOT"])+"/")
			for _, suffix := range []string{"-wal", "-shm"} {
				present := false
				for _, entry := range entries {
					if entry.Path == "data/"+db+suffix {
						present = true
					}
				}
				if !present {
					if err = root.Remove(db + suffix); err != nil && !os.IsNotExist(err) {
						return err
					}
				}
			}
			if err = fsutil.SyncDirectory(root, path.Dir(db)); err != nil {
				return err
			}
		} else {
			stream, ok := d.Runner.(InputRunner)
			if !ok {
				return errors.New("bounded MySQL recovery input unavailable")
			}
			db := cfg.Services["mysql"].Environment["MYSQL_DATABASE"]
			if !validSQLName(db) {
				return recovery.ErrUnsafe
			}
			f, err := os.Open(filepath.Join(directory, "material", "mysql_dump", "database.sql"))
			if err != nil {
				return err
			}
			defer f.Close()
			input := io.MultiReader(strings.NewReader("DROP DATABASE IF EXISTS `"+db+"`;\n"), f)
			if err = stream.RunFrom(ctx, input, "docker", append(d.composeArgs(true), "exec", "-T", "mysql", "sh", "-c", `MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysql -u root`)...); err != nil {
				return errors.New("explicit MySQL state restoration failed; source remains fenced and failed dump retained")
			}
		}
		previous := state.Previous
		previous.State = "upgrade_fenced"
		for _, entry := range verified.Manifest.Files {
			if entry.Path == "deployment/"+ImagesFile {
				if err = replaceStateFile(ctx, filepath.Join(directory, "material", "deployment"), ImagesFile, d.Directory, ImagesFile, entry); err != nil {
					return err
				}
			}
		}
		if err = replaceJSON(filepath.Join(d.Directory, ReceiptFile), previous); err != nil {
			return err
		}
		return nil
	})
	if e != nil {
		return state, e
	}
	fact, e := d.runtimeFact(ctx)
	if e != nil || fact.NodeID != node || !fact.NativeMaintenance || !fact.Database.LogicalIdle || fact.Database.SchemaGeneration != p.FromGeneration {
		return state, errors.New("restored source database identity/generation verification failed; retained mounts remain fenced")
	}
	if _, e = d.Compose(ctx, true, "run", "--rm", "--no-deps", "-T", "web", "recovery-verify"); e != nil {
		return state, errors.New("restored state cannot read retained business files; source remains fenced")
	}
	p.RecoveryOf = approval
	p.From = p.Target
	p.Target = state.Previous.Revision
	p.SourceSHA = state.Previous.SourceSHA
	p.Generation = p.FromGeneration
	p.Images = state.Previous.Images
	p.ServiceImages = state.Previous.ServiceImages
	p.SHA256 = p.digest()
	state.Plan = p
	state.Phase = "prepared_fenced"
	state.Failure = ""
	return state, d.saveUpgrade(state)
}

func checkRestoreDestinationCapacity(roots map[string]string, entries []recovery.Entry, free func(string) (uint64, error)) error {
	return checkRestoreFilesystemCapacity(roots, entries, free, diskFilesystem)
}

func restoreStateDirectories(roots map[string]string, directories []recovery.Directory) error {
	for _, directory := range directories {
		class, relative, ok := strings.Cut(directory.Path, "/")
		if class == "deployment" || class == "mysql_dump" {
			continue
		}
		if !ok {
			relative = "."
		}
		if roots[class] == "" {
			return recovery.ErrUnsafe
		}
		root, e := os.OpenRoot(roots[class])
		if e != nil {
			return e
		}
		if relative != "." {
			parts := strings.Split(relative, "/")
			for i := range parts {
				name := strings.Join(parts[:i+1], "/")
				info, err := root.Lstat(name)
				if os.IsNotExist(err) {
					err = root.Mkdir(name, 0700)
				} else if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
					err = recovery.ErrUnsafe
				}
				if err != nil {
					root.Close()
					return err
				}
			}
		}
		if e = root.Chown(relative, directory.UID, directory.GID); e == nil {
			e = root.Chmod(relative, os.FileMode(directory.Mode))
		}
		if e == nil {
			e = fsutil.SyncDirectory(root, relative)
		}
		root.Close()
		if e != nil {
			return e
		}
	}
	return nil
}

func (d *Deployment) stateDumpArgs() []string {
	return append(d.composeArgs(true), "exec", "-T", "mysql", "sh", "-c", `MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysqldump --single-transaction --quick --skip-lock-tables --hex-blob --routines --events --triggers --no-tablespaces -u root --databases "$MYSQL_DATABASE"`)
}

func (d *Deployment) upgradeRecoveryRoots(ctx context.Context, cfg Config) (map[string]string, error) {
	data, e := upgradeDataRoot(cfg)
	if e != nil {
		return nil, e
	}
	roots := map[string]string{"data": data, "deployment": d.Directory}
	classes := map[string]string{"runtime_secrets": "runtime_secrets", "storage_secrets": "runtime_secrets", "certificate_state": "certificate_state", "certificate_published": "certificate_published", "redis_data": "redis_data"}
	for name, service := range cfg.Services {
		for _, m := range service.Volumes {
			class := ""
			directory := ""
			if m.Type == "bind" && m.Source != data {
				class = recoveredMountClass(name, m.Target)
				directory = m.Source
			}
			if m.Type == "volume" {
				class = classes[m.Source]
				if class != "" {
					volume, ok := cfg.Volumes[m.Source]
					if !ok {
						return nil, recovery.ErrUnsafe
					}
					directory, e = d.volumeRoot(ctx, volume.Name)
					if e != nil {
						return nil, e
					}
				}
			}
			if class != "" {
				if prior, ok := roots[class]; ok && prior != directory {
					return nil, recovery.ErrUnsafe
				}
				roots[class] = directory
			}
		}
	}
	for name, volume := range cfg.Volumes {
		if class := classes[name]; class != "" && roots[class] == "" {
			directory, err := d.volumeRoot(ctx, volume.Name)
			if err != nil {
				return nil, err
			}
			roots[class] = directory
		}
	}
	return roots, nil
}

func retainStateFile(ctx context.Context, source, name, target, targetName string) error {
	info, e := os.Lstat(filepath.Join(source, name))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return recovery.ErrUnsafe
	}
	if e = os.MkdirAll(target, 0700); e != nil {
		return e
	}
	return replaceStateFile(ctx, source, name, target, targetName, recovery.Entry{Bytes: info.Size(), Mode: 0600, UID: os.Getuid(), GID: os.Getgid()})
}

func replaceStateFile(ctx context.Context, source, name, target, targetName string, entry recovery.Entry) error {
	src, e := os.OpenRoot(source)
	if e != nil {
		return e
	}
	defer src.Close()
	dst, e := os.OpenRoot(target)
	if e != nil {
		return e
	}
	defer dst.Close()
	for _, pair := range []struct {
		root *os.Root
		name string
	}{{src, name}, {dst, targetName}} {
		parts := strings.Split(pair.name, "/")
		for i := range parts {
			current := strings.Join(parts[:i+1], "/")
			info, err := pair.root.Lstat(current)
			if os.IsNotExist(err) && pair.root == dst && i < len(parts)-1 {
				if err = pair.root.Mkdir(current, 0700); err != nil {
					return err
				}
				continue
			}
			if os.IsNotExist(err) && pair.root == dst && i == len(parts)-1 {
				continue
			}
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 || i < len(parts)-1 && !info.IsDir() || i == len(parts)-1 && !info.Mode().IsRegular() {
				return recovery.ErrUnsafe
			}
		}
	}
	in, e := src.Open(name)
	if e != nil {
		return e
	}
	defer in.Close()
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	tempName := path.Join(path.Dir(targetName), ".foc-state-"+hex.EncodeToString(nonce[:]))
	temp, e := dst.OpenFile(tempName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer dst.Remove(tempName)
	h := sha256.New()
	size, e := io.CopyBuffer(io.MultiWriter(temp, h), &stateReader{ctx, in}, make([]byte, 64<<10))
	if e == nil && (size != entry.Bytes || entry.SHA256 != "" && hex.EncodeToString(h.Sum(nil)) != entry.SHA256) {
		e = recovery.ErrUnsafe
	}
	if e == nil {
		e = temp.Chown(entry.UID, entry.GID)
	}
	if e == nil {
		e = temp.Chmod(os.FileMode(entry.Mode))
	}
	if e == nil {
		e = temp.Sync()
	}
	e = errors.Join(e, temp.Close())
	if e != nil {
		return e
	}
	if e = dst.Rename(tempName, targetName); e != nil {
		return e
	}
	return fsutil.SyncDirectory(dst, path.Dir(targetName))
}

type stateReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *stateReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
