package operator

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	"os"
	"path"
	"strings"
)

func upgradeDataSelection(cfg Config, r Receipt) ([]string, error) {
	return upgradeStateSelection(cfg, r, true)
}
func upgradeStateSelection(cfg Config, r Receipt, requireDatabase bool) ([]string, error) {
	selected := []string{maintenance.Marker, sitecontrol.Manual, sitecontrol.ForceOpen, ".native-runtime.lock", ".native-maintenance-control.lock", sitecontrol.Lock, "media-keys/media-premaster.key"}
	data, err := upgradeDataRoot(cfg)
	if err != nil {
		return nil, err
	}
	keyRoot, err := os.OpenRoot(data)
	if err != nil {
		return nil, err
	}
	defer keyRoot.Close()
	if parent, err := keyRoot.Lstat("media-keys"); err == nil {
		if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("media premaster directory is unsafe")
		}
		if key, err := keyRoot.Lstat("media-keys/media-premaster.key"); err == nil {
			if !key.Mode().IsRegular() || key.Mode()&os.ModeSymlink != 0 || requireDatabase && (key.Size() != 32 || key.Mode().Perm() != 0600) {
				return nil, errors.New("media premaster state is unsafe")
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if r.Database == "sqlite" {
		root := cfg.Services["web"].Environment["DATA_ROOT"]
		database := cfg.Services["web"].Environment["SQLITE_PATH"]
		if !path.IsAbs(root) || !path.IsAbs(database) || path.Clean(database) != database || !strings.HasPrefix(database, path.Clean(root)+"/") {
			return nil, errors.New("upgrade state backup requires the recorded SQLite file inside DATA_ROOT")
		}
		relative := strings.TrimPrefix(database, path.Clean(root)+"/")
		selected = append(selected, relative, relative+"-wal", relative+"-shm")
		data, e := upgradeDataRoot(cfg)
		if e != nil {
			return nil, e
		}
		opened, e := os.OpenRoot(data)
		if e != nil {
			return nil, e
		}
		defer opened.Close()
		parts := strings.Split(relative, "/")
		for i := range parts {
			info, e := opened.Lstat(strings.Join(parts[:i+1], "/"))
			if !requireDatabase && os.IsNotExist(e) {
				continue
			}
			if e != nil || info.Mode()&os.ModeSymlink != 0 || i < len(parts)-1 && !info.IsDir() || i == len(parts)-1 && !info.Mode().IsRegular() {
				return nil, errors.New("recorded SQLite state path missing or unsafe")
			}
		}
	}
	return selected, nil
}

func (d *Deployment) UpgradeBackupCapacity(ctx context.Context, r Receipt, output string) (BackupCapacity, error) {
	return d.backupCapacityScope(ctx, r, output, "", recovery.UpgradeStateScope)
}
func (d *Deployment) requireUpgradeBackupCapacity(ctx context.Context, r Receipt, output string) error {
	p, e := d.UpgradeBackupCapacity(ctx, r, output)
	if e != nil {
		return e
	}
	if !p.Fits {
		return errors.New("upgrade state backup capacity insufficient; media and lyrics are excluded")
	}
	return nil
}
