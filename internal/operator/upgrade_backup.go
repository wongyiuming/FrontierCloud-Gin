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
	selected := []string{maintenance.Marker, sitecontrol.Manual, sitecontrol.ForceOpen, ".native-runtime.lock", ".native-maintenance-control.lock", sitecontrol.Lock}
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
