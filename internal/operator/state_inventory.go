package operator

import (
	"context"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

// Inventory visits state classes only; data subtrees outside the fixed state
// selection are pruned before reading metadata or copying content.
func inventoryState(ctx context.Context, roots map[string]string, selection []string) ([]recovery.Entry, error) {
	var entries []recovery.Entry
	for class, directory := range roots {
		if class == "deployment" {
			continue
		}
		root, e := os.OpenRoot(directory)
		if e != nil {
			return nil, e
		}
		e = fs.WalkDir(root.FS(), ".", func(name string, item fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e := ctx.Err(); e != nil {
				return e
			}
			if class == "data" && !recovery.SelectedPath(selection, name, item.IsDir()) {
				if item.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if name == "." || item.IsDir() {
				return nil
			}
			if class == "data" && (name == maintenance.Marker || name == sitecontrol.Manual || name == sitecontrol.ForceOpen || name == ".native-runtime.lock" || name == ".native-maintenance-control.lock" || name == sitecontrol.Lock) {
				return nil
			}
			if strings.ContainsAny(name, "\\\x00\r\n") || len(name) > 4096 {
				return recovery.ErrUnsafe
			}
			info, e := root.Lstat(name)
			if e != nil {
				return e
			}
			if !info.Mode().IsRegular() || len(entries) >= recovery.MaxFiles {
				return recovery.ErrUnsafe
			}
			entries = append(entries, recovery.Entry{Path: class + "/" + name, Bytes: info.Size()})
			return nil
		})
		root.Close()
		if e != nil {
			return nil, e
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}
