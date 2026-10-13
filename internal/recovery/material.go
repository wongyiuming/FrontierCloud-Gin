package recovery

import (
	"context"
	"io/fs"
	"os"
	"path"
	"strings"
)

// CheckMaterial verifies an extracted member against its already hash-checked
// source archive before Compose preparation rewrites deployment metadata.
// It never initializes keys, repairs permissions, follows links or starts a node.
func CheckMaterial(ctx context.Context, directory string, expected Report) error {
	return checkMaterial(ctx, directory, expected, false)
}

// CheckPreparingMaterial retains full data/key verification while allowing only
// the operator's rewritten deployment metadata during a same-intent retry.
func CheckPreparingMaterial(ctx context.Context, directory string, expected Report) error {
	return checkMaterial(ctx, directory, expected, true)
}

func checkMaterial(ctx context.Context, directory string, expected Report, preparing bool) error {
	if !expected.Verified || validateManifest(expected.Manifest) != nil {
		return ErrUnsafe
	}
	info, e := os.Lstat(directory)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafe
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return e
	}
	defer root.Close()
	allowed := map[string]bool{".": true, "deployment/.fc-recovery-set.json": true}
	mutable := map[string]bool{}
	if preparing {
		for _, name := range []string{".fc-deployment.json", ".fc-images.json", ".fc-restore.json", "docker-compose.recovered.json"} {
			mutable["deployment/"+name] = true
			allowed["deployment/"+name] = true
		}
	}
	for _, entry := range expected.Manifest.Files {
		allowed[entry.Path] = true
		for parent := path.Dir(entry.Path); parent != "."; parent = path.Dir(parent) {
			allowed[parent] = true
		}
	}
	for _, directory := range expected.Manifest.Directories {
		allowed[directory.Path] = true
		for parent := path.Dir(directory.Path); parent != "."; parent = path.Dir(parent) {
			allowed[parent] = true
		}
	}
	if e = fs.WalkDir(root.FS(), ".", func(name string, item fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if !allowed[name] {
			knownScratch := false
			if item.Type().IsRegular() {
				for _, final := range []string{"deployment/.fc-deployment.json", "deployment/.fc-images.json", "deployment/.fc-restore.json", "deployment/docker-compose.recovered.json", "deployment/.fc-recovery-set.json"} {
					if name == final+".next" || strings.HasPrefix(name, final+".next-") {
						knownScratch = true
					}
				}
			}
			if !knownScratch {
				return ErrUnsafe
			}
		}
		if item.Type()&os.ModeSymlink != 0 || !item.IsDir() && !item.Type().IsRegular() {
			return ErrUnsafe
		}
		return nil
	}); e != nil {
		return e
	}
	for _, entry := range expected.Manifest.Files {
		if mutable[entry.Path] {
			continue
		}
		actual, e := hashFile(ctx, root, entry.Path)
		if e != nil || actual.Bytes != entry.Bytes || actual.SHA256 != entry.SHA256 || actual.Mode != entry.Mode || actual.UID != entry.UID || actual.GID != entry.GID {
			return ErrUnsafe
		}
	}
	for _, directory := range expected.Manifest.Directories {
		info, e := root.Lstat(directory.Path)
		if e != nil || !info.IsDir() || int64(info.Mode().Perm()) != directory.Mode {
			return ErrUnsafe
		}
	}
	return nil
}
