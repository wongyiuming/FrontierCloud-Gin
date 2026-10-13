package deployment

import (
	"io"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
)

// ReadRetainedBinding verifies the selected native store without creating a
// lock, binding, directory or database. It is not initialization authority.
func ReadRetainedBinding(c config.Config) ([]byte, error) {
	want, e := fingerprint(c)
	if e != nil {
		return nil, e
	}
	root, e := os.OpenRoot(c.DataRoot)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	info, e := root.Lstat(Binding)
	if e != nil || !info.Mode().IsRegular() || info.Size() != int64(len(want)) {
		return nil, ErrSelection
	}
	f, e := root.Open(Binding)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return nil, ErrSelection
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(len(want))+1))
	if e != nil || string(raw) != want {
		return nil, ErrSelection
	}
	after, e := root.Lstat(Binding)
	if e != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) {
		return nil, ErrSelection
	}
	return raw, nil
}
