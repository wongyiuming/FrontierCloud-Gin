//go:build !windows

package resourceinventory

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestContentOpenRejectsLinkAndDoesNotBlockOnReplacedFIFO(t *testing.T) {
	dir := t.TempDir()
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if e = unix.Mkfifo(filepath.Join(dir, "changed"), 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		file, e := openContentFile(root, "changed")
		if e == nil {
			info, err := file.Stat()
			if err != nil {
				e = err
			} else if info.Mode().IsRegular() {
				e = os.ErrInvalid
			}
			file.Close()
		}
		done <- e
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("FIFO accepted as regular content")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO replacement blocked before regular-file validation")
	}
	if e = os.WriteFile(filepath.Join(dir, "regular"), []byte("bytes"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("regular", filepath.Join(dir, "link")); e != nil {
		t.Fatal(e)
	}
	if file, e := openContentFile(root, "link"); e == nil {
		file.Close()
		t.Fatal("final symlink followed")
	}
}
