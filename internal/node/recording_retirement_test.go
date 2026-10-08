package node

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmptyRecordingVolumeAllowsOnlyRegularZeroByteNativeLeases(t *testing.T) {
	for _, kind := range []string{"empty", "lease", "nonempty", "unknown", "symlink", "journal"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			name := ".recording-" + strings.Repeat("a", 32) + ".lease"
			data := []byte{}
			if kind == "unknown" {
				name = "unrecognized.lease"
			}
			if kind == "journal" {
				name = ".recording-" + strings.Repeat("a", 32) + ".json"
			}
			if kind == "nonempty" {
				data = []byte("not a lease")
			}
			if kind == "symlink" {
				if err := os.Symlink("missing", filepath.Join(dir, name)); err != nil {
					t.Skip("symlinks unavailable")
				}
			} else if kind != "empty" {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			s := Service{recordings: root}
			called := false
			err = s.emptyRecordings(context.Background(), func() error { called = true; return nil })
			allowed := kind == "empty" || kind == "lease"
			if (err == nil) != allowed || called != allowed {
				t.Fatal(kind, called, err)
			}
		})
	}
}
