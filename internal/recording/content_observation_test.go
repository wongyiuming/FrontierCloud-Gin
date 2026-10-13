package recording

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedContentNativeRecordingRoot(t *testing.T) {
	mounted := t.TempDir()
	name, e := Path(strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Dir(filepath.Join(mounted, name)), 0700); e != nil {
		t.Fatal(e)
	}
	data := []byte("opaque encrypted recording snapshot")
	if e = os.WriteFile(filepath.Join(mounted, name), data, 0600); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(mounted)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	service := &Storage{root: root}
	size := int64(len(data))
	item := store.ExpectedPhysicalItem{Path: "recordings/" + name, ExpectedBytes: &size}
	calls := 0
	result, e := service.ObserveManagedContent(context.Background(), item, size, func() error { calls++; return nil })
	sum := sha256.Sum256(data)
	if e != nil || result.SHA256 != hex.EncodeToString(sum[:]) || calls != 2 {
		t.Fatal(result, calls, e)
	}
	if _, e = service.ObserveManagedContent(context.Background(), item, size+1, func() error { return nil }); e == nil {
		t.Fatal("wrong size")
	}
	if e = os.WriteFile(filepath.Join(mounted, ".recordings-recovery-required"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = service.ObserveManagedContent(context.Background(), item, size, func() error { return nil }); e == nil {
		t.Fatal("recovery fence")
	}
}
