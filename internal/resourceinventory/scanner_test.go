package resourceinventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func inventoryFixture(t *testing.T) (string, *os.Root, *Scanner) {
	t.Helper()
	dir := t.TempDir()
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	return dir, root, nil
}
func TestScannerReportsHiddenNestedSparseAndLinksWithoutWriting(t *testing.T) {
	dir, root, _ := inventoryFixture(t)
	for _, name := range []string{"music/hidden/nested", ".business-backups", ".delete-fixture"} {
		if e := root.MkdirAll(name, 0700); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < 300; i++ {
		name := fmt.Sprintf("music/hidden/nested/%03d.mp3", i)
		f, e := root.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write([]byte("ID3")); e != nil {
			t.Fatal(e)
		}
		f.Close()
	}
	for _, name := range []string{".business-backups/only-recovery.tar", ".delete-fixture/0", ".migration-data-fixture.part", "unmanaged.txt"} {
		f, e := root.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		f.Close()
	}
	f, e := root.OpenFile("music/large.bin", os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(17 << 30); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if e = root.Link("music/hidden/nested/000.mp3", "same-byte-hardlink"); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("music", filepath.Join(dir, "loop")); e != nil {
		t.Fatal(e)
	}
	outside := t.TempDir()
	if e = os.WriteFile(filepath.Join(outside, "secret"), []byte("never enumerate outside root"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(outside, filepath.Join(dir, "outside")); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	scanner, e := New(root)
	if e != nil {
		t.Fatal(e)
	}
	defer scanner.Close()
	entries := map[string]Entry{}
	var count uint64
	var bytes int64
	for seq := uint64(0); ; seq++ {
		page, e := scanner.Next(context.Background(), seq)
		if e != nil {
			t.Fatal(e)
		}
		if len(page.Entries) > PageEntries {
			t.Fatal("unbounded page")
		}
		raw, _ := json.Marshal(page)
		if len(raw) > PageBytes+2048 {
			t.Fatal("unbounded encoded response", len(raw))
		}
		replay, e := scanner.Next(context.Background(), seq)
		if e != nil || !reflect.DeepEqual(page, replay) {
			t.Fatal("lost page acknowledgment", e)
		}
		for _, entry := range page.Entries {
			if _, ok := entries[entry.Path]; ok {
				t.Fatal("duplicate entry", entry.Path)
			}
			entries[entry.Path] = entry
			count++
			bytes += entry.LogicalBytes
		}
		if page.EntryCount != count || page.LogicalBytes != bytes || len(page.ObservationSHA256) != 64 {
			t.Fatal("prefix accounting", page)
		}
		if page.Complete {
			break
		}
	}
	for _, name := range []string{".business-backups/only-recovery.tar", ".delete-fixture/0", ".migration-data-fixture.part", "unmanaged.txt", "music/hidden/nested/299.mp3"} {
		if _, ok := entries[name]; !ok {
			t.Fatal("silently omitted physical path", name)
		}
	}
	if entries["loop"].Kind != "symlink" || entries["outside"].Kind != "symlink" {
		t.Fatal("links not reported")
	}
	for name := range entries {
		if strings.HasPrefix(name, "outside/") || strings.HasPrefix(name, "loop/") {
			t.Fatal("followed symlink", name)
		}
	}
	if entries["music/large.bin"].LogicalBytes != 17<<30 || bytes != (17<<30)+903 {
		t.Fatal("logical bytes are not physical allocated bytes", bytes)
	}
	after, e := os.ReadDir(dir)
	if e != nil || len(before) != len(after) {
		t.Fatal("read-only scan changed root", e)
	}
}
func TestScannerRejectsChangedDirectoryAndInvalidSequences(t *testing.T) {
	_, root, _ := inventoryFixture(t)
	for i := 0; i < PageEntries+10; i++ {
		f, e := root.OpenFile(fmt.Sprintf("%03d", i), os.O_CREATE|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		f.Close()
	}
	scanner, e := New(root)
	if e != nil {
		t.Fatal(e)
	}
	defer scanner.Close()
	if _, e = scanner.Next(context.Background(), 1); !errors.Is(e, ErrSequence) {
		t.Fatal("skipped first page", e)
	}
	first, e := scanner.Next(context.Background(), 0)
	if e != nil || first.Complete {
		t.Fatal(first, e)
	}
	// Change the active root timestamp deterministically, independently of
	// filesystem timestamp granularity or the name order returned by readdir.
	info, e := root.Lstat(".")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chtimes(root.Name(), info.ModTime(), info.ModTime().Add(2e9)); e != nil {
		t.Fatal(e)
	}
	if page, e := scanner.Next(context.Background(), 1); !errors.Is(e, ErrChanged) || page.Complete {
		t.Fatal("changed scan completed", page, e)
	}
	if _, e = scanner.Next(context.Background(), 1); !errors.Is(e, ErrSequence) {
		t.Fatal("failed session resumed", e)
	}
	fresh, e := New(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	if _, e = fresh.Next(context.Background(), 1); !errors.Is(e, ErrSequence) {
		t.Fatal("restart adopted stale cursor", e)
	}
	if e = scanner.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = root.Lstat("."); e != nil {
		t.Fatal("scanner closed borrowed root", e)
	}
}
func TestScannerBoundsDeepPathsAndHonorsCancellation(t *testing.T) {
	_, root, _ := inventoryFixture(t)
	if e := root.MkdirAll(strings.Repeat("d/", MaxDepth+1), 0700); e != nil {
		t.Fatal(e)
	}
	scanner, e := New(root)
	if e != nil {
		t.Fatal(e)
	}
	defer scanner.Close()
	var fault error
	for seq := uint64(0); seq < 10; seq++ {
		page, e := scanner.Next(context.Background(), seq)
		if e != nil {
			fault = e
			break
		}
		if page.Complete {
			t.Fatal("excess depth accepted")
		}
	}
	if !errors.Is(fault, ErrLimit) {
		t.Fatal("unbounded handles/depth", fault)
	}
	scanner, e = New(root)
	if e != nil {
		t.Fatal(e)
	}
	defer scanner.Close()
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, e = scanner.Next(ctx, 0); !errors.Is(e, context.Canceled) {
		t.Fatal("ignored cancellation", e)
	}
}

func TestScannerBoundsEncodedPagesAndCarriesPendingEntries(t *testing.T) {
	_, root, _ := inventoryFixture(t)
	parts := make([]string, 20)
	for i := range parts {
		parts[i] = strings.Repeat(string(rune(1)), 180)
	}
	parent := strings.Join(parts, "/")
	if e := root.MkdirAll(parent, 0700); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 40; i++ {
		f, e := root.OpenFile(parent+fmt.Sprintf("/%03d", i), os.O_CREATE|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		f.Close()
	}
	scanner, e := New(root)
	if e != nil {
		t.Fatal(e)
	}
	defer scanner.Close()
	seen := map[string]bool{}
	pages := 0
	for seq := uint64(0); ; seq++ {
		page, e := scanner.Next(context.Background(), seq)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := json.Marshal(page)
		if e != nil || len(raw) > PageBytes+2048 {
			t.Fatal("escaped names bypassed response bound", len(raw), e)
		}
		for _, entry := range page.Entries {
			if seen[entry.Path] {
				t.Fatal("pending entry duplicated")
			}
			seen[entry.Path] = true
		}
		pages++
		if page.Complete {
			break
		}
	}
	if len(seen) != 60 || pages < 10 {
		t.Fatal("byte-bound pagination omitted entries", len(seen), pages)
	}
}
