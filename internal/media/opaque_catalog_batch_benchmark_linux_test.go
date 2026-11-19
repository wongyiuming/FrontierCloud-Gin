//go:build linux

package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	_ "modernc.org/sqlite"
)

func benchmarkCurrentRSS() uint64 {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if fields := strings.Fields(line); len(fields) == 3 && fields[0] == "VmRSS:" && fields[2] == "kB" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				return value * 1024
			}
		}
	}
	return 0
}

// This measures only the experimental encrypted tree batch scan, not a
// complete public catalog or an authorization/consistency proof. Profiling is
// opt-in and begins after fixture construction.
func TestOpaqueCatalogBatch2631Profile(t *testing.T) {
	if os.Getenv("FC_CATALOG_BATCH_PROFILE") != "1" {
		t.Skip("explicit isolated performance fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, parentID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, db, codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := sealedtree.InitializeFence(ctx, tree, root, dir); err != nil {
		t.Fatal(err)
	}
	if err := tree.CreateDirectoryWithFacts(ctx, sealedtree.Entry{ParentID: rootID, ObjectID: parentID, Kind: "directory", Name: "benchmark"}, sealedtree.Facts{ObjectID: parentID}); err != nil {
		t.Fatal(err)
	}
	pub, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(nil)
	for i := 0; i < 2631; i++ {
		id := fmt.Sprintf("%064x", 100000+i)
		entry := sealedtree.Entry{ParentID: parentID, ObjectID: id, Kind: "audio", Name: fmt.Sprintf("song-%06d.mp3", i)}
		facts := sealedtree.Facts{ObjectID: id, Playback: &sealedtree.PlaybackFact{LegacyMediaPath: "music/benchmark/" + entry.Name, PlayScore: int64(i), Preference: int64(i%11 - 5), CreatedAt: "2026-01-01", UpdatedAt: "2026-01-01"}}
		placement := sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: strings.Repeat("f", 32), Bytes: 0, ETag: `"fixture"`, SHA256: hex.EncodeToString(digest[:]), State: "active"}
		prepared, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, facts)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(nil)); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	profileDir := os.Getenv("FC_CATALOG_PROFILE_DIR")
	writeProfile := func(name string) {
		if profileDir == "" {
			return
		}
		f, e := os.OpenFile(filepath.Join(profileDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		if e = pprof.Lookup("allocs").WriteTo(f, 0); e != nil {
			f.Close()
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
	}
	writeProfile("alloc-before.pb.gz")
	var cpu *os.File
	if profileDir != "" {
		cpu, err = os.OpenFile(filepath.Join(profileDir, "cpu.pb.gz"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err = pprof.StartCPUProfile(cpu); err != nil {
			cpu.Close()
			t.Fatal(err)
		}
	}
	rssBefore := benchmarkCurrentRSS()
	stopRSS := make(chan struct{})
	peakRSS := make(chan uint64, 1)
	go func() {
		peak := rssBefore
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if rss := benchmarkCurrentRSS(); rss > peak {
					peak = rss
				}
			case <-stopRSS:
				if rss := benchmarkCurrentRSS(); rss > peak {
					peak = rss
				}
				peakRSS <- peak
				return
			}
		}
	}()
	started := time.Now()
	var maxLease time.Duration
	var items []Track
	var scope sealedtree.CatalogScopeProof
	cursor := ""
	for {
		lockStart := time.Now()
		lease, e := tree.AcquireReadFence(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if cursor == "" {
			scope, e = tree.CaptureCatalogScopeWithLease(ctx, lease, parentID, false)
			if e != nil {
				lease.Release()
				t.Fatal(e)
			}
		}
		page, next, e := tree.ListCatalogPageWithLease(ctx, lease, parentID, cursor, 128, false)
		lease.Release()
		if duration := time.Since(lockStart); duration > maxLease {
			maxLease = duration
		}
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range page {
			if item.Entry.Kind != "audio" || item.Facts.Playback == nil {
				t.Fatal("unexpected tree item")
			}
			items = append(items, Track{MediaID: item.Entry.ObjectID, MediaPath: "music/benchmark/" + item.Entry.Name, PlaybackStats: store.PlaybackStats{Preference: int(item.Facts.Playback.Preference), PlayScore: item.Facts.Playback.PlayScore}})
		}
		if next == "" {
			break
		}
		if next == cursor {
			t.Fatal("nonadvancing cursor")
		}
		cursor = next
	}
	sortTracks(items)
	lockStart := time.Now()
	finalLease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = tree.CheckCatalogScopeWithLease(ctx, finalLease, parentID, false, scope)
	finalLease.Release()
	if duration := time.Since(lockStart); duration > maxLease {
		maxLease = duration
	}
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	close(stopRSS)
	observedPeakRSS := <-peakRSS
	if cpu != nil {
		pprof.StopCPUProfile()
		if err := cpu.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Heap profile samples may lag collection. Force the profile snapshot
	// forward after the timed and RSS-sampled interval; never include this GC
	// in reported query or lease duration.
	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	writeProfile("alloc-after.pb.gz")
	if len(items) != 2631 {
		t.Fatal("incomplete catalog", len(items))
	}
	t.Logf("tree_batch_count=%d query_and_sort=%s max_acquire_through_release=%s alloc_delta=%d heap_before_after_gc=%d heap_after_after_gc=%d rss_before=%d sampled_rss_peak=%d", len(items), elapsed, maxLease, after.TotalAlloc-before.TotalAlloc, before.HeapAlloc, after.HeapAlloc, rssBefore, observedPeakRSS)
}
