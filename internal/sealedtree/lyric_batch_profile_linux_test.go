//go:build linux && lyric_profile

package sealedtree

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/sys/unix"
)

// Fixture-only population skips blob I/O, but creates the authenticated tree,
// facts, placements, aliases, nonce reservations and index used by the real
// batch. Construction is not part of the measured interval.
func seedLyricProfile(t *testing.T, s *SQLStore, db *sql.DB, entry Entry) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		t.Fatal(err)
	}
	name, err := s.tree.Seal(entry.ParentID, entry.ObjectID, entry.Kind, entry.Name, 1)
	if err != nil {
		t.Fatal(err)
	}
	nameID, err := reserveEncryptionID(ctx, tx, name)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := s.tree.SealFacts(Facts{ObjectID: entry.ObjectID}, 1)
	if err != nil {
		t.Fatal(err)
	}
	factsID, err := FactsEncryptionID(facts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reserveID(ctx, tx, factsID); err != nil {
		t.Fatal(err)
	}
	p := fixturePlacement(t, entry.ObjectID)
	empty := sha256.Sum256(nil)
	p.Bytes, p.SHA256, p.State = 0, hex.EncodeToString(empty[:]), "active"
	placement, err := s.tree.SealPlacement(p, 1)
	if err != nil {
		t.Fatal(err)
	}
	placementID, err := PlacementEncryptionID(placement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reserveID(ctx, tx, placementID); err != nil {
		t.Fatal(err)
	}
	alias, err := s.tree.BlobIndex(p.ReadAlias)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{placement.BlobIndex, alias} {
		if _, err = tx.Exec(`INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(`INSERT INTO sealed_tree_records(object_index,parent_index,lookup_tag,revision,encryption_id,sealed) VALUES(?,?,?,?,?,?)`, name.ObjectIndex, name.ParentIndex, name.Lookup, 1, nameID, name.Sealed); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO sealed_tree_facts(object_index,revision,encryption_id,sealed) VALUES(?,?,?,?)`, facts.ObjectIndex, 1, factsID, facts.Sealed); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO sealed_tree_placements(object_index,blob_index,revision,encryption_id,sealed) VALUES(?,?,?,?,?)`, placement.ObjectIndex, placement.BlobIndex, 1, placementID, placement.Sealed); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO sealed_tree_aliases(alias_index,object_index) VALUES(?,?)`, alias, name.ObjectIndex); err != nil {
		t.Fatal(err)
	}
	if err = s.listingAdd(ctx, tx, entry, name, listingVisibleGroup); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func lyricProfileRSS() uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				n, _ := strconv.ParseUint(fields[1], 10, 64)
				return n * 1024
			}
		}
	}
	return 0
}

func lyricProfileAllocs(t *testing.T, dir, name string) {
	t.Helper()
	if dir == "" {
		return
	}
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err = pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLyricBatchOneCoreProfile(t *testing.T) {
	count := 2631
	if text := os.Getenv("FC_LYRIC_PROFILE_COUNT"); text != "" {
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 {
			t.Fatal("invalid fixture count")
		}
		count = n
	}
	ctx := context.Background()
	db, s, _, _, _ := fencedFixture(t)
	for _, q := range []string{`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT NOT NULL,role TEXT NOT NULL)`, `INSERT INTO node_identity VALUES(1,'ffffffffffffffffffffffffffffffff','Master')`, `CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	music := Entry{ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", 100), Kind: "directory", Name: "music"}
	lyrics := Entry{ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", 101), Kind: "directory", Name: "lyrics"}
	for _, entry := range []Entry{music, lyrics} {
		if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	lyric := Entry{ParentID: lyrics.ObjectID, ObjectID: fmt.Sprintf("%064x", 102), Kind: "lyric", Name: "fixture.lrc"}
	seedLyricProfile(t, s, db, lyric)
	ops := NativeLyricOperation{OriginID: lyric.ObjectID, TargetIDs: make([]string, 0, count), Changes: make([]NativeLyricChange, 0, count)}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("%064x", i+1000)
		entry := Entry{ParentID: music.ObjectID, ObjectID: id, Kind: "audio", Name: fmt.Sprintf("track-%05d.mp3", i)}
		seedLyricProfile(t, s, db, entry)
		ops.TargetIDs = append(ops.TargetIDs, id)
		ops.Changes = append(ops.Changes, NativeLyricChange{TrackID: id, ExpectedFactsRevision: 1, LyricID: lyric.ObjectID})
	}
	abort := os.Getenv("FC_LYRIC_PROFILE_ABORT") == "1"
	if abort {
		if _, err := db.Exec(`CREATE TRIGGER profile_audit_fail BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	profileDir := os.Getenv("FC_LYRIC_PROFILE_DIR")
	lyricProfileAllocs(t, profileDir, "alloc-before.pb.gz")
	var cpuFile *os.File
	if profileDir != "" {
		var err error
		cpuFile, err = os.Create(filepath.Join(profileDir, "cpu.pb.gz"))
		if err != nil {
			t.Fatal(err)
		}
		if err = pprof.StartCPUProfile(cpuFile); err != nil {
			cpuFile.Close()
			t.Fatal(err)
		}
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	startRSS := lyricProfileRSS()
	var peak atomic.Uint64
	peak.Store(startRSS)
	done := make(chan struct{})
	stopped := make(chan struct{})
	probe, err := s.fence.root.OpenFile(treeFenceFile, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var blockedAt, releasedAt atomic.Int64
	var probeError atomic.Bool
	start := time.Now()
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		check := func() {
			err := unix.Flock(int(probe.Fd()), unix.LOCK_SH|unix.LOCK_NB)
			if err == nil {
				_ = unix.Flock(int(probe.Fd()), unix.LOCK_UN)
				if blockedAt.Load() != 0 {
					releasedAt.CompareAndSwap(0, time.Since(start).Nanoseconds())
				}
			} else if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
				blockedAt.CompareAndSwap(0, time.Since(start).Nanoseconds())
			} else {
				probeError.Store(true)
			}
		}
		for {
			select {
			case <-done:
				check()
				return
			case <-ticker.C:
				check()
				current := lyricProfileRSS()
				for old := peak.Load(); current > old && !peak.CompareAndSwap(old, current); old = peak.Load() {
				}
			}
		}
	}()
	operationErr := s.ApplyNativeLyricBatch(ctx, ops, store.AdminAudit{})
	elapsed := time.Since(start)
	close(done)
	<-stopped
	if cpuFile != nil {
		pprof.StopCPUProfile()
		if err = cpuFile.Close(); err != nil {
			t.Fatal(err)
		}
		lyricProfileAllocs(t, profileDir, "alloc-after.pb.gz")
	}
	if probeError.Load() {
		t.Fatal("shared lock probe failed")
	}
	runtime.ReadMemStats(&after)
	if abort && operationErr == nil || !abort && operationErr != nil {
		t.Fatal("unexpected batch result", operationErr)
	}
	var audits int
	if err = db.QueryRow(`SELECT COUNT(*) FROM admin_audit_log`).Scan(&audits); err != nil || !abort && audits < 1 || abort && audits != 0 {
		t.Fatal("audit outcome", err)
	}
	if abort {
		var modified int
		if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_facts WHERE revision<>1`).Scan(&modified); err != nil || modified != 0 {
			t.Fatal("batch was not rolled back", err)
		}
	}
	observedLock := time.Duration(0)
	if blockedAt.Load() > 0 && releasedAt.Load() > blockedAt.Load() {
		observedLock = time.Duration(releasedAt.Load() - blockedAt.Load())
	}
	t.Logf("lyric_profile count=%d abort=%v elapsed_ms=%.3f write_lock_observed_sampled_ms=%.3f write_lock_upper_bound_ms=%.3f lock_probe_interval_ms=2 total_alloc_bytes=%d heap_before_bytes=%d heap_after_bytes=%d rss_before_bytes=%d sampled_peak_rss_bytes=%d audit_fragments=%d setup_excluded=true", count, abort, float64(elapsed.Microseconds())/1000, float64(observedLock.Microseconds())/1000, float64(elapsed.Microseconds())/1000, after.TotalAlloc-before.TotalAlloc, before.Alloc, after.Alloc, startRSS, peak.Load(), audits)
}
