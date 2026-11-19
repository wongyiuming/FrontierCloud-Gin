//go:build linux && lyric_profile

package sealedtree

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/sys/unix"
)

// This is a local-only feasibility experiment, not an import, recovery or
// production activation API. It writes only encrypted tree records and keyed
// indexes to a private, per-task stage. Authorization, old writers, external
// rollback anchors, crash-safe stage cleanup and cross-host locks remain gates.
type stagedLyricRow struct {
	Index, ParentIndex, Lookup, NameID, OldFactsID, NewFactsID, BlobIndex, PlacementID, AliasIndex string
	NameRevision, OldFactsRevision, PlacementRevision                                              int64
	NameSealed, OldFactsSealed, NewFactsSealed, PlacementSealed                                    []byte
}
type stagedLyricCapture struct {
	row   stagedLyricRow
	facts Facts
	path  string
}

func stageLyricMAC(key []byte, job string, sequence int, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("frontiercloud:lyric-stage:fixture:v1\x00"))
	m.Write([]byte(job))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(sequence))
	m.Write(n[:])
	m.Write(payload)
	return m.Sum(nil)
}

func writeStagedLyric(w io.Writer, key []byte, job string, sequence int, row stagedLyricRow) error {
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(row); err != nil {
		return err
	}
	raw := buffer.Bytes()
	if len(raw) > 128*1024 {
		return ErrInvalid
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(raw)))
	for _, part := range [][]byte{n[:], raw, stageLyricMAC(key, job, sequence, raw)} {
		if _, err := w.Write(part); err != nil {
			return err
		}
	}
	return nil
}

func readStagedLyric(r io.Reader, key []byte, job string, sequence int) (stagedLyricRow, error) {
	var row stagedLyricRow
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return row, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > 128*1024 {
		return row, ErrInvalid
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(r, raw); err != nil {
		return row, err
	}
	var tag [32]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil {
		return row, err
	}
	if !hmac.Equal(tag[:], stageLyricMAC(key, job, sequence, raw)) {
		return row, ErrInvalid
	}
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&row); err != nil {
		return row, err
	}
	return row, nil
}

func stagingRow(ctx context.Context, s *SQLStore, tx *sql.Tx, cache *lyricTxCache, id, lyricID string) (stagedLyricCapture, error) {
	var empty stagedLyricCapture
	r, entry, err := s.recordByID(ctx, tx, id)
	if err != nil || entry.Kind != "audio" {
		return empty, ErrInvalid
	}
	trackPath, err := cache.path(entry)
	if err != nil || !strings.HasPrefix(trackPath, "music/") {
		return empty, ErrInvalid
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, r.ObjectIndex)
	if err != nil || revision != 1 || facts.Revocation != nil || facts.InternalPlaceholder {
		return empty, ErrInvalid
	}
	if noPendingLyricRevocation(ctx, tx, r.ObjectIndex) != nil {
		return empty, ErrInvalid
	}
	placement, err := s.placementFor(ctx, tx, entry, r.ObjectIndex)
	if err != nil || placement.State != "active" {
		return empty, ErrInvalid
	}
	if _, err = cache.lyric(lyricID); err != nil {
		return empty, err
	}
	old, err := scanFacts(tx.QueryRowContext(ctx, `SELECT object_index,revision,encryption_id,sealed FROM sealed_tree_facts WHERE object_index=?`, r.ObjectIndex))
	if err != nil || old.Revision != revision {
		return empty, ErrInvalid
	}
	var placeID, blob string
	var placeRevision int64
	var placeSealed []byte
	if tx.QueryRowContext(ctx, `SELECT blob_index,revision,encryption_id,sealed FROM sealed_tree_placements WHERE object_index=?`, r.ObjectIndex).Scan(&blob, &placeRevision, &placeID, &placeSealed) != nil {
		return empty, ErrInvalid
	}
	nameID, err := EncryptionID(r)
	if err != nil {
		return empty, err
	}
	oldID, err := FactsEncryptionID(old)
	if err != nil {
		return empty, err
	}
	alias, err := s.tree.BlobIndex(placement.ReadAlias)
	if err != nil {
		return empty, err
	}
	return stagedLyricCapture{row: stagedLyricRow{Index: r.ObjectIndex, ParentIndex: r.ParentIndex, Lookup: r.Lookup, NameID: nameID, OldFactsID: oldID, BlobIndex: blob, PlacementID: placeID, AliasIndex: alias, NameRevision: r.Revision, OldFactsRevision: revision, PlacementRevision: placeRevision, NameSealed: r.Sealed, OldFactsSealed: old.Sealed, PlacementSealed: placeSealed}, facts: facts, path: trackPath}, nil
}

func stagingTarget(ctx context.Context, s *SQLStore, tx *sql.Tx, entry Entry) (stagedLyricRow, error) {
	var row stagedLyricRow
	r, got, err := s.recordByID(ctx, tx, entry.ObjectID)
	if err != nil || got != entry {
		return row, ErrInvalid
	}
	facts, rev, err := s.factsFor(ctx, tx, entry, r.ObjectIndex)
	if err != nil || facts.Revocation != nil || facts.InternalPlaceholder {
		return row, ErrInvalid
	}
	old, err := scanFacts(tx.QueryRowContext(ctx, `SELECT object_index,revision,encryption_id,sealed FROM sealed_tree_facts WHERE object_index=?`, r.ObjectIndex))
	if err != nil || old.Revision != rev {
		return row, ErrInvalid
	}
	p, err := s.placementFor(ctx, tx, entry, r.ObjectIndex)
	if err != nil || p.State != "active" {
		return row, ErrInvalid
	}
	row.Index = r.ObjectIndex
	row.ParentIndex, row.Lookup = r.ParentIndex, r.Lookup
	row.NameRevision = r.Revision
	row.NameSealed = r.Sealed
	row.NameID, err = EncryptionID(r)
	if err != nil {
		return row, err
	}
	row.OldFactsRevision = rev
	row.OldFactsSealed = old.Sealed
	row.OldFactsID, err = FactsEncryptionID(old)
	if err != nil {
		return row, err
	}
	row.NewFactsID = row.OldFactsID
	row.AliasIndex, err = s.tree.BlobIndex(p.ReadAlias)
	if err != nil {
		return row, err
	}
	if tx.QueryRowContext(ctx, `SELECT blob_index,revision,encryption_id,sealed FROM sealed_tree_placements WHERE object_index=?`, r.ObjectIndex).Scan(&row.BlobIndex, &row.PlacementRevision, &row.PlacementID, &row.PlacementSealed) != nil {
		return row, ErrInvalid
	}
	return row, nil
}

func stageMatch(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	var n int
	if tx.QueryRowContext(ctx, query, args...).Scan(&n) != nil || n != 1 {
		return ErrConflict
	}
	return nil
}

func assertStageOpaque(file *os.File, patterns ...[]byte) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	buffer := make([]byte, 128*1024+64)
	carry := 0
	for {
		n, err := file.Read(buffer[carry:])
		if n > 0 {
			view := buffer[:carry+n]
			for _, pattern := range patterns {
				if bytes.Contains(view, pattern) {
					return ErrInvalid
				}
			}
			carry = 64
			if len(view) < carry {
				carry = len(view)
			}
			copy(buffer[:carry], view[len(view)-carry:])
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func commitStagedLyric(ctx context.Context, s *SQLStore, file *os.File, key []byte, job string, count int, checks []CatalogScopeCheck, lyricID string, lyricSnapshot stagedLyricRow, audit lyricAuditPayload) error {
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	var identity, role string
	if tx.QueryRowContext(ctx, `SELECT node_id,role FROM node_identity WHERE singleton=1`).Scan(&identity, &role) != nil || identity != "ffffffffffffffffffffffffffffffff" || role != "Master" {
		return ErrInvalid
	}
	for _, check := range checks {
		state, e := s.catalogScope(ctx, tx, check.ParentID, check.IncludeHidden)
		if e != nil {
			return e
		}
		got, e := s.openListingCursor(check.Proof.sealed, s.listingMAC("scope-proof", state.scope), state.revision, state.anchor)
		if e != nil || got != s.listingMAC("scope-proof-marker", check.ParentID) {
			return ErrConflict
		}
	}
	// Verify the target's exact authenticated records again, even if its scope
	// revision was tampered with outside the cooperating writer protocol.
	if err = checkStagedIdentity(ctx, tx, lyricSnapshot); err != nil {
		return err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(file, 128*1024)
	groups := map[string]bool{}
	for i := 0; i < count; i++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		row, e := readStagedLyric(reader, key, job, i)
		if e != nil {
			return e
		}
		newID, e := FactsEncryptionID(FactsRecord{ObjectIndex: row.Index, Revision: row.OldFactsRevision + 1, Sealed: row.NewFactsSealed})
		if e != nil || !hmac.Equal([]byte(newID), []byte(row.NewFactsID)) {
			return ErrInvalid
		}
		if e = checkStagedIdentity(ctx, tx, row); e != nil {
			return e
		}
		if _, e = reserveID(ctx, tx, row.NewFactsID); e != nil {
			return e
		}
		result, e := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=? AND encryption_id=? AND sealed=?`, row.OldFactsRevision+1, row.NewFactsID, row.NewFactsSealed, row.Index, row.OldFactsRevision, row.OldFactsID, row.OldFactsSealed)
		if e != nil {
			return e
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return ErrConflict
		}
		// All tracks in this measured fixture share one authenticated parent.
		groups[s.listingClassGroup(checks[0].ParentID, listingVisibleGroup)] = true
	}
	if _, e := reader.Peek(1); e != io.EOF {
		return ErrInvalid
	}
	for group := range groups {
		if err = s.listingAdjust(ctx, tx, group, 0); err != nil {
			return err
		}
	}
	if err = s.appendEncryptedLyricAudit(ctx, tx, job, audit); err != nil {
		return err
	}
	_ = lyricID
	return tx.Commit()
}

func checkStagedIdentity(ctx context.Context, tx *sql.Tx, row stagedLyricRow) error {
	if !hexID(row.Index) || !hexID(row.ParentIndex) || !hexID(row.Lookup) || !hexID(row.NameID) || !hexID(row.OldFactsID) || !hexID(row.NewFactsID) || !hexID(row.BlobIndex) || !hexID(row.PlacementID) || !hexID(row.AliasIndex) {
		return ErrInvalid
	}
	if err := stageMatch(ctx, tx, `SELECT COUNT(*) FROM sealed_tree_records WHERE object_index=? AND parent_index=? AND lookup_tag=? AND revision=? AND encryption_id=? AND sealed=?`, row.Index, row.ParentIndex, row.Lookup, row.NameRevision, row.NameID, row.NameSealed); err != nil {
		return err
	}
	if err := stageMatch(ctx, tx, `SELECT COUNT(*) FROM sealed_tree_facts WHERE object_index=? AND revision=? AND encryption_id=? AND sealed=?`, row.Index, row.OldFactsRevision, row.OldFactsID, row.OldFactsSealed); err != nil {
		return err
	}
	if err := stageMatch(ctx, tx, `SELECT COUNT(*) FROM sealed_tree_placements WHERE object_index=? AND blob_index=? AND revision=? AND encryption_id=? AND sealed=?`, row.Index, row.BlobIndex, row.PlacementRevision, row.PlacementID, row.PlacementSealed); err != nil {
		return err
	}
	if err := stageMatch(ctx, tx, `SELECT COUNT(*) FROM sealed_tree_aliases WHERE object_index=? AND alias_index=?`, row.Index, row.AliasIndex); err != nil {
		return err
	}
	var pending int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?`, row.Index).Scan(&pending) != nil || pending != 0 {
		return ErrConflict
	}
	for _, id := range []string{row.NameID, row.OldFactsID, row.PlacementID} {
		if err := stageMatch(ctx, tx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, id); err != nil {
			return err
		}
	}
	for _, id := range []string{row.BlobIndex, row.AliasIndex} {
		if err := stageMatch(ctx, tx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, id); err != nil {
			return err
		}
	}
	return nil
}

func TestLyricTwoPhaseFeasibility(t *testing.T) {
	count := 2631
	if raw := os.Getenv("FC_LYRIC_PROFILE_COUNT"); raw != "" {
		v, e := strconv.Atoi(raw)
		if e != nil || v < 1 {
			t.Fatal("invalid count")
		}
		count = v
	}
	ctx := context.Background()
	db, s, _, dbPath, _ := fencedFixture(t)
	for _, q := range []string{`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT NOT NULL,role TEXT NOT NULL)`, `INSERT INTO node_identity VALUES(1,'ffffffffffffffffffffffffffffffff','Master')`, `CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`} {
		if _, e := db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	music := Entry{ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", 100), Kind: "directory", Name: "music"}
	lyrics := Entry{ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", 101), Kind: "directory", Name: "lyrics"}
	for _, e := range []Entry{music, lyrics} {
		if err := s.CreateDirectoryWithFacts(ctx, e, Facts{ObjectID: e.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	lyric := Entry{ParentID: lyrics.ObjectID, ObjectID: fmt.Sprintf("%064x", 102), Kind: "lyric", Name: "fixture.lrc"}
	seedLyricProfile(t, s, db, lyric)
	ids := make([]string, count)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i+1000)
		seedLyricProfile(t, s, db, Entry{ParentID: music.ObjectID, ObjectID: ids[i], Kind: "audio", Name: fmt.Sprintf("track-%05d.mp3", i)})
	}
	var busy, walFrames, checkpointed int
	if err := db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &walFrames, &checkpointed); err != nil || busy != 0 {
		t.Fatal("fixture checkpoint", err)
	}
	job, err := NewBlobID()
	if err != nil {
		t.Fatal(err)
	}
	stageDir := t.TempDir()
	stagePath := filepath.Join(stageDir, ".lyric-stage-"+job)
	file, err := os.OpenFile(stagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// Preallocate a conservative upper bound before preparing any row.
	perItem := int64(2*(1+recordSaltBytes+nonceBytes+factsPayloadBytes+16) + 16384)
	if int64(count) > int64(^uint64(0)>>1)/perItem {
		t.Fatal("stage reservation overflow")
	}
	reservation := int64(count) * perItem
	if err = unix.Fallocate(int(file.Fd()), 0, 0, reservation); err != nil {
		t.Fatal("stage capacity reservation", err)
	}
	key, err := hex.DecodeString(s.listingMAC("lyric-stage-fixture", job, s.rootID, "ffffffffffffffffffffffffffffffff"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	rssBefore := lyricProfileRSS()
	var peakRSS atomic.Uint64
	peakRSS.Store(rssBefore)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				current := lyricProfileRSS()
				for old := peakRSS.Load(); current > old && !peakRSS.CompareAndSwap(old, current); old = peakRSS.Load() {
				}
			}
		}
	}()
	prepStart := time.Now()
	var longestRead time.Duration
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p1, err := s.CaptureCatalogScopeWithLease(ctx, lease, music.ObjectID, false)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := s.CaptureCatalogScopeWithLease(ctx, lease, lyrics.ObjectID, false)
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	checks := []CatalogScopeCheck{{ParentID: music.ObjectID, Proof: p1}, {ParentID: lyrics.ObjectID, Proof: p2}}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
	targets := make([]string, 0, count)
	changes := make([]LyricAuditChange, 0, count)
	var origin stagedLyricRow
	for start := 0; start < count; start += 128 {
		readStart := time.Now()
		lease, err = s.AcquireReadFence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.CheckCatalogScopesWithLease(ctx, lease, checks); err != nil {
			t.Fatal(err)
		}
		tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if e != nil {
			t.Fatal(e)
		}
		cache := lyricTxCache{s: s, tx: tx, ctx: ctx, masterID: "ffffffffffffffffffffffffffffffff", entries: map[string]lyricCachedEntry{}, parents: map[string]string{}, lyrics: map[string]string{}}
		if _, e = cache.lyric(lyric.ObjectID); e != nil {
			t.Fatal(e)
		}
		if start == 0 {
			origin, e = stagingTarget(ctx, s, tx, lyric)
			if e != nil {
				t.Fatal(e)
			}
		}
		end := start + 128
		if end > count {
			end = count
		}
		batch := make([]stagedLyricCapture, 0, end-start)
		for i := start; i < end; i++ {
			capture, e := stagingRow(ctx, s, tx, &cache, ids[i], lyric.ObjectID)
			if e != nil {
				t.Fatal(e)
			}
			batch = append(batch, capture)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
		if e = lease.Check(ctx); e != nil {
			t.Fatal(e)
		}
		lease.Release()
		if duration := time.Since(readStart); duration > longestRead {
			longestRead = duration
		}
		for i, capture := range batch {
			facts := capture.facts
			facts.Lyric = &LyricFact{LegacyMediaPath: capture.path, LyricID: lyric.ObjectID, LegacyLyricPath: "lyrics/fixture.lrc", CreatedAt: now, UpdatedAt: now}
			facts.InternalDefaultLyric = nil
			facts.LyricResolution = &LyricResolutionFact{State: "explicit", Origin: "native", OperationID: job, PreviousRevision: capture.row.OldFactsRevision, RelationCreatedAt: now, RelationUpdatedAt: now}
			facts.LyricResolution.Evidence, e = s.nativeLyricEvidence(facts)
			if e != nil {
				t.Fatal(e)
			}
			next, e := s.tree.SealFacts(facts, capture.row.OldFactsRevision+1)
			if e != nil {
				t.Fatal(e)
			}
			capture.row.NewFactsSealed = next.Sealed
			capture.row.NewFactsID, e = FactsEncryptionID(next)
			if e != nil {
				t.Fatal(e)
			}
			if e = writeStagedLyric(file, key, job, start+i, capture.row); e != nil {
				t.Fatal(e)
			}
			targets = append(targets, capture.path)
			changes = append(changes, LyricAuditChange{Track: capture.path, Lyric: "lyrics/fixture.lrc"})
		}
	}
	pos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(pos); err != nil {
		t.Fatal(err)
	}
	if err = assertStageOpaque(file, []byte("track-00000.mp3"), []byte("lyrics/fixture.lrc")); err != nil {
		t.Fatal("stage exposed logical path", err)
	}
	if err = file.Sync(); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(stageDir)
	if err != nil {
		t.Fatal(err)
	}
	if err = parent.Sync(); err != nil {
		parent.Close()
		t.Fatal(err)
	}
	parent.Close()
	prepDuration := time.Since(prepStart)
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("FC_LYRIC_PROFILE_ABORT") == "1" {
		var b [1]byte
		if _, err = file.ReadAt(b[:], pos-1); err != nil {
			t.Fatal(err)
		}
		b[0] ^= 1
		if _, err = file.WriteAt(b[:], pos-1); err != nil {
			t.Fatal(err)
		}
		if err = file.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	audit := lyricAuditPayload{Origin: "lyrics/fixture.lrc", Targets: targets, Changes: changes, Relations: count, At: now, Audit: store.AdminAudit{TargetCount: count + 1}}
	writeStart := time.Now()
	err = commitStagedLyric(ctx, s, file, key, job, count, checks, lyric.ObjectID, origin, audit)
	writeDuration := time.Since(writeStart)
	close(done)
	<-stopped
	runtime.ReadMemStats(&after)
	abort := os.Getenv("FC_LYRIC_PROFILE_ABORT") == "1"
	if abort && err == nil || !abort && err != nil {
		t.Fatal("unexpected commit", err)
	}
	if abort {
		var changed int
		if e := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_facts WHERE revision<>1`).Scan(&changed); e != nil || changed != 0 {
			t.Fatal("tampered stage partially committed", e)
		}
	}
	var walBytes int64
	if stat, e := os.Stat(dbPath + "-wal"); e == nil {
		walBytes = stat.Size()
	}
	rssAfter := lyricProfileRSS()
	current, err := os.Lstat(stagePath)
	if err != nil || !os.SameFile(info, current) {
		t.Fatal("stage file replaced", err)
	}
	if err = os.Remove(stagePath); err != nil {
		t.Fatal(err)
	}
	t.Logf("lyric_two_phase count=%d abort=%v prep_ms=%.3f max_shared_read_upper_ms=%.3f commit_write_lock_upper_ms=%.3f stage_reserved_bytes=%d stage_bytes=%d wal_bytes=%d total_alloc_bytes=%d rss_before_bytes=%d sampled_peak_rss_bytes=%d rss_after_bytes=%d setup_excluded=true", count, abort, float64(prepDuration.Microseconds())/1000, float64(longestRead.Microseconds())/1000, float64(writeDuration.Microseconds())/1000, reservation, pos, walBytes, after.TotalAlloc-before.TotalAlloc, rssBefore, peakRSS.Load(), rssAfter)
}
