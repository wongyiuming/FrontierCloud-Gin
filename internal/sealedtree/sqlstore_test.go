package sealedtree

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

func sqliteFixture(t *testing.T) (*sql.DB, *SQLStore, string) {
	t.Helper()
	name := filepath.Join(t.TempDir(), "tree.sqlite")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(name)+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root := strings.Repeat("a", 64)
	s, err := InitializeSQLite(context.Background(), db, fixture(t), root)
	if err != nil {
		t.Fatal(err)
	}
	s.unsafePrototype = true // isolated synthetic fixture; runtime constructors never set this
	return db, s, name
}

func fixturePlacement(t *testing.T, objectID string) Placement {
	t.Helper()
	blobID, err := NewBlobID()
	if err != nil {
		t.Fatal(err)
	}
	alias, err := NewBlobID()
	if err != nil {
		t.Fatal(err)
	}
	return Placement{ObjectID: objectID, NativeObjectID: objectID, OwnerID: strings.Repeat("f", 32), BlobID: blobID, ReadAlias: alias, Bytes: 7, SHA256: strings.Repeat("9", 64)}
}

func TestPendingIntegrityCheckRejectsTampering(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "秘密.mp3"}
	op, err := s.PrepareFile(ctx, entry, fixturePlacement(t, entry.ObjectID))
	if err != nil {
		t.Fatal(err)
	}
	if count, err := s.Check(ctx); err != nil || count != 0 {
		t.Fatalf("pending should authenticate, not count as active: %d %v", count, err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_pending_files SET name_sealed=zeroblob(length(name_sealed)) WHERE operation_id=?`, op); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Check(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatalf("corrupt pending accepted: %v", err)
	}
}

func TestPendingOperationIdentityIsAuthenticated(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "private.mp3"}
	op, err := s.PrepareFile(ctx, entry, fixturePlacement(t, entry.ObjectID))
	if err != nil {
		t.Fatal(err)
	}
	replacement := strings.Repeat("d", 64)
	if _, err = db.Exec(`UPDATE sealed_tree_operation_ids SET operation_id=? WHERE operation_id=?`, replacement, op); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_pending_files SET operation_id=? WHERE operation_id=?`, replacement, op); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Check(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatalf("operation substitution accepted: %v", err)
	}
}

func TestOrphanPendingReservationIsRejected(t *testing.T) {
	db, s, _ := sqliteFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "private.mp3"}
	op, err := s.PrepareFile(context.Background(), entry, fixturePlacement(t, entry.ObjectID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM sealed_tree_pending_files WHERE operation_id=?`, op); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Check(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("orphan pending reservation accepted: %v", err)
	}
}

func TestNameReadsRejectMissingEncryptionReservation(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "album"}
	if err := s.Create(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM sealed_tree_encryption_ids WHERE encryption_id=(SELECT encryption_id FROM sealed_tree_records LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, entry.ObjectID); !errors.Is(err, ErrInvalid) {
		t.Fatal("Get accepted unreserved encrypted record", err)
	}
	if _, _, err := s.Find(ctx, s.rootID, entry.Name); !errors.Is(err, ErrInvalid) {
		t.Fatal("Find accepted unreserved encrypted record", err)
	}
	if _, _, err := s.List(ctx, s.rootID, "", 10); !errors.Is(err, ErrInvalid) {
		t.Fatal("List accepted unreserved encrypted record", err)
	}
}

func TestUnfencedTreeMutationAndPublicResolutionFailClosed(t *testing.T) {
	_, s, _ := sqliteFixture(t)
	s.unsafePrototype = false
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "album"}
	if err := s.CreateDirectoryWithFacts(context.Background(), entry, Facts{ObjectID: entry.ObjectID}); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("unfenced mutation accepted", err)
	}
	if _, err := s.ResolveVisiblePath(context.Background(), entry.ObjectID); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("unfenced public resolution accepted", err)
	}
}

func TestSQLiteTransactionsPreserveIdentityAndRejectCycles(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	dir, sub, song := strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	for _, entry := range []Entry{
		{ParentID: s.rootID, ObjectID: dir, Kind: "directory", Name: "私密专辑"},
		{ParentID: dir, ObjectID: sub, Kind: "directory", Name: "子目录"},
		{ParentID: sub, ObjectID: song, Kind: "audio", Name: "晴天.mp3"},
	} {
		var err error
		if entry.Kind == "directory" {
			err = s.Create(ctx, entry)
		} else {
			err = s.CreateFile(ctx, entry, fixturePlacement(t, entry.ObjectID))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	got, revision, err := s.Find(ctx, sub, "晴天.mp3")
	if err != nil || got.ObjectID != song || revision != 1 {
		t.Fatalf("find failed: %v", err)
	}
	duplicate := Entry{ParentID: sub, ObjectID: strings.Repeat("e", 64), Kind: "audio", Name: "晴天.mp3"}
	if err := s.CreateFile(ctx, duplicate, fixturePlacement(t, duplicate.ObjectID)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate sibling accepted: %v", err)
	}
	if _, err = s.Move(ctx, dir, sub, "cycle", 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("directory cycle accepted: %v", err)
	}
	if _, err = s.Move(ctx, sub, s.rootID, "迁出", 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision accepted: %v", err)
	}
	if next, err := s.Move(ctx, sub, s.rootID, "迁出", 1); err != nil || next != 2 {
		t.Fatalf("move failed: %v", err)
	}
	got, revision, err = s.Get(ctx, song)
	if err != nil || got.ParentID != sub || got.Name != "晴天.mp3" || revision != 1 {
		t.Fatalf("descendant identity changed: %v", err)
	}
	placement, err := s.GetPlacement(ctx, song)
	if err != nil || placement.ObjectID != song || placement.BlobID == song || placement.Bytes != 7 {
		t.Fatalf("directory move changed opaque placement: %v", err)
	}
	if count, err := s.Check(ctx); err != nil || count != 3 {
		t.Fatalf("tree check failed: %d %v", count, err)
	}
	var nonces int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&nonces); err != nil || nonces != 6 {
		t.Fatalf("record key history not retained: %d %v", nonces, err)
	}
}

func TestSQLiteFilePlacementIsAtomicAndNeverReusesBlob(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	first := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "first.mp3"}
	placement := fixturePlacement(t, first.ObjectID)
	if err := s.Create(ctx, first); !errors.Is(err, ErrInvalid) {
		t.Fatal("file without placement accepted")
	}
	if err := s.CreateFile(ctx, first, placement); err != nil {
		t.Fatal(err)
	}
	second := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "second.mp3"}
	duplicate := placement
	duplicate.ObjectID = second.ObjectID
	duplicate.NativeObjectID = second.ObjectID
	if err := s.CreateFile(ctx, second, duplicate); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate physical blob accepted")
	}
	if _, _, err := s.Get(ctx, second.ObjectID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("failed placement left a logical entry")
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_placement BEFORE INSERT ON sealed_tree_placements BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFile(ctx, second, fixturePlacement(t, second.ObjectID)); err == nil {
		t.Fatal("injected placement failure accepted")
	}
	if _, _, err := s.Get(ctx, second.ObjectID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("failed placement transaction left an entry")
	}
	var names, placements, salts, blobs int
	if err := db.QueryRow(`SELECT (SELECT COUNT(*) FROM sealed_tree_records),(SELECT COUNT(*) FROM sealed_tree_placements),(SELECT COUNT(*) FROM sealed_tree_encryption_ids),(SELECT COUNT(*) FROM sealed_tree_blob_ids)`).Scan(&names, &placements, &salts, &blobs); err != nil || names != 1 || placements != 1 || salts != 3 || blobs != 2 {
		t.Fatalf("partial operation persisted: %d %d %d %d %v", names, placements, salts, blobs, err)
	}
	if count, err := s.Check(ctx); err != nil || count != 1 {
		t.Fatalf("original placement lost: %d %v", count, err)
	}
}

func TestSQLiteIntegrityDetectsAuthenticatedParentCycle(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	a, b := strings.Repeat("b", 64), strings.Repeat("c", 64)
	if err := s.Create(ctx, Entry{ParentID: s.rootID, ObjectID: a, Kind: "directory", Name: "A"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, Entry{ParentID: a, ObjectID: b, Kind: "directory", Name: "B"}); err != nil {
		t.Fatal(err)
	}
	// Simulate a faulty trusted importer writing a validly encrypted but cyclic
	// record. Check must reject even though ciphertext authentication succeeds.
	forged, err := s.tree.Seal(b, a, "directory", "A", 2)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := EncryptionID(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sealed_tree_encryption_ids(encryption_id) VALUES(?)`, salt); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sealed_tree_records SET parent_index=?,lookup_tag=?,revision=?,encryption_id=?,sealed=? WHERE object_index=?`, forged.ParentIndex, forged.Lookup, forged.Revision, salt, forged.Sealed, forged.ObjectIndex); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Check(ctx); !errors.Is(err, ErrConflict) {
		t.Fatalf("authenticated cycle accepted: %v", err)
	}
}

func TestOpaqueReadAliasReservationsRejectCrossObjectReuse(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	first := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "first"}
	placement := fixturePlacement(t, first.ObjectID)
	if err := s.CreateFile(ctx, first, placement); err != nil {
		t.Fatal(err)
	}
	second := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "second"}
	for _, collision := range []string{placement.ReadAlias, placement.BlobID} {
		candidate := fixturePlacement(t, second.ObjectID)
		candidate.ReadAlias = collision
		if err := s.CreateFile(ctx, second, candidate); !errors.Is(err, ErrConflict) {
			t.Fatal("alias reuse was accepted", err)
		}
	}
	candidate := fixturePlacement(t, second.ObjectID)
	candidate.BlobID = placement.ReadAlias
	if err := s.CreateFile(ctx, second, candidate); !errors.Is(err, ErrConflict) {
		t.Fatal("alias reused as blob", err)
	}
	orphan := strings.Repeat("d", 64)
	if _, err := db.Exec(`INSERT INTO sealed_tree_aliases(alias_index,object_index) VALUES(?,?)`, orphan, strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Check(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatal("orphan alias mapping was accepted", err)
	}
	if _, err := db.Exec(`DELETE FROM sealed_tree_aliases WHERE alias_index=?`, orphan); err != nil {
		t.Fatal(err)
	}
	index, err := s.tree.BlobIndex(placement.ReadAlias)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM sealed_tree_blob_ids WHERE blob_index=?`, index); err != nil {
		t.Fatal(err)
	}
	if _, err = s.GetPlacement(ctx, first.ObjectID); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing alias reservation was accepted", err)
	}
}

func TestPendingReadAliasReservationIsDurableAndAuthenticated(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	first := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "first"}
	placement := fixturePlacement(t, first.ObjectID)
	if _, err := s.PrepareFileWithFacts(ctx, first, placement, Facts{ObjectID: first.ObjectID}); err != nil {
		t.Fatal(err)
	}
	second := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "second"}
	candidate := fixturePlacement(t, second.ObjectID)
	candidate.ReadAlias = placement.ReadAlias
	if _, err := s.PrepareFileWithFacts(ctx, second, candidate, Facts{ObjectID: second.ObjectID}); !errors.Is(err, ErrConflict) {
		t.Fatal("pending alias was reused", err)
	}
	index, err := s.tree.BlobIndex(placement.ReadAlias)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM sealed_tree_blob_ids WHERE blob_index=?`, index); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Check(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatal("pending alias reservation loss was accepted", err)
	}
}

func TestSQLiteNeverPersistsNamesOrRawIDs(t *testing.T) {
	ctx := context.Background()
	_, s, filename := sqliteFixture(t)
	dir, file := strings.Repeat("b", 64), strings.Repeat("c", 64)
	if err := s.Create(ctx, Entry{ParentID: s.rootID, ObjectID: dir, Kind: "directory", Name: "隐藏专辑秘密名字"}); err != nil {
		t.Fatal(err)
	}
	placement := fixturePlacement(t, file)
	if err := s.CreateFile(ctx, Entry{ParentID: dir, ObjectID: file, Kind: "audio", Name: "独特曲名.private.mp3"}, placement); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Move(ctx, file, dir, "新的私密曲名.mp3", 1); err != nil {
		t.Fatal(err)
	}
	pendingID := strings.Repeat("d", 64)
	pending := fixturePlacement(t, pendingID)
	if _, err := s.PrepareFile(ctx, Entry{ParentID: dir, ObjectID: pendingID, Kind: "audio", Name: "未完成歌曲.private.mp3"}, pending); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(filename + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"隐藏专辑秘密名字", "独特曲名.private.mp3", "新的私密曲名.mp3", "未完成歌曲.private.mp3", s.rootID, dir, file, pendingID, placement.OwnerID, placement.BlobID, placement.SHA256, pending.BlobID} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatalf("plaintext identity or name persisted in %s", suffix)
			}
		}
	}
}

func TestSQLiteFailsClosedAndRollsBack(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	if _, err := InitializeSQLite(ctx, db, fixture(t), s.rootID); !errors.Is(err, ErrConflict) {
		t.Fatal("existing database accepted as empty")
	}
	wrong, err := New(bytes.Repeat([]byte{0x43}, 32), bytes.Repeat([]byte{0x91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(ctx, db, wrong, s.rootID); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong key accepted")
	}
	if _, err := OpenSQLite(ctx, db, fixture(t), strings.Repeat("d", 64)); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong root accepted")
	}
	recovered, err := OpenSQLiteWithMaster(ctx, db, bytes.Repeat([]byte{0x42}, 32))
	if err != nil || recovered.rootID != s.rootID {
		t.Fatal("namespace root was not recovered automatically")
	}
	if _, err := OpenSQLiteWithMaster(ctx, db, bytes.Repeat([]byte{0x43}, 32)); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong master recovered namespace root")
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_tree BEFORE INSERT ON sealed_tree_records BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	failure := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "回滚.mp3"}
	err = s.CreateFile(ctx, failure, fixturePlacement(t, failure.ObjectID))
	if err == nil {
		t.Fatal("injected failure accepted")
	}
	var fence, reservations, records int
	if err := db.QueryRow(`SELECT write_fence FROM sealed_tree_meta`).Scan(&fence); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_records`).Scan(&records); err != nil || fence != 0 || reservations != 1 || records != 0 {
		t.Fatalf("transaction left partial state: %d %d %d %v", fence, reservations, records, err)
	}
}

func TestSQLiteConcurrentWritersSerialize(t *testing.T) {
	ctx := context.Background()
	_, s, _ := sqliteFixture(t)
	const total = 12
	var wg sync.WaitGroup
	errs := make(chan error, total)
	for i := range total {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			entry := Entry{ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", i+1), Kind: "audio", Name: fmt.Sprintf("track-%d.mp3", i)}
			blobID, err := NewBlobID()
			if err != nil {
				errs <- err
				return
			}
			alias, err := NewBlobID()
			if err != nil {
				errs <- err
				return
			}
			errs <- s.CreateFile(ctx, entry, Placement{ObjectID: entry.ObjectID, NativeObjectID: entry.ObjectID, OwnerID: strings.Repeat("f", 32), BlobID: blobID, ReadAlias: alias, Bytes: 7, SHA256: strings.Repeat("9", 64)})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent writer failed: %v", err)
		}
	}
	if count, err := s.Check(ctx); err != nil || count != total {
		t.Fatalf("concurrent writes lost: %d %v", count, err)
	}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		entries, next, err := s.List(ctx, s.rootID, cursor, 5)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if seen[entry.ObjectID] {
				t.Fatal("duplicate object across pages")
			}
			seen[entry.ObjectID] = true
		}
		if next == "" {
			break
		}
		if next == cursor {
			t.Fatal("pagination did not advance")
		}
		cursor = next
	}
	if len(seen) != total {
		t.Fatalf("paged enumeration lost objects: %d", len(seen))
	}
	if _, _, err := s.List(ctx, s.rootID, "invalid", 5); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid cursor accepted")
	}
}

func TestSQLiteDetectsEncryptionIdentityMismatch(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	id := strings.Repeat("b", 64)
	if err := s.CreateFile(ctx, Entry{ParentID: s.rootID, ObjectID: id, Kind: "audio", Name: "name.mp3"}, fixturePlacement(t, id)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sealed_tree_records SET encryption_id=?`, strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, id); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched encryption identity accepted: %v", err)
	}
	if _, err := s.Check(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatalf("integrity check missed mismatch: %v", err)
	}
}

func TestSQLiteRootCorruptionFailsClosedWithoutRegeneration(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	var original []byte
	if err := db.QueryRow(`SELECT root_sealed FROM sealed_tree_meta WHERE singleton=1`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), original...)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := db.Exec(`UPDATE sealed_tree_meta SET root_sealed=? WHERE singleton=1`, corrupt); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLiteWithMaster(ctx, db, bytes.Repeat([]byte{0x42}, 32)); !errors.Is(err, ErrInvalid) {
		t.Fatal("corrupt root reopened")
	}
	if _, err := s.Check(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatal("live store ignored corrupt root")
	}
	if err := s.Create(ctx, Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "not-published"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("corrupt root admitted a write")
	}
	var fence int
	if err := db.QueryRow(`SELECT write_fence FROM sealed_tree_meta`).Scan(&fence); err != nil || fence != 0 {
		t.Fatal("failed write did not roll back fence")
	}
	if _, err := db.Exec(`UPDATE sealed_tree_meta SET root_sealed=? WHERE singleton=1`, original); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLiteWithMaster(ctx, db, bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatal("authenticated original root could not be restored")
	}
}

func TestSQLiteCrashRollsBackUncommittedWrite(t *testing.T) {
	if os.Getenv("FC_SEALED_TREE_CRASH_CHILD") == "1" {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(os.Getenv("FC_SEALED_TREE_FIXTURE_DB"))+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
		if err != nil {
			os.Exit(81)
		}
		tree, err := New(bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x91}, 32))
		if err != nil {
			os.Exit(82)
		}
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil || lockWriter(context.Background(), tx) != nil {
			os.Exit(83)
		}
		record, err := tree.Seal(strings.Repeat("a", 64), strings.Repeat("e", 64), "audio", "crash-name.mp3", 1)
		if err != nil {
			os.Exit(84)
		}
		id, err := reserveEncryptionID(context.Background(), tx, record)
		if err != nil {
			os.Exit(85)
		}
		if _, err = tx.Exec(`INSERT INTO sealed_tree_records(object_index,parent_index,lookup_tag,revision,encryption_id,sealed) VALUES(?,?,?,?,?,?)`, record.ObjectIndex, record.ParentIndex, record.Lookup, record.Revision, id, record.Sealed); err != nil {
			os.Exit(86)
		}
		os.Exit(91) // Simulated process death, before Commit or deferred rollback.
	}
	db, s, filename := sqliteFixture(t)
	ctx := context.Background()
	committed := strings.Repeat("b", 64)
	if err := s.CreateFile(ctx, Entry{ParentID: s.rootID, ObjectID: committed, Kind: "audio", Name: "安全.mp3"}, fixturePlacement(t, committed)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSQLiteCrashRollsBackUncommittedWrite$")
	cmd.Env = append(os.Environ(), "FC_SEALED_TREE_CRASH_CHILD=1", "FC_SEALED_TREE_FIXTURE_DB="+filename)
	if err := cmd.Run(); err == nil {
		t.Fatal("child unexpectedly succeeded")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 91 {
		t.Fatalf("child failed before simulated crash: %v", err)
	}
	reopened, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filename)+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	resumed, err := OpenSQLite(ctx, reopened, fixture(t), s.rootID)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := resumed.Check(ctx); err != nil || count != 1 {
		t.Fatalf("crash recovery mismatch: %d %v", count, err)
	}
	if _, _, err := resumed.Get(ctx, committed); err != nil {
		t.Fatal("committed record lost after crash")
	}
	if _, _, err := resumed.Get(ctx, strings.Repeat("e", 64)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("uncommitted record survived: %v", err)
	}
	var integrity string
	if err := reopened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("SQLite integrity failed: %s %v", integrity, err)
	}
}
