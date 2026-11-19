package preprodimport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func testID(c string, n int) string { return strings.Repeat(c, n) }
func testOptions() Options {
	return Options{MaxBytesPerSecond: 4 * 1024 * 1024, Progress: func(Event) error { return nil }}
}
func digest(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func fixture(t *testing.T) (Snapshot, []byte, string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("private ACL ownership not implemented; importer must fail closed")
	}
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	out := filepath.Join(root, "out")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"master", "direct", "relay"} {
		if err := os.MkdirAll(filepath.Join(stage, role, "objects"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(stage, role, "partial"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := []byte(strings.Repeat("k", 32))
	manager, err := mediacrypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(16)
	if err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Version: 1, SourceProjectionSHA256: testID("f", 64), PremasterKeyID: manager.KeyID(),
		DeclaredSections:  []string{"media", "lyrics", "directories", "links", "visibility", "preferences", "encryption_nonces"},
		Mappings:          []Mapping{{testID("1", 32), testID("4", 32), "master", 1000}, {testID("2", 32), testID("5", 32), "direct", 1000}, {testID("3", 32), testID("6", 32), "relay", 1000}},
		ExcludedSourceIDs: []string{testID("7", 32)},
		Media:             []Media{{MediaID: testID("a", 64), ObjectID: testID("b", 64), SourceID: testID("1", 32), Path: "music/album/song.mp3", Kind: "audio", Size: meta.CiphertextSize, SHA256: digest(bytes.Repeat([]byte("c"), int(meta.CiphertextSize))), Encryption: &meta}, {MediaID: testID("c", 64), ObjectID: testID("d", 64), SourceID: testID("2", 32), Path: "vido/category/movie.mp4", Kind: "video", Size: 5, SHA256: digest([]byte("video"))}},
		Lyrics:            []Lyric{{ID: testID("e", 64), Path: "lyrics/a/song.lrc", Size: 5, SHA256: digest([]byte("lyric"))}},
		Directories:       []Directory{{ID: testID("0", 64), Path: "music/album"}},
		Links:             []Link{{MediaID: testID("a", 64), LyricID: testID("e", 64)}},
		Visibility:        []Visibility{{Path: "music/album", Hidden: true}, {Path: "music/currently-empty", Hidden: true}},
		Preferences:       []Preference{{ID: testID("0", 64), Value: 11, PlayScore: 2}},
		RetiredNonces:     []NonceTombstone{{ObjectID: testID("8", 64), FileID: testID("9", 32)}},
	}
	for _, v := range []struct {
		role, id string
		data     []byte
	}{{"master", testID("b", 64), bytes.Repeat([]byte("c"), int(meta.CiphertextSize))}, {"direct", testID("d", 64), []byte("video")}, {"master", testID("e", 64), []byte("lyric")}} {
		if err := os.WriteFile(filepath.Join(stage, v.role, "objects", v.id+".blob"), v.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return s, key, stage, out
}
func TestPrepareMediaOnlyProjectionPreservesIDsAndSeparateOwners(t *testing.T) {
	s, key, stage, out := fixture(t)
	r, err := preparePlaintextFixture(context.Background(), s, key, stage, out, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if r.MediaCount != 2 || r.LyricCount != 1 || r.LinkCount != 1 || r.SourceAuthenticated || r.SnapshotConsistent || r.RuntimeReady || r.ScratchDirectory != "" {
		t.Fatalf("incorrect claim: %+v", r)
	}
	db, err := sql.Open("sqlite", filepath.Join(out, "media-only-projection.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var target, role string
	if err = db.QueryRow("SELECT target_id,role FROM media WHERE media_id=?", testID("c", 64)).Scan(&target, &role); err != nil || target != testID("5", 32) || role != "direct" {
		t.Fatalf("owner mapping: %s %s %v", target, role, err)
	}
	var lyric string
	if err = db.QueryRow("SELECT lyric_id FROM lyric_link WHERE media_id=?", testID("a", 64)).Scan(&lyric); err != nil || lyric != testID("e", 64) {
		t.Fatalf("lyric binding: %q %v", lyric, err)
	}
	var hidden bool
	if err = db.QueryRow("SELECT hidden FROM visibility WHERE path=?", "music/album").Scan(&hidden); err != nil || !hidden {
		t.Fatalf("hidden rule missing: %v %v", hidden, err)
	}
	if err = db.QueryRow("SELECT hidden FROM visibility WHERE path=?", "music/currently-empty").Scan(&hidden); err != nil || !hidden {
		t.Fatalf("empty-folder hidden rule missing: %v %v", hidden, err)
	}
	var pref int
	if err = db.QueryRow("SELECT value FROM preference WHERE id=?", testID("0", 64)).Scan(&pref); err != nil || pref != 11 {
		t.Fatalf("directory priority missing: %d %v", pref, err)
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('node_identity','node_relationships','users','sessions','global_media_objects')").Scan(&count); err != nil || count != 0 {
		t.Fatalf("projection contains runnable or sensitive schema: %d %v", count, err)
	}
	if _, err = preparePlaintextFixture(context.Background(), s, key, stage, out, testOptions()); err != nil {
		t.Fatalf("identical retry failed: %v", err)
	}
	if _, err = db.Exec("UPDATE media SET path='music/changed/song.mp3' WHERE media_id=?", testID("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err = preparePlaintextFixture(context.Background(), s, key, stage, out, testOptions()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("modified projection accepted: %v", err)
	}
}

func TestSnapshotShapeCanBeCheckedWithoutProductionPremaster(t *testing.T) {
	s, key, _, _ := fixture(t)
	owners, report, err := validateSnapshotShape(s)
	if err != nil || len(owners) != 3 || report.MediaCount != 2 || report.LyricCount != 1 || report.SourceAuthenticated || report.SnapshotConsistent || report.RuntimeReady {
		t.Fatalf("structural check changed trust state: %+v %v", report, err)
	}
	if _, _, err = validate(s, bytes.Repeat([]byte("z"), 32)); err == nil {
		t.Fatal("source-side legacy key proof accepted wrong premaster")
	}
	if _, _, err = validate(s, key); err != nil {
		t.Fatal(err)
	}
	bad := s
	bad.PremasterKeyID = "invalid"
	if _, _, err = validateSnapshotShape(bad); err == nil {
		t.Fatal("invalid key identity accepted")
	}
	bad = s
	bad.Links = []Link{{MediaID: s.Media[1].MediaID, LyricID: s.Lyrics[0].ID}}
	if _, _, err = validateSnapshotShape(bad); err == nil {
		t.Fatal("invalid media/lyric relation accepted")
	}
	bad = s
	bad.RetiredNonces = append([]NonceTombstone(nil), s.RetiredNonces...)
	bad.RetiredNonces[0].ObjectID = s.Directories[0].ID
	if _, _, err = validateSnapshotShape(bad); err == nil {
		t.Fatal("live directory also accepted as tombstone")
	}
	if _, _, err = validate(bad, key); err == nil {
		t.Fatal("source validation accepted directory tombstone conflict")
	}
}

func TestSnapshotShapeAcceptsEmptyMediaAndLyricsOnlyWithCanonicalDigest(t *testing.T) {
	s, _, _, _ := fixture(t)
	media := s
	media.Media = append([]Media(nil), s.Media...)
	media.Media[1].Size = 0
	media.Media[1].SHA256 = digest(nil)
	if _, _, err := validateSnapshotShape(media); err != nil {
		t.Fatal("empty media rejected", err)
	}
	media.Media[1].SHA256 = testID("a", 64)
	if _, _, err := validateSnapshotShape(media); err == nil {
		t.Fatal("empty media with wrong digest accepted")
	}
	lyric := s
	lyric.Lyrics = append([]Lyric(nil), s.Lyrics...)
	lyric.Lyrics[0].Size = 0
	lyric.Lyrics[0].SHA256 = digest(nil)
	if _, _, err := validateSnapshotShape(lyric); err != nil {
		t.Fatal("empty lyric rejected", err)
	}
	lyric.Lyrics[0].SHA256 = testID("a", 64)
	if _, _, err := validateSnapshotShape(lyric); err == nil {
		t.Fatal("empty lyric with wrong digest accepted")
	}
}

func TestSyntheticProjectionPreservesEmptyMediaAndLyrics(t *testing.T) {
	s, key, stage, out := fixture(t)
	s.Media[1].Size, s.Media[1].SHA256 = 0, digest(nil)
	s.Lyrics[0].Size, s.Lyrics[0].SHA256 = 0, digest(nil)
	for _, p := range []string{filepath.Join(stage, "direct", "objects", s.Media[1].ObjectID+".blob"), filepath.Join(stage, "master", "objects", s.Lyrics[0].ID+".blob")} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := preparePlaintextFixture(context.Background(), s, key, stage, out, testOptions())
	if err != nil || report.RuntimeReady {
		t.Fatalf("empty synthetic projection: %+v %v", report, err)
	}
	db, err := sql.Open("sqlite", filepath.Join(out, "media-only-projection.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, table := range []string{"media", "lyric"} {
		var size int64
		var sha string
		if err := db.QueryRow("SELECT size,sha256 FROM "+table+" WHERE size=0").Scan(&size, &sha); err != nil || size != 0 || sha != digest(nil) {
			t.Fatalf("empty %s projection: size=%d err=%v", table, size, err)
		}
	}
	var links int
	if err := db.QueryRow("SELECT count(*) FROM lyric_link").Scan(&links); err != nil || links != 1 {
		t.Fatalf("lyric relationship: %d %v", links, err)
	}
}
func TestRejectCorruptionAndRetryWithoutOverwrite(t *testing.T) {
	s, key, stage, out := fixture(t)
	p := filepath.Join(stage, "direct", "objects", testID("d", 64)+".blob")
	if err := os.WriteFile(p, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := preparePlaintextFixture(context.Background(), s, key, stage, out, testOptions()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad bytes accepted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(out, "media-only-projection.sqlite")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failure published output", err)
	}
	if err := os.WriteFile(p, []byte("video"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := preparePlaintextFixture(context.Background(), s, key, stage, out, testOptions()); err != nil {
		t.Fatal("retry failed", err)
	}
}
func TestRejectUnsafeSnapshotFacts(t *testing.T) {
	for _, name := range []string{"wrong key", "source target alias", "excluded owner", "missing lyric", "video lyric link", "duplicate id", "bad path", "capacity", "bad digest", "duplicate file id", "tombstone active object", "missing section", "unknown visibility", "bad preference", "cancel"} {
		t.Run(name, func(t *testing.T) {
			s, key, stage, out := fixture(t)
			ctx := context.Background()
			switch name {
			case "wrong key":
				key = []byte(strings.Repeat("x", 32))
			case "source target alias":
				s.Mappings[0].TargetID = s.Mappings[1].SourceID
			case "excluded owner":
				s.Media[0].SourceID = s.ExcludedSourceIDs[0]
			case "missing lyric":
				s.Links[0].LyricID = testID("0", 64)
			case "video lyric link":
				s.Links[0].MediaID = s.Media[1].MediaID
			case "duplicate id":
				s.Media[1].MediaID = s.Media[0].MediaID
			case "bad path":
				s.Media[0].Path = "music/../escape.mp3"
			case "capacity":
				s.Mappings[0].Capacity = 1
			case "bad digest":
				s.Media[0].SHA256 = testID("0", 64)
			case "duplicate file id":
				s.RetiredNonces[0].FileID = s.Media[0].Encryption.FileID
			case "tombstone active object":
				s.RetiredNonces[0].ObjectID = s.Media[0].MediaID
			case "missing section":
				s.DeclaredSections = s.DeclaredSections[1:]
			case "unknown visibility":
				s.Visibility[0].Path = "music/../escape"
			case "bad preference":
				s.Preferences[0].Value = 500001
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := preparePlaintextFixture(ctx, s, key, stage, out, testOptions()); err == nil {
				t.Fatal("unsafe input accepted")
			}
			if _, err := os.Lstat(filepath.Join(out, "media-only-projection.sqlite")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe output published")
			}
		})
	}
}
func TestDecodeRejectsUnknownSensitiveFieldsAndTrailingData(t *testing.T) {
	for _, input := range []string{`{"version":1,"users":[{"password":"secret"}]}`, `{"version":1,"sessions":[]}`, `{"version":1,"node_identity":{"private_key":"secret"}}`, `{"version":1} {}`} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatal("unexpected field or trailing data accepted")
		}
	}
}
func TestPrepareRejectsStagingSymlink(t *testing.T) {
	s, key, stage, out := fixture(t)
	f := filepath.Join(stage, "direct", "objects", testID("d", 64)+".blob")
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(stage, "master", "objects", testID("e", 64)+".blob"), f); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := preparePlaintextFixture(context.Background(), s, key, stage, out, testOptions()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted symlink: %v", err)
	}
}

func TestProgressFailureLeavesRecoverableProjection(t *testing.T) {
	s, key, stage, out := fixture(t)
	sentinel := errors.New("journal unavailable")
	opts := testOptions()
	opts.Progress = func(event Event) error {
		if event.Kind == "projection_prepared" {
			return sentinel
		}
		return nil
	}
	r, err := preparePlaintextFixture(context.Background(), s, key, stage, out, opts)
	if !errors.Is(err, sentinel) || r.ScratchDirectory == "" {
		t.Fatalf("prepared failure not recorded: %+v %v", r, err)
	}
	if _, err = os.Lstat(filepath.Join(out, "media-only-projection.sqlite")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published after failed journal")
	}
	if _, err = preparePlaintextFixture(context.Background(), s, key, stage, out, testOptions()); err != nil {
		t.Fatal("retry failed", err)
	}
}

func TestPublishedJournalFailureIsIdempotentlyReconciled(t *testing.T) {
	s, key, stage, out := fixture(t)
	sentinel := errors.New("journal unavailable")
	opts := testOptions()
	opts.Progress = func(event Event) error {
		if event.Kind == "projection_published" {
			return sentinel
		}
		return nil
	}
	if _, err := preparePlaintextFixture(context.Background(), s, key, stage, out, opts); !errors.Is(err, sentinel) {
		t.Fatalf("expected journal failure: %v", err)
	}
	seen := false
	opts.Progress = func(event Event) error {
		if event.Kind == "projection_already_verified" {
			seen = true
		}
		return nil
	}
	if _, err := preparePlaintextFixture(context.Background(), s, key, stage, out, opts); err != nil || !seen {
		t.Fatalf("failed to reconcile already published projection: %v", err)
	}
}

func TestRateLimitHonorsCancellation(t *testing.T) {
	s, key, stage, out := fixture(t)
	opts := testOptions()
	opts.MaxBytesPerSecond = 1
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := preparePlaintextFixture(ctx, s, key, stage, out, opts); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("throttle ignored cancellation: %v", err)
	}
}

func TestBuiltinAndEncryptedLyricAreExplicit(t *testing.T) {
	for _, kind := range []string{"builtin", "encrypted"} {
		t.Run(kind, func(t *testing.T) {
			s, key, stage, out := fixture(t)
			l := &s.Lyrics[0]
			p := filepath.Join(stage, "master", "objects", l.ID+".blob")
			if kind == "builtin" {
				data := []byte("[00:00.00]建设中，暂无歌词\n")
				l.Path = "lyrics/default.lrc"
				l.Builtin = true
				l.Size = int64(len(data))
				l.SHA256 = digest(data)
				if err := os.WriteFile(p, data, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				m, err := mediacrypto.NewMetadata(16)
				if err != nil {
					t.Fatal(err)
				}
				data := bytes.Repeat([]byte("z"), int(m.CiphertextSize))
				l.Size = m.CiphertextSize
				l.SHA256 = digest(data)
				l.Encryption = &m
				if err = os.WriteFile(p, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := preparePlaintextFixture(context.Background(), s, key, stage, out, testOptions()); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", filepath.Join(out, "media-only-projection.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var builtin bool
			var enc sql.NullString
			if err = db.QueryRow("SELECT builtin,encryption_json FROM lyric WHERE id=?", l.ID).Scan(&builtin, &enc); err != nil {
				t.Fatal(err)
			}
			if builtin != (kind == "builtin") || enc.Valid != (kind == "encrypted") {
				t.Fatalf("lyric treatment lost: builtin=%v enc=%v", builtin, enc.Valid)
			}
		})
	}
}

func TestUnsafeRuntimePathsRejected(t *testing.T) {
	for _, path := range []string{"music/file.mp3", "music/a/b/c/file.mp3", "music/a/no-format.txt", "music/a:bad/song.mp3"} {
		s, key, stage, out := fixture(t)
		s.Media[0].Path = path
		if _, err := preparePlaintextFixture(context.Background(), s, key, stage, out, testOptions()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %q: %v", path, err)
		}
	}
}

func TestPublicPrepareFailsClosedBeforeFilesystemAccess(t *testing.T) {
	dir := t.TempDir()
	stage := filepath.Join(dir, "must-not-create-stage")
	out := filepath.Join(dir, "must-not-create-output")
	if _, err := Prepare(context.Background(), Snapshot{}, nil, stage, out, Options{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected closed encrypted-tree gate, got %v", err)
	}
	for _, p := range []string{stage, out} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("public entry touched %q: %v", p, err)
		}
	}
}
