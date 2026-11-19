package preprodimport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	_ "modernc.org/sqlite"
)

const projectionDDL = `
CREATE TABLE projection_meta(version INTEGER NOT NULL, projection_sha256 TEXT NOT NULL, source_projection_sha256 TEXT NOT NULL, premaster_key_id TEXT NOT NULL, source_authenticated INTEGER NOT NULL CHECK(source_authenticated=0), snapshot_consistent INTEGER NOT NULL CHECK(snapshot_consistent=0), runtime_ready INTEGER NOT NULL CHECK(runtime_ready=0));
CREATE TABLE owner_mapping(source_id TEXT PRIMARY KEY,target_id TEXT NOT NULL UNIQUE,role TEXT NOT NULL UNIQUE,capacity INTEGER NOT NULL);
CREATE TABLE excluded_source(source_id TEXT PRIMARY KEY);
CREATE TABLE media(media_id TEXT PRIMARY KEY,object_id TEXT NOT NULL,source_id TEXT NOT NULL,target_id TEXT NOT NULL,role TEXT NOT NULL,path TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,size INTEGER NOT NULL,sha256 TEXT NOT NULL,encryption_json TEXT,UNIQUE(source_id,object_id));
CREATE TABLE lyric(id TEXT PRIMARY KEY,path TEXT NOT NULL UNIQUE,size INTEGER NOT NULL,sha256 TEXT NOT NULL,builtin INTEGER NOT NULL,encryption_json TEXT);
CREATE TABLE directory(id TEXT PRIMARY KEY,path TEXT NOT NULL UNIQUE);
CREATE TABLE lyric_link(media_id TEXT PRIMARY KEY,lyric_id TEXT NOT NULL);
CREATE TABLE visibility(path TEXT PRIMARY KEY,hidden INTEGER NOT NULL);
CREATE TABLE preference(id TEXT PRIMARY KEY,value INTEGER NOT NULL,play_score INTEGER NOT NULL);
CREATE TABLE retired_nonce(object_id TEXT PRIMARY KEY,file_id TEXT NOT NULL UNIQUE);
`

// preparePlaintextFixture is only exercised with synthetic fixtures. It is not
// an importer or a security boundary, and must never receive real metadata.
func preparePlaintextFixture(ctx context.Context, s Snapshot, premaster []byte, stageDir, parentDir string, opts Options) (report Report, err error) {
	owners, report, err := validate(s, premaster)
	if err != nil {
		return report, err
	}
	if opts.Progress == nil || opts.MaxBytesPerSecond <= 0 || opts.MaxBytesPerSecond > 4*1024*1024 {
		return report, invalid("progress journal or rate limit")
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = opts.Progress(Event{Kind: "verification_started"}); err != nil {
		return report, err
	}
	limit := &limiter{start: time.Now(), rate: opts.MaxBytesPerSecond}
	stageInfo, err := os.Lstat(stageDir)
	if err != nil || !privateOwned(stageInfo, true) {
		return report, invalid("stage directory")
	}
	stage, err := os.OpenRoot(stageDir)
	if err != nil {
		return report, err
	}
	defer stage.Close()
	opened, err := stage.Stat(".")
	if err != nil || !os.SameFile(stageInfo, opened) {
		return report, invalid("stage root changed")
	}
	for _, m := range s.Media {
		role := owners[m.SourceID].Role
		if err = verifyFile(ctx, stage, role, m.ObjectID, m.Size, m.SHA256, limit); err != nil {
			return report, err
		}
		if err = opts.Progress(Event{Kind: "object_verified", Role: role, ObjectID: m.ObjectID, Bytes: m.Size}); err != nil {
			return report, err
		}
	}
	for _, l := range s.Lyrics {
		if err = verifyFile(ctx, stage, "master", l.ID, l.Size, l.SHA256, limit); err != nil {
			return report, err
		}
		if err = opts.Progress(Event{Kind: "object_verified", Role: "master", ObjectID: l.ID, Bytes: l.Size}); err != nil {
			return report, err
		}
	}
	parent, err := os.Lstat(parentDir)
	if err != nil || !privateOwned(parent, true) {
		return report, invalid("private output parent")
	}
	final := filepath.Join(parentDir, "media-only-projection.sqlite")
	if _, err = os.Lstat(final); err == nil {
		if err = checkExisting(ctx, final, s, owners, report); err != nil {
			return report, err
		}
		if err = opts.Progress(Event{Kind: "projection_already_verified"}); err != nil {
			return report, err
		}
		return report, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return report, invalid("output cannot be checked")
	}
	scratch, err := os.MkdirTemp(parentDir, ".fc-media-projection-")
	if err != nil {
		return report, err
	}
	report.ScratchDirectory = scratch
	dbpath := filepath.Join(scratch, "projection.sqlite")
	f, err := os.OpenFile(dbpath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return report, err
	}
	if err = f.Close(); err != nil {
		return report, err
	}
	db, err := sql.Open("sqlite", dbpath)
	if err != nil {
		return report, err
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, db.Close())
		}
	}()
	if _, err = db.ExecContext(ctx, "PRAGMA journal_mode=DELETE"); err != nil {
		return report, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, projectionDDL); err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO projection_meta VALUES (1,?,?,?,0,0,0)", report.ProjectionSHA256, s.SourceProjectionSHA256, s.PremasterKeyID); err != nil {
		return report, err
	}
	for _, m := range s.Mappings {
		if _, err = tx.ExecContext(ctx, "INSERT INTO owner_mapping VALUES (?,?,?,?)", m.SourceID, m.TargetID, m.Role, m.Capacity); err != nil {
			return report, err
		}
	}
	for _, id := range s.ExcludedSourceIDs {
		if _, err = tx.ExecContext(ctx, "INSERT INTO excluded_source VALUES (?)", id); err != nil {
			return report, err
		}
	}
	for _, m := range s.Media {
		var enc any
		if m.Encryption != nil {
			var raw []byte
			raw, err = json.Marshal(m.Encryption)
			if err != nil {
				return report, err
			}
			enc = string(raw)
		}
		dest := owners[m.SourceID]
		if _, err = tx.ExecContext(ctx, "INSERT INTO media VALUES (?,?,?,?,?,?,?,?,?,?)", m.MediaID, m.ObjectID, m.SourceID, dest.TargetID, dest.Role, m.Path, m.Kind, m.Size, m.SHA256, enc); err != nil {
			return report, err
		}
	}
	for _, l := range s.Lyrics {
		var enc any
		if l.Encryption != nil {
			raw, marshalErr := json.Marshal(l.Encryption)
			if marshalErr != nil {
				return report, marshalErr
			}
			enc = string(raw)
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO lyric VALUES (?,?,?,?,?,?)", l.ID, l.Path, l.Size, l.SHA256, l.Builtin, enc); err != nil {
			return report, err
		}
	}
	for _, d := range s.Directories {
		if _, err = tx.ExecContext(ctx, "INSERT INTO directory VALUES (?,?)", d.ID, d.Path); err != nil {
			return report, err
		}
	}
	for _, l := range s.Links {
		if _, err = tx.ExecContext(ctx, "INSERT INTO lyric_link VALUES (?,?)", l.MediaID, l.LyricID); err != nil {
			return report, err
		}
	}
	for _, v := range s.Visibility {
		if _, err = tx.ExecContext(ctx, "INSERT INTO visibility VALUES (?,?)", v.Path, v.Hidden); err != nil {
			return report, err
		}
	}
	for _, p := range s.Preferences {
		if _, err = tx.ExecContext(ctx, "INSERT INTO preference VALUES (?,?,?)", p.ID, p.Value, p.PlayScore); err != nil {
			return report, err
		}
	}
	for _, n := range s.RetiredNonces {
		if _, err = tx.ExecContext(ctx, "INSERT INTO retired_nonce VALUES (?,?)", n.ObjectID, n.FileID); err != nil {
			return report, err
		}
	}
	if err = tx.Commit(); err != nil {
		return report, err
	}
	var integrity string
	if err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return report, invalid("projection integrity")
	}
	if err = db.Close(); err != nil {
		return report, err
	}
	closed = true
	f, err = os.OpenFile(dbpath, os.O_RDWR, 0)
	if err != nil {
		return report, err
	}
	err = errors.Join(f.Sync(), f.Close())
	if err != nil {
		return report, err
	}
	if err = opts.Progress(Event{Kind: "projection_prepared"}); err != nil {
		return report, err
	}
	if err = os.Link(dbpath, final); err != nil {
		return report, err
	} // no overwrite
	if runtime.GOOS != "windows" {
		dir, openErr := os.Open(parentDir)
		if openErr != nil {
			return report, openErr
		}
		if syncErr := errors.Join(dir.Sync(), dir.Close()); syncErr != nil {
			return report, syncErr
		}
	}
	if err = os.Remove(dbpath); err != nil {
		return report, err
	}
	if err = os.Remove(scratch); err != nil {
		return report, err
	}
	report.ScratchDirectory = ""
	if err = opts.Progress(Event{Kind: "projection_published"}); err != nil {
		return report, err
	}
	return report, nil
}
