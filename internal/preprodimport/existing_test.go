package preprodimport

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
)

// checkExisting verifies every projected row against the same typed input. It
// supports retry after publication without ever modifying the existing file.
func checkExisting(ctx context.Context, name string, s Snapshot, owners map[string]Mapping, report Report) error {
	before, err := os.Lstat(name)
	if err != nil || !privateOwned(before, false) {
		return invalid("existing projection ownership")
	}
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(name)}
	q := u.Query()
	q.Set("mode", "ro")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return invalid("existing projection integrity")
	}
	tables := []struct {
		name  string
		count int
	}{{"projection_meta", 1}, {"owner_mapping", len(s.Mappings)}, {"excluded_source", len(s.ExcludedSourceIDs)}, {"media", len(s.Media)}, {"lyric", len(s.Lyrics)}, {"directory", len(s.Directories)}, {"lyric_link", len(s.Links)}, {"visibility", len(s.Visibility)}, {"preference", len(s.Preferences)}, {"retired_nonce", len(s.RetiredNonces)}}
	var total int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&total); err != nil || total != len(tables) {
		return invalid("existing projection tables")
	}
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')").Scan(&total); err != nil || total != 0 {
		return invalid("existing projection executable schema")
	}
	for _, t := range tables {
		if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+t.name).Scan(&total); err != nil || total != t.count {
			return invalid("existing projection count")
		}
	}
	var version, auth, consistent, ready int
	var projection, source, key string
	if err = db.QueryRowContext(ctx, "SELECT version,projection_sha256,source_projection_sha256,premaster_key_id,source_authenticated,snapshot_consistent,runtime_ready FROM projection_meta").Scan(&version, &projection, &source, &key, &auth, &consistent, &ready); err != nil || version != 1 || projection != report.ProjectionSHA256 || source != s.SourceProjectionSHA256 || key != s.PremasterKeyID || auth != 0 || consistent != 0 || ready != 0 {
		return invalid("existing projection metadata")
	}
	for _, m := range s.Mappings {
		var target, role string
		var cap int64
		if err = db.QueryRowContext(ctx, "SELECT target_id,role,capacity FROM owner_mapping WHERE source_id=?", m.SourceID).Scan(&target, &role, &cap); err != nil || target != m.TargetID || role != m.Role || cap != m.Capacity {
			return invalid("existing owner mapping")
		}
	}
	for _, id := range s.ExcludedSourceIDs {
		if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM excluded_source WHERE source_id=?", id).Scan(&total); err != nil || total != 1 {
			return invalid("existing exclusion")
		}
	}
	for _, m := range s.Media {
		var object, sourceID, target, role, path, kind, sha string
		var size int64
		var enc sql.NullString
		if err = db.QueryRowContext(ctx, "SELECT object_id,source_id,target_id,role,path,kind,size,sha256,encryption_json FROM media WHERE media_id=?", m.MediaID).Scan(&object, &sourceID, &target, &role, &path, &kind, &size, &sha, &enc); err != nil {
			return invalid("existing media")
		}
		var want string
		if m.Encryption != nil {
			raw, e := json.Marshal(m.Encryption)
			if e != nil {
				return e
			}
			want = string(raw)
		}
		owner := owners[m.SourceID]
		if object != m.ObjectID || sourceID != m.SourceID || target != owner.TargetID || role != owner.Role || path != m.Path || kind != m.Kind || size != m.Size || sha != m.SHA256 || enc.Valid != (m.Encryption != nil) || enc.Valid && enc.String != want {
			return invalid("existing media changed")
		}
	}
	for _, l := range s.Lyrics {
		var path, sha string
		var size int64
		var builtin bool
		var enc sql.NullString
		if err = db.QueryRowContext(ctx, "SELECT path,size,sha256,builtin,encryption_json FROM lyric WHERE id=?", l.ID).Scan(&path, &size, &sha, &builtin, &enc); err != nil {
			return invalid("existing lyric")
		}
		var want string
		if l.Encryption != nil {
			raw, e := json.Marshal(l.Encryption)
			if e != nil {
				return e
			}
			want = string(raw)
		}
		if path != l.Path || size != l.Size || sha != l.SHA256 || builtin != l.Builtin || enc.Valid != (l.Encryption != nil) || enc.Valid && enc.String != want {
			return invalid("existing lyric changed")
		}
	}
	for _, d := range s.Directories {
		var path string
		if err = db.QueryRowContext(ctx, "SELECT path FROM directory WHERE id=?", d.ID).Scan(&path); err != nil || path != d.Path {
			return invalid("existing directory")
		}
	}
	for _, l := range s.Links {
		var id string
		if err = db.QueryRowContext(ctx, "SELECT lyric_id FROM lyric_link WHERE media_id=?", l.MediaID).Scan(&id); err != nil || id != l.LyricID {
			return invalid("existing lyric link")
		}
	}
	for _, v := range s.Visibility {
		var hidden bool
		if err = db.QueryRowContext(ctx, "SELECT hidden FROM visibility WHERE path=?", v.Path).Scan(&hidden); err != nil || hidden != v.Hidden {
			return invalid("existing visibility")
		}
	}
	for _, p := range s.Preferences {
		var value int
		var score int64
		if err = db.QueryRowContext(ctx, "SELECT value,play_score FROM preference WHERE id=?", p.ID).Scan(&value, &score); err != nil || value != p.Value || score != p.PlayScore {
			return invalid("existing preference")
		}
	}
	for _, n := range s.RetiredNonces {
		var file string
		if err = db.QueryRowContext(ctx, "SELECT file_id FROM retired_nonce WHERE object_id=?", n.ObjectID).Scan(&file); err != nil || file != n.FileID {
			return invalid("existing nonce")
		}
	}
	if err = db.Close(); err != nil {
		return err
	}
	after, err := os.Lstat(name)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return invalid("existing projection changed")
	}
	return nil
}
