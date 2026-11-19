//go:build linux

package sealedtree

import (
	"context"
	"fmt"
	"path"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Compares only the layout and immediate-parent owner checks. It excludes
// reservation, Owner network I/O and media encryption. Fixture overhead and
// synthetic data mean these numbers cannot be treated as production SLOs.
func TestCoordinatedLayoutLegacyScale(t *testing.T) {
	for _, size := range []int{128, 512} {
		t.Run(fmt.Sprintf("pending_%d", size), func(t *testing.T) {
			ctx := context.Background()
			db, s, _, _, _ := fencedFixture(t)
			for _, q := range []string{`CREATE TABLE scale_legacy_objects(media_path TEXT, storage_member_id TEXT, state TEXT)`, `CREATE TABLE scale_legacy_uploads(media_path TEXT, storage_member_id TEXT, state TEXT)`, `CREATE INDEX scale_global_path ON scale_legacy_objects(media_path)`} {
				if _, err := db.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			var dirs []Entry
			for _, d := range []Entry{{ParentID: s.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}, {ParentID: strings.Repeat("1", 64), ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "cat"}, {ParentID: strings.Repeat("2", 64), ObjectID: strings.Repeat("3", 64), Kind: "directory", Name: "sub"}} {
				if err := s.CreateDirectoryWithFacts(ctx, d, Facts{ObjectID: d.ObjectID}); err != nil {
					t.Fatal(err)
				}
				dirs = append(dirs, d)
			}
			owner := strings.Repeat("f", 32)
			for i := 0; i < size; i++ {
				id := fmt.Sprintf("%064x", i+1000)
				name := fmt.Sprintf("song-%05d.mp3", i)
				entry := Entry{ParentID: dirs[2].ObjectID, ObjectID: id, Kind: "audio", Name: name}
				placement := fixturePlacement(t, id)
				placement.BlobID, placement.ReadAlias = "", ""
				if _, err := s.PrepareFileWithFreshLocators(ctx, entry, placement, Facts{ObjectID: id}); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`INSERT INTO scale_legacy_uploads VALUES(?,?,'reserved')`, "music/cat/sub/"+name, owner); err != nil {
					t.Fatal(err)
				}
			}
			cpu := func() time.Duration {
				var u syscall.Rusage
				if err := syscall.Getrusage(syscall.RUSAGE_SELF, &u); err != nil {
					t.Fatal(err)
				}
				return time.Duration(u.Utime.Sec+u.Stime.Sec)*time.Second + time.Duration(u.Utime.Usec+u.Stime.Usec)*time.Microsecond
			}
			beforeCPU := cpu()
			started := time.Now()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := tx.QueryContext(ctx, `SELECT media_path,storage_member_id FROM scale_legacy_objects WHERE state IN ('active','pending_delete','renaming') AND (media_path=? OR (media_path LIKE ? ESCAPE '!' AND substr(media_path,1,length(?))=?)) UNION ALL SELECT media_path,storage_member_id FROM scale_legacy_uploads WHERE state='reserved' AND (media_path=? OR (media_path LIKE ? ESCAPE '!' AND substr(media_path,1,length(?))=?))`, "music/cat", "music/cat/%", "music/cat/", "music/cat/", "music/cat", "music/cat/%", "music/cat/", "music/cat/")
			if err != nil {
				t.Fatal(err)
			}
			seen := 0
			for rows.Next() {
				var name, member string
				if err := rows.Scan(&name, &member); err != nil {
					t.Fatal(err)
				}
				if strings.Count(name, "/") != 3 || path.Dir(name) != "music/cat/sub" || member != owner {
					t.Fatal("legacy inconsistent")
				}
				seen++
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			rows.Close()
			tx.Rollback()
			legacyWall, legacyCPU := time.Since(started), cpu()-beforeCPU
			if seen != size {
				t.Fatal("legacy incomplete", seen)
			}
			beforeCPU = cpu()
			started = time.Now()
			err = s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
				tx, e := db.BeginTx(ctx, nil)
				if e != nil {
					return e
				}
				defer tx.Rollback()
				return m.CheckMediaCategoryAndOwnerTx(ctx, tx, dirs[2].ObjectID, owner)
			})
			newWall, newCPU := time.Since(started), cpu()-beforeCPU
			if err != nil {
				t.Fatal(err)
			}
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			beforeCPU = cpu()
			started = time.Now()
			proof, err := s.PreflightCategoryAndOwner(bounded, dirs[2].ObjectID, owner)
			preflightWall, preflightCPU := time.Since(started), cpu()-beforeCPU
			if err != nil {
				t.Fatal(err)
			}
			beforeCPU = cpu()
			started = time.Now()
			err = s.WithCoordinatedMutation(bounded, db, func(m *CoordinatedMutation) error {
				tx, e := db.BeginTx(bounded, nil)
				if e != nil {
					return e
				}
				defer tx.Rollback()
				return m.ConsumeCategoryOwnerPreflightTx(bounded, tx, proof, dirs[2].ObjectID, owner)
			})
			commitWall, commitCPU := time.Since(started), cpu()-beforeCPU
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("synthetic size=%d legacy_wall=%s legacy_cpu=%s tree_wall=%s tree_cpu=%s preflight_wall=%s preflight_cpu=%s proof_commit_wall=%s proof_commit_cpu=%s; single sample, one CPU, no production guarantee", size, legacyWall, legacyCPU, newWall, newCPU, preflightWall, preflightCPU, commitWall, commitCPU)
		})
	}
}
