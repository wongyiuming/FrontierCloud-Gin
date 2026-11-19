package business_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestLegacyPhysicalGateRejectsTreeMissingSchemaAndCancellation(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	repo := db.Nodes().(*business.Repository)
	if err := repo.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		t.Fatal("empty tree", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1}); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*business.Repository{repo, business.New(raw, db.Backend())} {
		if err := candidate.CheckLegacyPhysicalWritesAllowed(ctx); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("durable tree marker accepted", err)
		}
	}
	if _, err := raw.ExecContext(ctx, `DELETE FROM sealed_tree_meta WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := repo.CheckLegacyPhysicalWritesAllowed(cancelled); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("cancelled context accepted", err)
	}
	if _, err := raw.ExecContext(ctx, `DROP TABLE sealed_tree_meta`); err != nil {
		t.Fatal(err)
	}
	if err := repo.CheckLegacyPhysicalWritesAllowed(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("missing tree marker schema accepted", err)
	}
}

func TestLegacyWritersRejectDurableTreeWithoutService(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	repo := business.New(raw, db.Backend())
	operation, object, user := strings.Repeat("1", 32), strings.Repeat("2", 64), strings.Repeat("3", 32)
	if err := repo.DeferExpiredUpload(ctx, operation); err != nil {
		t.Fatal("empty tree baseline", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1}); err != nil {
		t.Fatal(err)
	}
	check := func(candidate *business.Repository) {
		t.Helper()
		checks := map[string]func() error{
			"legacy encryption key initialization": func() error { return candidate.CheckEncryptionKey(ctx, strings.Repeat("a", 64)) },
			"ensure objects": func() error {
				_, e := candidate.EnsureObjects(ctx, []store.MediaObject{{ID: object, Path: "music/group/item.mp3", Kind: "audio"}})
				return e
			},
			"playback": func() error {
				_, e := candidate.RecordPlayback(ctx, store.MediaObject{ID: object, Path: "music/group/item.mp3", Kind: "audio"}, operation)
				return e
			},
			"global playback": func() error {
				_, e := candidate.RecordGlobalPlayback(ctx, object, operation)
				return e
			},
			"global preference": func() error {
				_, e := candidate.SetGlobalPreference(ctx, object, 0, store.AdminAudit{})
				return e
			},
			"owned recording deletion": func() error {
				_, e := candidate.StageOwnedRecordingDeletion(ctx, operation, user, operation)
				return e
			},
			"owned user deletion":     func() error { return candidate.StageOwnedUserDeletion(ctx, operation, user) },
			"account deletion stage":  func() error { _, e := candidate.StageUserDeletion(ctx, user, store.KaraokeAudit{}); return e },
			"account deletion finish": func() error { _, e := candidate.FinishUserDeletion(ctx, user, store.KaraokeAudit{}); return e },
			"owned upload reservation": func() error {
				return candidate.ReserveOwnedUpload(ctx, operation, user, store.MediaObject{ID: object, Path: "music/group/item.mp3", Kind: "audio"}, 1, store.GiB, store.NodeAudit{})
			},
			"owned upload completion": func() error {
				return candidate.CompleteOwnedUpload(ctx, operation, store.MediaObject{ID: object, Path: "music/group/item.mp3", Kind: "audio"}, 1, `"etag"`, store.GiB, store.NodeAudit{})
			},
			"owned upload release": func() error { return candidate.ReleaseOwnedUpload(ctx, operation, store.NodeAudit{}) },
			"owned rename preflight": func() error {
				return candidate.CheckOwnedRename(ctx, user, "music/group/item.mp3", "music/group/new.mp3")
			},
			"owned rename completion": func() error {
				return candidate.CompleteOwnedRename(ctx, user, "music/group/item.mp3", "music/group/new.mp3", operation, store.NodeAudit{})
			},
			"offline rename history": func() error { _, e := candidate.DrainCompletedRenames(ctx, user, store.NodeAudit{}); return e },
			"s3 start create":        func() error { _, e := candidate.S3StartCreate(ctx, operation, 1); return e },
			"s3 finish create":       func() error { _, e := candidate.S3FinishCreate(ctx, operation, 1, "", "", ""); return e },
			"s3 issue part":          func() error { _, e := candidate.S3IssuePart(ctx, operation, 1, strings.Repeat("a", 64), 1); return e },
			"s3 start complete":      func() error { _, e := candidate.S3StartComplete(ctx, operation, 1); return e },
			"s3 finalize": func() error {
				_, e := candidate.S3FinalizeUpload(ctx, operation, 1, store.S3ObjectProof{}, store.AdminAudit{})
				return e
			},
			"s3 request abort": func() error { _, e := candidate.S3RequestAbort(ctx, operation, store.AdminAudit{}); return e },
			"s3 finish abort": func() error {
				_, e := candidate.S3FinishAbort(ctx, operation, 1, store.S3AbsenceProof{}, store.AdminAudit{})
				return e
			},
			"s3 read grant":   func() error { _, e := candidate.S3IssueReadGrant(ctx, object, 1); return e },
			"s3 start delete": func() error { _, e := candidate.S3StartDelete(ctx, object, store.AdminAudit{}); return e },
			"s3 finish delete": func() error {
				return candidate.S3FinishDelete(ctx, object, 1, store.S3AbsenceProof{}, store.AdminAudit{})
			},
			"bind lyric": func() error {
				return candidate.BindLyric(ctx, store.MediaObject{ID: object, Path: "music/group/item.mp3", Kind: "audio"}, store.MediaObject{Path: "lyrics/example.lrc", Kind: "lyric"})
			},
			"reserve": func() error {
				_, e := candidate.ReserveUpload(ctx, "music/group/item.mp3", "primary", 10, 10*store.GiB, store.AdminAudit{})
				return e
			},
			"finalize": func() error {
				_, e := candidate.FinalizeUpload(ctx, operation, object, 10, `"etag"`, store.AdminAudit{})
				return e
			},
			"recovered finalize": func() error {
				_, e := candidate.FinalizeRecoveredUpload(ctx, operation, object, 10, `"`+strings.Repeat("a", 64)+`"`, store.AdminAudit{})
				return e
			},
			"defer upload": func() error { return candidate.DeferExpiredUpload(ctx, operation) },
			"prepare delete": func() error {
				_, e := candidate.PrepareGlobalDelete(ctx, []store.DeleteItem{{Path: "music/group/item.mp3"}}, store.AdminAudit{})
				return e
			},
			"complete delete": func() error { return candidate.CompleteGlobalDelete(ctx, object, store.AdminAudit{}) },
			"rename": func() error {
				_, e := candidate.PrepareGlobalRename(ctx, "music/group/item.mp3", "music/group/new.mp3", store.AdminAudit{})
				return e
			},
			"rename completion": func() error { return candidate.CompleteGlobalRename(ctx, operation) },
			"recording deletion": func() error {
				_, e := candidate.StageRecordingDeletion(ctx, user, operation, false, store.KaraokeAudit{})
				return e
			},
			"recording completion": func() error { return candidate.CompleteRecordingDeletion(ctx, user, operation, store.KaraokeAudit{}) },
			"recording recovery":   func() error { return candidate.DeferRecordingDeletion(ctx, operation) },
			"local upload": func() error {
				return candidate.CompleteUpload(ctx, store.MediaObject{ID: object, Path: "music/group/item.mp3", Kind: "audio"}, operation, store.AdminAudit{})
			},
			"local rename": func() error {
				return candidate.CompleteRename(ctx, "music/group/item.mp3", "music/group/new.mp3", operation, store.AdminAudit{})
			},
			"hidden": func() error { return candidate.SetHidden(ctx, []string{"music/group"}, true, store.AdminAudit{}) },
			"preference": func() error {
				_, e := candidate.SetPreference(ctx, store.MediaObject{ID: object, Path: "music/group/item.mp3", Kind: "audio"}, 0, store.AdminAudit{})
				return e
			},
			"priority": func() error {
				_, e := candidate.MovePriority(ctx, store.PriorityScope{}, store.PriorityMove{}, store.AdminAudit{})
				return e
			},
			"lyric binding": func() error {
				_, e := candidate.ReplaceLyricRelations(ctx, store.MediaObject{ID: object, Path: "music/group/item.mp3", Kind: "audio"}, nil, store.MediaObject{Path: "lyrics/default.lrc", Kind: "lyric"}, store.AdminAudit{})
				return e
			},
		}
		for name, run := range checks {
			if err := run(); !errors.Is(err, store.ErrNodeState) {
				t.Errorf("%s bypassed durable tree marker: %v", name, err)
			}
		}
	}
	check(repo)
	if db.Backend() == "sqlite" {
		var path string
		if err := raw.QueryRowContext(ctx, `SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
			t.Fatal(err)
		}
		opened, err := sqlitestore.OpenExisting(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		defer opened.Close()
		check(opened.Nodes().(*business.Repository))
	}
}
