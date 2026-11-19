package media

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestLegacyUploadPhysicalWritesRejectPersistedTree(t *testing.T) {
	ctx := context.Background()
	root, db, svc := masterFixture(t)
	stage, err := svc.Stage(ctx, strings.NewReader("ID3payload"), 10)
	if err != nil {
		t.Fatal(err)
	}
	stage.retain = true
	defer stage.Close()
	journal := uploadJournal{Format: "frontiercloud-local-upload", Version: 1, ID: stage.id, Object: store.MediaObject{Path: "music/fenced/song.mp3", Kind: "audio"}, Bytes: stage.Bytes, SHA256: stage.Digest, Audit: store.AdminAudit{Action: "upload_item"}}
	if err = svc.writeUploadJournal(ctx, journal); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Stage(ctx, strings.NewReader("ID3payload"), 10); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("new stage accepted", err)
	}
	// Master must reject before looking up or contacting any remote owner.
	if _, err = svc.UploadMasterBytes(ctx, "unresolved", strings.NewReader("ID3payload"), store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("master byte upload accepted", err)
	}
	if _, err = svc.FinalizeMasterUpload(ctx, "unresolved", store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("master finalize accepted", err)
	}
	if _, err = svc.ReserveMasterUpload(ctx, "new.mp3", "music/fenced", "", "direct", 10, 255, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("master reservation accepted", err)
	}
	if err = svc.RetryExpiredUploads(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("legacy sweeper accepted", err)
	}
	legacyGrants := []func() error{
		func() error { _, err := svc.MigrationReceiver(ctx); return err },
		func() error { _, err := svc.MigrationChunk(ctx, "", "", 0, 0, 0); return err },
		func() error { _, err := svc.MigrationPublish(ctx, migrationdata.Spec{}, nil, nil); return err },
		func() error { _, err := svc.MigrationRetireAnchor(ctx, migrationdata.Spec{}, nil); return err },
		func() error {
			return svc.MigrationCancelPublication(ctx, "", store.MigrationLease{}, store.MigrationShadowGrant{}, nil, store.NodeAudit{})
		},
		func() error {
			return svc.MigrationCleanup(ctx, "", store.MigrationLease{}, store.MigrationCleanupGrant{}, nil, store.NodeAudit{})
		},
		func() error {
			return svc.MigrationShadowCleanup(ctx, "", store.MigrationLease{}, store.MigrationShadowGrant{}, nil, store.NodeAudit{})
		},
		func() error {
			return svc.MigrationCleanupAuthorized(ctx, "", store.MigrationLease{}, "", nil, store.NodeAudit{})
		},
		func() error {
			return svc.MigrationShadowCleanupAuthorized(ctx, "", store.MigrationLease{}, "", nil, store.NodeAudit{})
		},
		func() error { _, err := svc.Rename(ctx, "music/artist", "new", store.AdminAudit{}); return err },
		func() error {
			_, err := svc.OwnedRename(ctx, "", "music/artist", "music/new", "", store.NodeAudit{})
			return err
		},
		func() error { return svc.finishRename(ctx, renameJournal{}) },
		func() error {
			_, err := svc.Delete(ctx, []string{"music/artist/song.mp3"}, store.AdminAudit{})
			return err
		},
		func() error { return svc.OwnedDelete(ctx, "", "", "music/artist/song.mp3", 0, store.NodeAudit{}) },
		func() error { return svc.finishDelete(ctx, store.DeleteOperation{}) },
		func() error { _, err := svc.Delivery(ctx, "music/fenced/song.mp3", "", "", "", false); return err },
		func() error { _, err := svc.Download(ctx, []string{"music/fenced/song.mp3"}); return err },
		func() error { _, err := svc.Stream(ctx, "music/fenced/song.mp3"); return err },
		func() error { _, err := svc.CryptoObject(ctx, "music/fenced/song.mp3", "", true); return err },
		func() error { _, err := svc.EncryptedLyric(ctx, "music/fenced/song.mp3", ""); return err },
		func() error { _, _, err := svc.RecordingLyricSource(ctx, ""); return err },
		func() error { _, _, err := svc.OpenCryptoLyric(ctx, "lyrics/fenced.lrc"); return err },
		func() error { _, _, err := svc.IngressLocalSource(ctx, store.MediaObject{}, 0); return err },
		func() error {
			_, _, _, _, err := svc.IngressLocalPlainSource(ctx, store.MediaObject{}, "", 0)
			return err
		},
		func() error { _, _, _, err := svc.FollowerDirectSource(ctx, store.MediaObject{}, 0); return err },
		func() error {
			_, _, _, _, _, err := svc.FollowerDirectPlainSource(ctx, store.MediaObject{}, "", 0)
			return err
		},
		func() error { _, _, err := svc.FollowerRelaySource(ctx, store.MediaObject{}); return err },
		func() error { _, _, err := svc.FollowerRelayObject(ctx, "", ""); return err },
		func() error { _, _, err := svc.MasterDirectSource(ctx, store.MediaObject{}, ""); return err },
		func() error { _, _, err := svc.OpenMasterDirect(ctx, "", "", ""); return err },
		func() error { _, _, err := svc.MasterRelaySource(ctx, store.MediaObject{}); return err },
		func() error { _, _, err := svc.OpenMasterRelay(ctx, "", ""); return err },
		func() error { _, _, err := svc.MasterLyricDirectSource(ctx, store.MediaObject{}, ""); return err },
		func() error { _, _, err := svc.OpenMasterLyricDirect(ctx, "", "", ""); return err },
		func() error { _, _, err := svc.MasterLyricRelaySource(ctx, store.MediaObject{}); return err },
		func() error { _, _, err := svc.OpenMasterLyricRelay(ctx, "", ""); return err },
	}
	for i, check := range legacyGrants {
		if err := check(); !errors.Is(err, store.ErrNodeState) {
			t.Fatalf("legacy grant %d accepted: %v", i, err)
		}
	}
	if err = svc.writeUploadJournal(ctx, journal); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("new journal accepted", err)
	}
	if err = svc.finishUpload(ctx, journal); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("physical publication accepted", err)
	}
	if _, err = NewContext(ctx, root, db.Media(), svc.identity); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("startup recovery accepted", err)
	}
	after, err := os.ReadDir(root)
	if err != nil || len(after) != len(before) {
		t.Fatal("fenced writes changed directory", err)
	}
	for _, name := range []string{stage.name, journalPath(stage.id)} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatal("recovery evidence lost", name, err)
		}
	}
	if _, err = os.Stat(filepath.Join(root, "music", "fenced", "song.mp3")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("target was created", err)
	}
	if _, err = os.Stat(filepath.Join(root, "music", "artist", "song.mp3")); err != nil {
		t.Fatal("existing legacy object was moved or deleted", err)
	}
}
