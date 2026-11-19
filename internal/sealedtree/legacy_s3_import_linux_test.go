//go:build linux

package sealedtree

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestLegacyS3BatchPreservesProviderIdentityAndRevalidatesOnReplay(t *testing.T) {
	for _, variant := range []string{"plain-video", "encrypted-explicit-lyric", "encrypted-default-lyric"} {
		t.Run(variant, func(t *testing.T) { testLegacyS3Batch(t, variant) })
	}
}

func testLegacyS3Batch(t *testing.T, variant string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath, treePath, mediaPath := filepath.Join(dir, "business.sqlite"), filepath.Join(dir, "tree"), filepath.Join(dir, "media")
	for _, location := range []string{treePath, filepath.Join(mediaPath, ".opaque-aliases"), filepath.Join(mediaPath, "lyrics")} {
		if err := os.MkdirAll(location, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := schema.Initialize(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataRoot: dir, SQLitePath: dbPath, DatabaseType: config.DatabaseSQLite, SecretsDirectory: filepath.Join(dir, "secrets")}
	gate, err := maintenance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := deployment.Bind(ctx, cfg, nil); err != nil {
		t.Fatal(err)
	}
	private, err := vault.Open(cfg.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	key, err := private.Seal(protocol.Encode(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	master := strings.Repeat("f", 32)
	exec(`INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','',?,123)`, master, key)
	p := fixtureS3Placement()
	p.ObjectID = strings.Repeat("4", 64)
	p.Proof.MediaID = p.ObjectID
	p.CreatedAt, p.UpdatedAt = 12, 13
	source, kind, parentPath := "vido/album/provider.mp4", "video", "vido/album"
	if variant != "plain-video" {
		source, kind, parentPath = "music/album/provider.mp3", "audio", "music/album"
		metadata, err := mediacrypto.NewMetadata(128)
		if err != nil {
			t.Fatal(err)
		}
		p.Encryption, p.Proof.Bytes = &metadata, metadata.CiphertextSize
		descriptor, err := json.Marshal(metadata)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES('media',?,?,?,1)`, p.ObjectID, metadata.FileID, string(descriptor))
		lyricID, lyricPath := strings.Repeat("e", 64), "lyrics/linked.lrc"
		lyricText := "[00:00.00]original link"
		if variant == "encrypted-default-lyric" {
			lyricPath, lyricText = "lyrics/default.lrc", sourceauth.DefaultLyricContent
		}
		if err := os.WriteFile(filepath.Join(mediaPath, filepath.FromSlash(lyricPath)), []byte(lyricText), 0600); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'lyric',?,?,'before','after')`, lyricID, lyricPath, localLegacyLocator(lyricPath))
		exec(`INSERT INTO media_lyric_links(media_id,media_path,lyric_id,lyric_path,created_at,updated_at) VALUES(?,?,?,?,'before','after')`, p.ObjectID, source, lyricID, lyricPath)
	}
	proof, err := json.Marshal(p.Proof)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES(?,NULL,'S3','S3',1,100000,?,0,0,'online',1,1)`, p.MemberID, p.Proof.Bytes)
	namespace, err := p.Location.Namespace()
	if err != nil {
		t.Fatal(err)
	}
	keyspace := namespace.Origin + "\n" + namespace.Bucket
	exec(`INSERT INTO s3_members(member_id,name,endpoint,region,bucket,prefix,address_style,namespace_key,created_at,updated_at) VALUES(?,'fixture',?,?,?,?,?,?,1,2)`, p.MemberID, p.Location.Endpoint, p.Location.Region, p.Location.Bucket, p.Location.Prefix, p.Location.AddressStyle, keyspace)
	exec(`INSERT INTO global_media_objects(media_id,storage_member_id,object_id,media_path,path_locator,object_kind,size_bytes,etag,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'active',?,?)`, p.ObjectID, p.MemberID, p.Proof.ObjectID, source, localLegacyLocator(source), kind, p.Proof.Bytes, p.Proof.ETag, p.CreatedAt, p.UpdatedAt)
	exec(`INSERT INTO s3_objects(media_id,member_id,object_key,object_id,proof_json,state,revision,created_at,updated_at) VALUES(?,?,?,?,?,'active',?,1,2)`, p.ObjectID, p.MemberID, p.Proof.Key, p.Proof.ObjectID, string(proof), p.ObjectRevision)
	exec(`INSERT INTO media_visibility(relative_path,hidden,updated_at) VALUES(?,1,'hidden ancestor')`, parentPath)
	codec := fixture(t)
	rootID := strings.Repeat("9", 64)
	if err := initializeExistingSQLiteOffline(ctx, cfg, gate, codec, rootID, treePath); err != nil {
		t.Fatal(err)
	}
	s, err := OpenSQLite(ctx, db, codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(treePath)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	if _, err := OpenFence(ctx, s, treeRoot, treePath); err != nil {
		t.Fatal(err)
	}
	mediaRoot, err := os.OpenRoot(mediaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer mediaRoot.Close()
	owner, err := ownerfence.Create(mediaRoot, mediaPath, localOwnerCodec{private})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.Acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := lease.Binding(ctx)
	lease.Release()
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO sealed_tree_owner_fence(singleton,fence_tag) VALUES(1,?)`, binding)
	run := func() (localMasterBatch, error) {
		return migrateLocalMasterBatchOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, private, master, "", 1)
	}
	if p.Encryption != nil {
		if progress, err := run(); err == nil || progress.Processed != 0 {
			t.Fatal("unreserved historical key ID admitted", progress, err)
		}
		if _, err := importLocalHistoryIDsOffline(ctx, gate, dir, dbPath, s, treeRoot, private, master); err != nil {
			t.Fatal(err)
		}
	}
	var originalCount, count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_records`).Scan(&originalCount); err != nil {
		t.Fatal(err)
	}
	exec(`CREATE TRIGGER fail_s3_metadata BEFORE INSERT ON sealed_tree_placements BEGIN SELECT RAISE(ABORT,'fixture interruption'); END`)
	if progress, err := run(); err == nil || progress.After != "" || progress.Processed != 0 {
		t.Fatal("partial S3 write advanced cursor", progress, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_records`).Scan(&count); err != nil || count != originalCount {
		t.Fatal("directory transaction did not roll back", count, err)
	}
	exec(`DROP TRIGGER fail_s3_metadata`)
	if progress, err := run(); err != nil || progress.After != p.ObjectID || progress.Processed != 1 {
		t.Fatal("S3 metadata not imported", progress, err)
	}
	read, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	view, viewErr := s.ReadS3ListingObjectWithLease(ctx, read, p.ObjectID, true)
	_, hiddenErr := s.ReadS3ListingObjectWithLease(ctx, read, p.ObjectID, false)
	read.Release()
	if viewErr != nil || !errors.Is(hiddenErr, ErrHidden) || view.Path != source || !reflect.DeepEqual(view.Placement, p) {
		t.Fatal("provider placement or visibility changed", viewErr, hiddenErr)
	}
	if variant == "encrypted-explicit-lyric" && (view.Facts.Lyric == nil || view.Facts.Lyric.LyricID != strings.Repeat("e", 64)) {
		t.Fatal("explicit lyric relation lost")
	}
	if variant == "encrypted-default-lyric" && (view.Facts.InternalDefaultLyric == nil || view.Facts.LyricResolution == nil || view.Facts.LyricResolution.State != "default") {
		t.Fatal("default lyric relation lost")
	}
	if kind == "audio" {
		lease, err := s.AcquireReadFence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		choice, err := s.SelectLyricForDisplayWithLease(ctx, lease, p.ObjectID)
		lease.Release()
		if err != nil || choice.Origin != "local" || choice.BuiltinFallback != (variant == "encrypted-default-lyric") || variant == "encrypted-explicit-lyric" && choice.ExplicitLyricID != strings.Repeat("e", 64) {
			t.Fatal("shared lyric selector did not verify S3 association", err)
		}
	}
	if progress, err := run(); err != nil || progress.Processed != 1 {
		t.Fatal("retry did not verify committed S3 metadata", progress, err)
	}
	var storedKey string
	var used int64
	if err := db.QueryRow(`SELECT o.object_key,m.used_bytes FROM s3_objects o JOIN cluster_storage_members m ON m.member_id=o.member_id WHERE o.media_id=?`, p.ObjectID).Scan(&storedKey, &used); err != nil || storedKey != p.Proof.Key || used != p.Proof.Bytes {
		t.Fatal("source provider key or quota changed", err)
	}
	exec(`UPDATE s3_members SET bucket='different-fixture' WHERE member_id=?`, p.MemberID)
	if progress, err := run(); err == nil || progress.Processed != 0 {
		t.Fatal("bucket disagreed with the durable namespace", progress, err)
	}
	exec(`UPDATE s3_members SET bucket=? WHERE member_id=?`, p.Location.Bucket, p.MemberID)
	exec(`UPDATE s3_objects SET revision=revision+1 WHERE media_id=?`, p.ObjectID)
	if progress, err := run(); err == nil || progress.Processed != 0 || progress.After != "" {
		t.Fatal("changed proof passed replay", progress, err)
	}
	if kind == "audio" {
		if err := s.ApplyNativeLyricBatch(ctx, NativeLyricOperation{OriginID: p.ObjectID, Changes: []NativeLyricChange{{TrackID: p.ObjectID, ExpectedFactsRevision: view.FactsRevision}}}, store.AdminAudit{}); err != nil {
			t.Fatal("Master could not update the imported S3 lyric association", err)
		}
		lease, err := s.AcquireReadFence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		choice, choiceErr := s.SelectLyricForDisplayWithLease(ctx, lease, p.ObjectID)
		updated, readErr := s.ReadS3ListingObjectWithLease(ctx, lease, p.ObjectID, true)
		lease.Release()
		if choiceErr != nil || readErr != nil || !choice.BuiltinFallback || choice.Origin != "native" || !reflect.DeepEqual(updated.Placement, p) {
			t.Fatal("lyric update changed provider placement or selected the wrong fallback", choiceErr, readErr)
		}
	}
}
