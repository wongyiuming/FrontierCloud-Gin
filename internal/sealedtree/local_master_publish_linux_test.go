//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"database/sql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type localOwnerCodec struct{ vault *vault.Vault }

func (c localOwnerCodec) SealOpaqueOwnerRecord(name string, data []byte) (string, error) {
	return c.vault.Seal(name + "\x00" + string(data))
}
func (c localOwnerCodec) OpenOpaqueOwnerRecord(name, value string) ([]byte, error) {
	p, e := c.vault.Unseal(value)
	if e != nil || !strings.HasPrefix(p, name+"\x00") {
		return nil, ErrInvalid
	}
	return []byte(strings.TrimPrefix(p, name+"\x00")), nil
}

func TestLocalMasterLegacyKeepsSourceOnFailureAndCommit(t *testing.T) {
	for _, mode := range []string{"video", "prepare-video", "prepare-lyric", "audio-none", "audio-explicit", "audio-default", "lyric", "onescope-video", "onescope-audio", "onescope-lyric"} {
		t.Run(mode, func(t *testing.T) { testLocalMasterLegacy(t, mode) })
	}
}

func testLocalMasterLegacy(t *testing.T, mode string) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "business.sqlite")
	treePath := filepath.Join(dir, "tree")
	mediaPath := filepath.Join(dir, "media")
	prefix, kind, filename := "vido", "video", "movie.mp4"
	if strings.HasPrefix(mode, "audio") || mode == "onescope-audio" {
		prefix, kind, filename = "music", "audio", "song.mp3"
	}
	if mode == "lyric" || mode == "prepare-lyric" || mode == "onescope-lyric" {
		prefix, kind, filename = "lyrics", "lyric", "song.lrc"
	}
	for _, p := range []string{treePath, filepath.Join(mediaPath, prefix, "album")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = schema.Initialize(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{DataRoot: dir, SQLitePath: dbPath, DatabaseType: config.DatabaseSQLite, SecretsDirectory: filepath.Join(dir, "secrets")}
	gate, err := maintenance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = deployment.Bind(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(c.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	key, err := v.Seal(protocol.Encode(bytes.Repeat([]byte{5}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	master := strings.Repeat("f", 32)
	if _, err = db.ExecContext(ctx, `INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','',?,123)`, master, key); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES(?,NULL,'MasterLocal','Local',1,100000,10,0,100000,'online',1,1)`, master); err != nil {
		t.Fatal(err)
	}
	videoID := strings.Repeat("4", 64)
	rootDirID := strings.Repeat("2", 64)
	albumID := strings.Repeat("3", 64)
	sourcePath := prefix + "/album/" + filename
	plaintext := []byte("synthetic original video bytes")
	metadata, err := mediacrypto.NewMetadata(int64(len(plaintext)))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := mediacrypto.New(bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := manager.FileKey(metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fileKey)
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := metadata.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	data := gcm.Seal(nil, nonce, plaintext, metadata.ChunkAAD(0))
	if err = os.WriteFile(filepath.Join(mediaPath, filepath.FromSlash(sourcePath)), data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ id, kind, p string }{{rootDirID, "directory", prefix}, {albumID, "directory", prefix + "/album"}, {videoID, kind, sourcePath}} {
		if _, err = db.ExecContext(ctx, `INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,?,?,?,?,?)`, item.id, item.kind, item.p, localLegacyLocator(item.p), "created", "updated"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO media_visibility(relative_path,hidden,updated_at) VALUES(?,1,'hidden')`, prefix+"/album"); err != nil {
		t.Fatal(err)
	}
	if kind != "lyric" {
		if _, err = db.ExecContext(ctx, `INSERT INTO global_media_objects(media_id,storage_member_id,object_id,media_path,path_locator,object_kind,size_bytes,etag,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'legacy-etag','active',12,13)`, videoID, master, videoID, sourcePath, localLegacyLocator(sourcePath), kind, len(data)); err != nil {
			t.Fatal(err)
		}
	}
	descriptor, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES('media',?,?,?,1)`, videoID, metadata.FileID, string(descriptor)); err != nil {
		t.Fatal(err)
	}
	var lyric *LyricFact
	var defaultLyric *DefaultLyricFact
	if mode == "audio-explicit" {
		lyricID := strings.Repeat("5", 64)
		lyricPath := "lyrics/album/song.lrc"
		if _, err = db.ExecContext(ctx, `INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'lyric',?,?,?,?)`, lyricID, lyricPath, localLegacyLocator(lyricPath), "lc", "lu"); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO media_lyric_links(media_id,media_path,lyric_id,lyric_path,created_at,updated_at) VALUES(?,?,?,?,?,?)`, videoID, sourcePath, lyricID, lyricPath, "linked", "updated"); err != nil {
			t.Fatal(err)
		}
		lyric = &LyricFact{LegacyMediaPath: sourcePath, LyricID: lyricID, LegacyLyricPath: lyricPath, CreatedAt: "linked", UpdatedAt: "updated"}
	}
	if mode == "audio-default" {
		lyricID := strings.Repeat("6", 64)
		lyricPath := "lyrics/default.lrc"
		if err = os.MkdirAll(filepath.Join(mediaPath, "lyrics"), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(mediaPath, filepath.FromSlash(lyricPath)), []byte(sourceauth.DefaultLyricContent), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'lyric',?,?,?,?)`, lyricID, lyricPath, localLegacyLocator(lyricPath), "lc", "lu"); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO media_lyric_links(media_id,media_path,lyric_id,lyric_path,created_at,updated_at) VALUES(?,?,?,?,?,?)`, videoID, sourcePath, lyricID, lyricPath, "linked", "updated"); err != nil {
			t.Fatal(err)
		}
		defaultLyric = &DefaultLyricFact{LegacyMediaPath: sourcePath, DefaultLyricID: lyricID, CreatedAt: "linked", UpdatedAt: "updated"}
	}
	tree := fixture(t)
	rootID := strings.Repeat("a", 64)
	if err = initializeExistingSQLiteOffline(ctx, c, gate, tree, rootID, treePath); err != nil {
		t.Fatal(err)
	}
	s, err := OpenSQLite(ctx, db, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(treePath)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	if _, err = OpenFence(ctx, s, treeRoot, treePath); err != nil {
		t.Fatal(err)
	}
	obj := &ObjectFact{CreatedAt: "created", UpdatedAt: "updated"}
	if !strings.HasPrefix(mode, "prepare-") && !strings.HasPrefix(mode, "onescope-") {
		if err = s.CreateDirectoryWithFacts(ctx, Entry{ParentID: rootID, ObjectID: rootDirID, Kind: "directory", Name: prefix}, Facts{ObjectID: rootDirID, Object: obj}); err != nil {
			t.Fatal(err)
		}
		if err = s.CreateDirectoryWithFacts(ctx, Entry{ParentID: rootDirID, ObjectID: albumID, Kind: "directory", Name: "album"}, Facts{ObjectID: albumID, Object: obj, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "hidden"}}); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256(data)
	entry := Entry{ParentID: albumID, ObjectID: videoID, Kind: kind, Name: filename}
	placement := Placement{ObjectID: videoID, NativeObjectID: videoID, OwnerID: master, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), ETag: "legacy-etag", State: "active", CreatedAt: 12, UpdatedAt: 13, Encryption: &metadata}
	if kind == "lyric" {
		placement.ETag = ""
		placement.CreatedAt = 0
		placement.UpdatedAt = 0
	}
	var pending PreparedFile
	if !strings.HasPrefix(mode, "prepare-") && !strings.HasPrefix(mode, "onescope-") {
		pending, err = s.PrepareFileWithFreshLocators(ctx, entry, placement, Facts{ObjectID: videoID, Object: obj, Lyric: lyric, InternalDefaultLyric: defaultLyric})
		if err != nil {
			t.Fatal(err)
		}
	}
	mediaRoot, err := os.OpenRoot(mediaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer mediaRoot.Close()
	if err = mediaRoot.Mkdir(".opaque-aliases", 0700); err != nil {
		t.Fatal(err)
	}
	owner, err := ownerfence.Create(mediaRoot, mediaPath, localOwnerCodec{v})
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
	if _, err = db.ExecContext(ctx, `INSERT INTO sealed_tree_owner_fence(singleton,fence_tag) VALUES(1,?)`, binding); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(mode, "onescope-") {
		if mode == "onescope-video" {
			otherID := strings.Repeat("7", 64)
			otherPath := prefix + "/album/other.mp4"
			if _, err = db.ExecContext(ctx, `INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'video',?,?,?,?)`, otherID, otherPath, localLegacyLocator(otherPath), "created", "updated"); err != nil {
				t.Fatal(err)
			}
			if _, err = db.ExecContext(ctx, `INSERT INTO global_media_objects(media_id,storage_member_id,object_id,media_path,path_locator,object_kind,size_bytes,etag,state,created_at,updated_at) VALUES(?,?,?,?,?,'video',?,'legacy-etag','active',12,13)`, otherID, master, otherID, otherPath, localLegacyLocator(otherPath), len(data)); err != nil {
				t.Fatal(err)
			}
			otherFile := filepath.Join(mediaPath, filepath.FromSlash(otherPath))
			if err = os.Symlink("missing", otherFile); err != nil {
				t.Fatal(err)
			}
			batch, e := migrateLocalMasterBatchOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, "", 2)
			if e == nil || batch.Processed != 1 || batch.After != videoID {
				t.Fatal("failed item advanced batch", batch, e)
			}
			if err = os.Remove(otherFile); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(otherFile, data, 0600); err != nil {
				t.Fatal(err)
			}
			batch, e = migrateLocalMasterBatchOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, batch.After, 1)
			if e != nil || batch.Processed != 1 || batch.After != otherID {
				t.Fatal("failed item did not resume", batch, e)
			}
			batch, e = migrateLocalMasterBatchOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, "", 2)
			if e != nil || batch.Processed != 2 {
				t.Fatal("full replay did not revalidate both operations", batch, e)
			}
			batch, e = migrateLocalMasterBatchOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, "", 1)
			if e != nil || batch.Processed != 1 || batch.After != videoID || !batch.HasMore {
				t.Fatal("batch bound was not honored", batch, e)
			}
			batch, e = migrateLocalMasterBatchOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, batch.After, 1)
			if e != nil || batch.Processed != 1 || batch.After != otherID || batch.HasMore {
				t.Fatal("bounded continuation failed", batch, e)
			}
			remoteID, relationID := strings.Repeat("8", 32), strings.Repeat("9", 32)
			if _, err = db.ExecContext(ctx, `INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES(?,?,'Follower','Direct',1,0,0,0,0,'healthy',1,1)`, remoteID, relationID); err != nil {
				t.Fatal(err)
			}
			if _, err = db.ExecContext(ctx, `UPDATE global_media_objects SET storage_member_id=? WHERE media_id=?`, remoteID, otherID); err != nil {
				t.Fatal(err)
			}
			batch, e = migrateLocalMasterBatchOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, videoID, 1)
			if e == nil || batch.Processed != 0 || batch.After != videoID {
				t.Fatal("remote owner was skipped or treated as local", batch, e)
			}
			if _, err = db.ExecContext(ctx, `UPDATE global_media_objects SET storage_member_id=? WHERE media_id=?`, master, otherID); err != nil {
				t.Fatal(err)
			}
			if _, e = migrateLocalMasterBatchOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, "not-an-id", 1); !errors.Is(e, ErrInvalid) {
				t.Fatal("invalid cursor accepted", e)
			}
			if _, e = migrateLocalMasterBatchOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, "", localMasterBatchLimit+1); !errors.Is(e, ErrInvalid) {
				t.Fatal("oversized batch accepted", e)
			}
		}
		first, err := migrateLocalMasterObjectOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, videoID)
		if err != nil {
			t.Fatal("same-scope initial migration", err)
		}
		second, err := migrateLocalMasterObjectOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, videoID)
		if err != nil || first != second {
			t.Fatal("same-scope restart must retain operation", err)
		}
		old, err := os.ReadFile(filepath.Join(mediaPath, filepath.FromSlash(sourcePath)))
		if err != nil || !bytes.Equal(old, data) {
			t.Fatal("old source changed", err)
		}
		return
	}
	if strings.HasPrefix(mode, "prepare-") {
		prepare := func() (PreparedFile, error) {
			return prepareLocalMasterOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, videoID)
		}
		if _, err = db.ExecContext(ctx, `CREATE TRIGGER fail_local_directory BEFORE INSERT ON sealed_tree_records WHEN (SELECT COUNT(*) FROM sealed_tree_records)>=1 BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err = prepare(); err == nil {
			t.Fatal("partial directory transaction accepted")
		}
		var count int
		if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_records`).Scan(&count); err != nil || count != 0 {
			t.Fatal("directory failure did not roll back", count, err)
		}
		if _, err = db.ExecContext(ctx, `DROP TRIGGER fail_local_directory`); err != nil {
			t.Fatal(err)
		}
		pending, err = prepare()
		if err != nil {
			t.Fatal("local source prepare", err)
		}
		retry, e := prepare()
		if e != nil || retry != pending {
			t.Fatal("pending preparation did not recover", e)
		}
	}
	var oldFactsID string
	if err = db.QueryRowContext(ctx, `SELECT encryption_id FROM sealed_tree_pending_facts WHERE operation_id=?`, pending.OperationID).Scan(&oldFactsID); err != nil {
		t.Fatal(err)
	}
	run := func() error {
		return publishLocalMasterLegacyOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, pending.OperationID)
	}
	if kind == "lyric" {
		if _, err = db.ExecContext(ctx, `INSERT INTO global_media_objects(media_id,storage_member_id,object_id,media_path,path_locator,object_kind,size_bytes,etag,state,created_at,updated_at) VALUES(?,?,?,?,?,'lyric',?,'remote','active',12,13)`, videoID, master, videoID, sourcePath, strings.Repeat("9", 64), len(data)); err != nil {
			t.Fatal(err)
		}
		if err = run(); err == nil {
			t.Fatal("conflicting global lyric owner accepted")
		}
		if _, err = db.ExecContext(ctx, `DELETE FROM global_media_objects WHERE media_id=?`, videoID); err != nil {
			t.Fatal(err)
		}
		otherID := strings.Repeat("b", 64)
		if _, err = db.ExecContext(ctx, `INSERT INTO global_media_objects(media_id,storage_member_id,object_id,media_path,path_locator,object_kind,size_bytes,etag,state,created_at,updated_at) VALUES(?,?,?,?,?,'lyric',?,'remote','active',12,13)`, otherID, master, otherID, sourcePath, strings.Repeat("9", 64), len(data)); err != nil {
			t.Fatal(err)
		}
		if err = run(); err == nil {
			t.Fatal("different global ID with same lyric path accepted")
		}
		if _, err = db.ExecContext(ctx, `DELETE FROM global_media_objects WHERE media_id=?`, otherID); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "audio-default" {
		defaultFile := filepath.Join(mediaPath, "lyrics", "default.lrc")
		if err = os.WriteFile(defaultFile, []byte("wrong"), 0600); err != nil {
			t.Fatal(err)
		}
		if err = run(); err == nil {
			t.Fatal("corrupt default lyric accepted")
		}
		if err = os.WriteFile(defaultFile, []byte(sourceauth.DefaultLyricContent), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(defaultFile, defaultFile+".held"); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink("default.lrc.held", defaultFile); err != nil {
			t.Fatal(err)
		}
		if err = run(); err == nil {
			t.Fatal("symlink default lyric accepted")
		}
		if err = os.Remove(defaultFile); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(defaultFile+".held", defaultFile); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "audio-none" {
		defaultID := strings.Repeat("6", 64)
		if _, err = db.ExecContext(ctx, `INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'lyric','lyrics/default.lrc',?,'created','updated')`, defaultID, localLegacyLocator("lyrics/default.lrc")); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO media_lyric_links(media_id,media_path,lyric_id,lyric_path,created_at,updated_at) VALUES(?,?,?,'lyrics/default.lrc','created','updated')`, videoID, sourcePath, defaultID); err != nil {
			t.Fatal(err)
		}
		if err = run(); err == nil {
			t.Fatal("unverified default lyric accepted")
		}
		if _, err = db.ExecContext(ctx, `DELETE FROM media_lyric_links WHERE media_id=?`, videoID); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `DELETE FROM media_objects WHERE media_id=?`, defaultID); err != nil {
			t.Fatal(err)
		}
	}
	if err = checkLocalOpaqueStage(mediaRoot, pending.OperationID, pending.BlobID, math.MaxInt64); err == nil {
		t.Fatal("insufficient disk capacity accepted")
	}
	if err = os.Symlink("vido", filepath.Join(mediaPath, "staging")); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("symlink staging directory accepted")
	}
	if err = os.Remove(filepath.Join(mediaPath, "staging")); err != nil {
		t.Fatal(err)
	}
	targetPath, err := BlobPath(pending.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	if err = mediaRoot.MkdirAll(path.Dir(targetPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("untrusted-target", filepath.Join(mediaPath, filepath.FromSlash(targetPath))); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("symlink opaque destination accepted")
	}
	if err = mediaRoot.Remove(targetPath); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE media_visibility SET hidden=0 WHERE relative_path=?`, prefix+"/album"); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("changed inherited visibility accepted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE media_visibility SET hidden=1 WHERE relative_path=?`, prefix+"/album"); err != nil {
		t.Fatal(err)
	}
	if mode == "audio-explicit" {
		if _, err = db.ExecContext(ctx, `UPDATE media_lyric_links SET lyric_path='lyrics/other.lrc' WHERE media_id=?`, videoID); err != nil {
			t.Fatal(err)
		}
		if err = run(); err == nil {
			t.Fatal("changed lyric relation accepted")
		}
		if _, err = db.ExecContext(ctx, `UPDATE media_lyric_links SET lyric_path=? WHERE media_id=?`, lyric.LegacyLyricPath, videoID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(ctx, `UPDATE sealed_tree_owner_fence SET fence_tag=? WHERE singleton=1`, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("wrong Owner fence accepted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE sealed_tree_owner_fence SET fence_tag=? WHERE singleton=1`, binding); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE media_encryption SET file_id=? WHERE object_kind='media' AND object_id=?`, strings.Repeat("a", 32), videoID); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("mismatched file ID accepted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE media_encryption SET file_id=? WHERE object_kind='media' AND object_id=?`, metadata.FileID, videoID); err != nil {
		t.Fatal(err)
	}
	originalName := filepath.Join(mediaPath, filepath.FromSlash(sourcePath))
	movedName := originalName + ".held"
	if err = os.Rename(originalName, movedName); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Base(movedName), originalName); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("symlink source accepted")
	}
	if err = os.Remove(originalName); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(movedName, originalName); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(originalName, bytes.Repeat([]byte{0x77}, len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("mismatched source digest accepted")
	}
	if err = os.WriteFile(originalName, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TRIGGER fail_publish BEFORE INSERT ON sealed_tree_records BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("injected final commit failure accepted")
	}
	old, err := os.ReadFile(filepath.Join(mediaPath, filepath.FromSlash(sourcePath)))
	if err != nil || !bytes.Equal(old, data) {
		t.Fatal("old object lost on failure", err)
	}
	if _, err = db.ExecContext(ctx, `DROP TRIGGER fail_publish`); err != nil {
		t.Fatal(err)
	}
	stage, err := stagePath(pending.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(mediaPath, filepath.FromSlash(stage)), bytes.Repeat([]byte{0x66}, len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("corrupt completed stage accepted")
	}
	if err = os.WriteFile(filepath.Join(mediaPath, filepath.FromSlash(stage)), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = run(); err != nil {
		t.Fatal("resume", err)
	}
	old, err = os.ReadFile(filepath.Join(mediaPath, filepath.FromSlash(sourcePath)))
	if err != nil || !bytes.Equal(old, data) {
		t.Fatal("old object lost on commit", err)
	}
	newPath, err := BlobPath(pending.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := mediaRoot.ReadFile(newPath)
	if err != nil || !bytes.Equal(blob, data) {
		t.Fatal("opaque blob mismatch", err)
	}
	plain, err := gcm.Open(nil, nonce, blob, metadata.ChunkAAD(0))
	if err != nil || !bytes.Equal(plain, plaintext) {
		t.Fatal("original ciphertext no longer decrypts", err)
	}
	gotPlacement, err := s.GetPlacement(ctx, videoID)
	if err != nil || !reflect.DeepEqual(gotPlacement.Encryption, &metadata) {
		t.Fatal("encryption descriptor changed", err)
	}
	got, _, err := s.Get(ctx, videoID)
	if err != nil || got != entry {
		t.Fatal("tree identity changed", err)
	}
	if err = run(); !errors.Is(err, ErrLocalImportReconcile) {
		t.Fatal("completed operation did not require current reconciliation", err)
	}
	recoverObject := func() (PreparedFile, error) {
		return migrateLocalMasterObjectOffline(ctx, gate, dir, dbPath, s, treeRoot, mediaRoot, owner, v, master, videoID)
	}
	resumed, err := recoverObject()
	if err != nil || resumed != pending {
		t.Fatal("committed object did not reconcile to original operation", err)
	}
	if err = os.WriteFile(filepath.Join(mediaPath, filepath.FromSlash(newPath)), bytes.Repeat([]byte{0x44}, len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = recoverObject(); err == nil {
		t.Fatal("changed committed target was accepted")
	}
	if err = os.WriteFile(filepath.Join(mediaPath, filepath.FromSlash(newPath)), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(originalName, bytes.Repeat([]byte{0x55}, len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = recoverObject(); err == nil {
		t.Fatal("changed original source was accepted")
	}
	if err = os.WriteFile(originalName, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE sealed_tree_owner_fence SET fence_tag=? WHERE singleton=1`, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err = recoverObject(); err == nil {
		t.Fatal("changed Owner fence was accepted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE sealed_tree_owner_fence SET fence_tag=? WHERE singleton=1`, binding); err != nil {
		t.Fatal(err)
	}
	var receiptMAC string
	if err = db.QueryRowContext(ctx, `SELECT receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=?`, pending.OperationID).Scan(&receiptMAC); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE sealed_tree_operation_ids SET receipt_mac=? WHERE operation_id=?`, strings.Repeat("0", 64), pending.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err = recoverObject(); err == nil {
		t.Fatal("changed completion receipt was accepted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE sealed_tree_operation_ids SET receipt_mac=? WHERE operation_id=?`, receiptMAC, pending.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err = recoverObject(); err != nil {
		t.Fatal("recovery after restoring valid source and target", err)
	}
	if kind == "audio" {
		actual, _, err := s.GetFacts(ctx, videoID)
		if err != nil || actual.LyricResolution == nil || actual.LyricResolution.Origin != "local" || !reflect.DeepEqual(actual.Lyric, lyric) || !reflect.DeepEqual(actual.InternalDefaultLyric, defaultLyric) {
			t.Fatal("local lyric evidence missing or changed", err)
		}
		lease, err := s.AcquireReadFence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.VerifyCatalogLyricFactsWithLease(ctx, lease, []CatalogItem{{Entry: entry, Facts: actual}}); err != nil {
			lease.Release()
			t.Fatal("local lyric proof rejected", err)
		}
		selection, err := s.SelectLyricForDisplayWithLease(ctx, lease, videoID)
		if err != nil || selection.Origin != "local" || (mode == "audio-explicit" && (selection.BuiltinFallback || selection.ExplicitLyricID != lyric.LyricID)) || (mode != "audio-explicit" && !selection.BuiltinFallback) {
			lease.Release()
			t.Fatal("local lyric selection changed", err)
		}
		actual.LyricResolution.Evidence = strings.Repeat("0", 64)
		if err = s.VerifyCatalogLyricFactsWithLease(ctx, lease, []CatalogItem{{Entry: entry, Facts: actual}}); err == nil {
			lease.Release()
			t.Fatal("tampered lyric proof accepted")
		}
		lease.Release()
		index, err := tree.ObjectIndex(videoID)
		if err != nil {
			t.Fatal(err)
		}
		var newFactsID string
		if err = db.QueryRowContext(ctx, `SELECT encryption_id FROM sealed_tree_facts WHERE object_index=?`, index).Scan(&newFactsID); err != nil || newFactsID == oldFactsID {
			t.Fatal("facts nonce was reused", err)
		}
		var reserved int
		if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id IN (?,?)`, oldFactsID, newFactsID).Scan(&reserved); err != nil || reserved != 2 {
			t.Fatal("facts nonce tombstones missing", err)
		}
	}
	var oldPath, oldDescriptor string
	oldQuery := `SELECT media_path FROM global_media_objects WHERE media_id=?`
	if kind == "lyric" {
		oldQuery = `SELECT media_path FROM media_objects WHERE media_id=?`
	}
	if err = db.QueryRowContext(ctx, oldQuery, videoID).Scan(&oldPath); err != nil || oldPath != sourcePath {
		t.Fatal("legacy authoritative row changed", err)
	}
	if err = db.QueryRowContext(ctx, `SELECT descriptor_json FROM media_encryption WHERE object_kind='media' AND object_id=?`, videoID).Scan(&oldDescriptor); err != nil || oldDescriptor != string(descriptor) {
		t.Fatal("legacy encryption row changed", err)
	}
}

func TestLocalLegacySourceRejectsReplacedAncestorAndLeaf(t *testing.T) {
	for _, change := range []string{"ancestor", "leaf"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "vido", "album"), 0700); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, "vido", "album", "x.mp4")
			if err := os.WriteFile(name, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			src, err := openLocalLegacySource(root, "vido/album/x.mp4")
			if err != nil {
				t.Fatal(err)
			}
			defer src.Close()
			if change == "ancestor" {
				if err = os.Rename(filepath.Join(dir, "vido", "album"), filepath.Join(dir, "vido", "held")); err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(filepath.Join(dir, "vido", "album"), 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = os.Rename(name, name+".held"); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(name, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err = src.Check(); err == nil {
				t.Fatal("replaced source accepted")
			}
			data, err := io.ReadAll(src.File())
			if err != nil || string(data) != "original" {
				t.Fatal("held source changed", err)
			}
		})
	}
}
