//go:build linux

package checkpoint

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestBusinessPointRestoresActualSQLiteAndEncryptedTree(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	db, e := sqlitestore.Open(filepath.Join(base, "live.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	codec, e := sealedtree.New(bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{9}, 32))
	if e != nil {
		t.Fatal(e)
	}
	tree, e := sealedtree.InitializeSQLite(ctx, db.Database(), codec, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	statements, e := migrations.Statements("sqlite")
	if e != nil {
		t.Fatal(e)
	}
	for _, statement := range statements {
		if _, e = db.Database().ExecContext(ctx, statement); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = db.Database().Exec(`INSERT INTO frontiercloud_schema(singleton,generation,created_at) VALUES(1,?,1)`, migrations.Generation); e != nil {
		t.Fatal(e)
	}
	master := strings.Repeat("1", 32)
	if _, e = db.Database().Exec(`INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','https://master.invalid','sealed-fixture',1)`, master); e != nil {
		t.Fatal(e)
	}
	fenceDir := filepath.Join(base, "fence")
	if e = os.Mkdir(fenceDir, 0700); e != nil {
		t.Fatal(e)
	}
	fenceRoot, e := os.OpenRoot(fenceDir)
	if e != nil {
		t.Fatal(e)
	}
	defer fenceRoot.Close()
	if _, e = sealedtree.InitializeFence(ctx, tree, fenceRoot, fenceDir); e != nil {
		t.Fatal(e)
	}
	media := filepath.Join(base, "media")
	scratch := filepath.Join(base, "scratch")
	os.Mkdir(media, 0700)
	os.Mkdir(scratch, 0700)
	dir := sealedtree.Entry{ParentID: strings.Repeat("a", 64), ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "private lyrics"}
	if e = tree.CreateDirectoryWithFacts(ctx, dir, sealedtree.Facts{ObjectID: dir.ObjectID}); e != nil {
		t.Fatal(e)
	}

	plain := []byte("[00:01.00] recover this lyric")
	meta, e := mediacrypto.NewMetadata(int64(len(plain)))
	if e != nil {
		t.Fatal(e)
	}
	manager, e := mediacrypto.New(bytes.Repeat([]byte{4}, 32))
	if e != nil {
		t.Fatal(e)
	}
	fileKey, e := manager.FileKey(meta)
	if e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(fileKey)
	if e != nil {
		t.Fatal(e)
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	n, e := meta.ChunkNonce(0)
	if e != nil {
		t.Fatal(e)
	}
	encrypted := aead.Seal(nil, n, plain, meta.ChunkAAD(0))
	digest := sha256.Sum256(encrypted)
	object, _ := sealedtree.NewBlobID()
	native, _ := sealedtree.NewBlobID()
	placement := sealedtree.Placement{ObjectID: object, NativeObjectID: native, OwnerID: master, Bytes: int64(len(encrypted)), SHA256: hex.EncodeToString(digest[:]), State: "active", Encryption: &meta}
	entry := sealedtree.Entry{ParentID: dir.ObjectID, ObjectID: object, Kind: "lyric", Name: "hidden-song.lrc"}
	pending, e := tree.PrepareFileWithFreshLocators(ctx, entry, placement, sealedtree.Facts{ObjectID: object, Visibility: &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "fixture"}})
	if e != nil {
		t.Fatal(e)
	}
	mediaRoot, e := os.OpenRoot(media)
	if e != nil {
		t.Fatal(e)
	}
	defer mediaRoot.Close()
	publisher, e := sealedtree.NewBlobPublisher(mediaRoot)
	if e != nil {
		t.Fatal(e)
	}
	if e = tree.PublishPending(ctx, pending.OperationID, publisher, bytes.NewReader(encrypted)); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Database().Exec(`INSERT INTO ip_permanent_whitelist(ip_address,created_at,created_by_session_hash,note) VALUES('198.51.100.7','2026-11-12','fixture','high-value policy')`); e != nil {
		t.Fatal(e)
	}
	src := Source{DB: db.Database(), Tree: tree, Vault: codecVault(t, 3), MediaRoot: media, Scratch: scratch, MasterID: master}
	logbook, e := logarchive.SharedCatalog(db.Database(), src.Vault, master)
	if e != nil {
		t.Fatal(e)
	}
	logTarget := logarchive.Target{MemberID: strings.Repeat("2", 32), RelationshipID: strings.Repeat("3", 32), Origin: "https://logs.invalid"}
	if _, e = logbook.Configure(ctx, logTarget, 0); e != nil {
		t.Fatal(e)
	}
	logTime := time.Now()
	if e = logbook.Append(ctx, logarchive.Audit, logTime, []byte(`{"message":"checkpoint-log-private"}`)); e != nil {
		t.Fatal(e)
	}
	if e = logbook.QueueCapture(ctx, logarchive.Access, logTime, logTime.Add(time.Millisecond), []byte(`[{"message":"checkpoint-pending-private"}]`)); e != nil {
		t.Fatal(e)
	}
	logPublic, e := logbook.IngestPublic(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var output bytes.Buffer
	if e = src.Write(ctx, 17, &output); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(output.Bytes(), []byte("SQLite format")) || bytes.Contains(output.Bytes(), []byte("private lyrics")) {
		t.Fatal("unencrypted state escaped")
	}
	sum := sha256.Sum256(output.Bytes())
	target := filepath.Join(base, "restore")
	if _, e = Restore(ctx, bytes.NewReader(output.Bytes()), hex.EncodeToString(sum[:]), int64(output.Len()), src.Vault, master, 17, target, func(c context.Context, d *sql.DB) error {
		if err := tree.ValidateCheckpointDatabase(c, d); err != nil {
			return err
		}
		return tree.ValidateCheckpointLyrics(c, d, filepath.Join(target, "media"), master)
	}); e != nil {
		t.Fatal(e)
	}
	restored, e := sqlitestore.OpenReadOnly(ctx, filepath.Join(target, "database.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	recoveredLogs, e := logarchive.ExistingCatalog(restored.Database(), src.Vault, master)
	if e != nil {
		t.Fatal(e)
	}
	recoveredConfig, e := recoveredLogs.Configuration(ctx)
	if e != nil || recoveredConfig.Target != logTarget {
		t.Fatal("business recovery lost log destination", e)
	}
	recoveredPublic, e := recoveredLogs.IngestPublic(ctx)
	if e != nil || !bytes.Equal(recoveredPublic, logPublic) {
		t.Fatal("business recovery lost log ingest authority", e)
	}
	logNow := time.Now().Add(time.Millisecond)
	logEntries, _, e := recoveredLogs.Query(ctx, logTime.Add(-time.Minute), logNow, logNow, logarchive.Audit, false, "")
	if e != nil || len(logEntries) != 1 {
		t.Fatal("business recovery lost log manifest", e)
	}
	logEntry, e := recoveredLogs.Entry(ctx, logEntries[0].Record.Header.ID)
	if e != nil {
		t.Fatal(e)
	}
	logPlain, e := logarchive.OpenForMaster(src.Vault, logEntry.Record, logEntry.Ciphertext)
	if e != nil || !bytes.Contains(logPlain, []byte("checkpoint-log-private")) {
		t.Fatal("business recovery lost usable log key", e)
	}
	logPending, e := recoveredLogs.PendingForMaster(ctx, logarchive.Access)
	if e != nil || len(logPending) != 1 {
		t.Fatal("business recovery lost encrypted log capture buffer", e)
	}
	copy, e := sealedtree.OpenSQLite(ctx, restored.Database(), codec, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	got, _, e := copy.Get(ctx, dir.ObjectID)
	if e != nil || got.Name != "private lyrics" {
		t.Fatal("restored encrypted business read", e)
	}

	restoredFacts, _, err := copy.GetFacts(ctx, object)
	if err != nil || restoredFacts.Visibility == nil || restoredFacts.Visibility.Hidden != 1 {
		t.Fatal("hidden lyric facts lost", err)
	}
	blobPath, e := sealedtree.BlobPath(pending.BlobID)
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := os.ReadFile(filepath.Join(target, "media", filepath.FromSlash(blobPath)))
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := aead.Open(nil, n, recovered, meta.ChunkAAD(0))
	if e != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("actual encrypted lyric failed after restore", e)
	}
	var note string
	if e = restored.Database().QueryRow(`SELECT note FROM ip_permanent_whitelist WHERE ip_address='198.51.100.7'`).Scan(&note); e != nil || note != "high-value policy" {
		t.Fatal("business security policy lost", e)
	}
	if _, e = Restore(ctx, bytes.NewReader(output.Bytes()), hex.EncodeToString(sum[:]), int64(output.Len()), src.Vault, master, 17, target, func(c context.Context, d *sql.DB) error {
		if err := tree.ValidateCheckpointDatabase(c, d); err != nil {
			return err
		}
		return tree.ValidateCheckpointLyrics(c, d, filepath.Join(target, "media"), master)
	}); e == nil {
		t.Fatal("occupied target accepted")
	}
	badTarget := filepath.Join(base, "bad")
	if _, e = Restore(ctx, bytes.NewReader(output.Bytes()), strings.Repeat("0", 64), int64(output.Len()), src.Vault, master, 17, badTarget, tree.ValidateCheckpointDatabase); e == nil {
		t.Fatal("bad digest accepted")
	}
	if _, e = os.Stat(badTarget); !os.IsNotExist(e) {
		t.Fatal("failed restore published files")
	}
}
