//go:build linux

package business

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

type fixtureLocalDeleteVolume struct {
	prepare func(context.Context, string, sealedtree.Placement) (sealedtree.MasterLocalDeletePrepared, error)
	clear   func(context.Context, string, sealedtree.Placement) error
}

func (v fixtureLocalDeleteVolume) PrepareOpaqueMasterLocalMediaDelete(ctx context.Context, op string, p sealedtree.Placement) (sealedtree.MasterLocalDeletePrepared, error) {
	return v.prepare(ctx, op, p)
}

func (v fixtureLocalDeleteVolume) ClearOpaqueMasterLocalDeletionStage(ctx context.Context, owner store.OwnerControlLease, op string, p sealedtree.Placement, authorize func(context.Context) error) error {
	if owner.Check(ctx) != nil || authorize(ctx) != nil {
		return store.ErrNodeState
	}
	return v.clear(ctx, op, p)
}

type fixtureLocalDeleteProof struct{ result error }

func (*fixtureLocalDeleteProof) Close() error { return nil }

func (p *fixtureLocalDeleteProof) Delete(ctx context.Context, owner store.OwnerControlLease, authorize func(context.Context) error) error {
	if owner.Check(ctx) != nil || authorize(ctx) != nil {
		return store.ErrNodeState
	}
	return p.result
}

func TestSelectedMasterLocalDeletionRequiresCommittedIntentAndAtomicRefund(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rootDir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(rootDir, "business.db"))+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	key, err := sealedtree.New(bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, master := strings.Repeat("a", 64), strings.Repeat("1", 32)
	tree, err := sealedtree.InitializeSQLite(ctx, db, key, rootID)
	if err != nil {
		t.Fatal(err)
	}
	stmts, err := migrations.Statements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range stmts {
		exec(stmt)
	}
	openDir := func(name string) (string, *os.Root) {
		t.Helper()
		dir := filepath.Join(rootDir, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })
		return dir, root
	}
	treeDir, treeRoot := openDir("tree")
	if _, err = sealedtree.InitializeFence(ctx, tree, treeRoot, treeDir); err != nil {
		t.Fatal(err)
	}
	volumeDir, volume := openDir("volume")
	if err = volume.Mkdir(".opaque-aliases", 0700); err != nil {
		t.Fatal(err)
	}
	owner, err := ownerfence.Create(volume, volumeDir, selectedCoordinatorCodec{})
	if err != nil {
		t.Fatal(err)
	}
	r := New(db, "sqlite")
	if err = r.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return owner.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = r.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','https://master.test','fixture-sealed-private',1)`, master)
	root := sealedtree.Entry{ParentID: rootID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "music"}
	album := sealedtree.Entry{ParentID: root.ObjectID, ObjectID: strings.Repeat("3", 64), Kind: "directory", Name: "album"}
	for _, entry := range []sealedtree.Entry{root, album} {
		if err = tree.CreateDirectoryWithFacts(ctx, entry, sealedtree.Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	metadata, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte{9}, int(metadata.CiphertextSize))
	digest := sha256.Sum256(content)
	entry := sealedtree.Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("4", 64), Kind: "audio", Name: "fixture.mp3"}
	p := sealedtree.Placement{ObjectID: entry.ObjectID, NativeObjectID: entry.ObjectID, OwnerID: master, SHA256: hex.EncodeToString(digest[:]),
		Bytes: int64(len(content)), State: "active", Encryption: &metadata}
	prepared, err := tree.PrepareFileWithFreshLocators(ctx, entry, p, sealedtree.Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := sealedtree.NewBlobPublisher(volume)
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at)
		VALUES(?,NULL,'MasterLocal','Local',1,1000,?,3,1000,'online',1,1)`, master, p.Bytes+7)
	used := func() int64 {
		t.Helper()
		var n, reserved int64
		if err := db.QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&n, &reserved); err != nil || reserved != 3 {
			t.Fatal("invalid local accounting", n, reserved, err)
		}
		return n
	}
	runtime := &SelectedUploadRuntime{repo: r, tree: tree, gate: recordingAudioFixtureGate{}}
	admin := strings.Repeat("e", 64)
	target := store.SelectedMediaDeleteTarget{Path: "music/album/fixture.mp3", ResourceID: entry.ObjectID}
	audit := store.AdminAudit{SourceSummary: target.Path, Detail: target.Path}
	item, err := runtime.QueueMasterLocalMediaDeletion(ctx, admin, target, audit)
	if err != nil || item.State != store.SelectedMediaDeletePending || used() != p.Bytes+7 {
		t.Fatal("failed to commit the exact pending intent", item, err)
	}
	read, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, visibleErr := tree.ReadVisibleObjectWithLease(ctx, read, entry.ObjectID)
	read.Release()
	if !errors.Is(visibleErr, sealedtree.ErrRevocationPending) {
		t.Fatal("pending intent did not block new public grants", visibleErr)
	}
	if next, err := runtime.QueueMasterLocalMediaDeletion(ctx, admin, target, audit); err != nil || next != item {
		t.Fatal("lost queue response changed the operation", next, err)
	}
	physical := &fixtureLocalDeleteProof{result: errors.New("volume busy")}
	preparations := 0
	volumeProof := fixtureLocalDeleteVolume{clear: func(_ context.Context, op string, placement sealedtree.Placement) error {
		if op != prepared.OperationID || placement.BlobID != prepared.BlobID {
			t.Fatal("stage cleanup did not use authenticated original publication", op)
		}
		return nil
	}, prepare: func(_ context.Context, op string, placement sealedtree.Placement) (sealedtree.MasterLocalDeletePrepared, error) {
		preparations++
		if op != item.OperationID || placement.BlobID != prepared.BlobID || placement.ObjectID != entry.ObjectID || placement.Encryption == nil || *placement.Encryption != metadata {
			t.Fatal("wrong prepared placement", op)
		}
		return physical, nil
	}}
	if err = runtime.AdvanceMasterLocalMediaDeletion(ctx, admin, item, audit, volumeProof); !errors.Is(err, physical.result) || used() != p.Bytes+7 {
		t.Fatal("failed physical proof changed quota", err)
	}
	physical.result = nil
	exec(`CREATE TRIGGER refuse_local_delete_audit BEFORE INSERT ON admin_audit_log WHEN NEW.action='opaque-media-delete' BEGIN SELECT RAISE(ABORT,'fixture'); END`)
	if err = runtime.AdvanceMasterLocalMediaDeletion(ctx, admin, item, audit, volumeProof); err == nil || used() != p.Bytes+7 {
		t.Fatal("catalog/refund committed without an audit", err)
	}
	exec(`DROP TRIGGER refuse_local_delete_audit`)
	if err = runtime.AdvanceMasterLocalMediaDeletion(ctx, admin, item, audit, volumeProof); err != nil || used() != 7 {
		t.Fatal("retry did not settle quota and catalog", err)
	}
	if err = runtime.AdvanceMasterLocalMediaDeletion(ctx, admin, item, audit, volumeProof); err != nil || preparations != 3 || used() != 7 {
		t.Fatal("completed operation repeated physical mutation or accounting", preparations, err)
	}
	if done, err := runtime.QueueMasterLocalMediaDeletion(ctx, admin, target, audit); err != nil || done.OperationID != item.OperationID || done.State != store.SelectedMediaDeleteDeleted {
		t.Fatal("lost success response did not resume the same operation", done, err)
	}
	if _, _, err = tree.GetFacts(ctx, entry.ObjectID); err == nil {
		t.Fatal("deleted object remains in the catalog")
	}
	var audits int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_audit_log WHERE action='opaque-media-delete' AND (source_summary IS NULL OR source_summary='') AND (detail IS NULL OR detail='')`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("expected one redacted success audit", audits, err)
	}
}
