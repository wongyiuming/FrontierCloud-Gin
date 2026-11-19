//go:build linux && ledger_fixture

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestRetainedTreeRuntimeVerifiesLocalAfterRebind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	paths := retainedTreeTestMounts(t)
	id, err := sealedtree.FixtureTreeCaptureMaster(ctx, paths[0], paths[1])
	if err != nil {
		t.Fatal(err)
	}
	blob, body := retainedLocalOwnerFixture(t, ctx, paths, id)
	gate, err := maintenance.OpenExisting(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	archiveDir := filepath.Join(filepath.Dir(paths[0]), "private-archive")
	if err := os.Mkdir(archiveDir, 0700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(archiveDir, "source.tar")
	selection := append([]string{"db.sqlite", "db.sqlite-wal", "db.sqlite-shm", maintenance.Marker, ".native-runtime.lock", ".native-maintenance-control.lock"}, sealedtree.MasterStatePaths()...)
	sources := []recovery.Root{{Class: "data", Directory: paths[0], IncludePaths: selection}, {Class: "runtime_secrets", Directory: paths[1]}}
	m := recovery.Manifest{NodeID: id, Role: "Master", Revision: strings.Repeat("d", 40), Database: "sqlite", Scope: recovery.UpgradeStateScope,
		SchemaGeneration: migrations.Generation, Consistency: "native-offline-and-deployment-writers-stopped", KeyReferences: []string{"runtime_secrets/node-vault.key", "runtime_secrets/" + sealedtree.MasterKeyFile}}
	archived, err := sealedtree.CreateMasterTreeBackupStaged(ctx, gate, paths[0], filepath.Join(paths[0], "db.sqlite"), paths[1], archive, m, sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	binding := strings.Repeat("b", 64)
	if err := gate.HoldTreeRecovery(ctx, binding); err != nil {
		t.Fatal(err)
	}
	request := runtimefacts.TreeRetainedRecoveryRequest{Action: "verify-local", Nonce: strings.Repeat("a", 64), BindingSHA256: binding,
		DatabaseRelative: "db.sqlite", NodeID: id, ArchiveSHA256: archived.SHA256, Manifest: &archived.Manifest}
	call := func(r runtimefacts.TreeRetainedRecoveryRequest, out io.Writer) error {
		commit := runtimefacts.TreeRetainedRecoveryCommit{Nonce: r.Nonce, BindingSHA256: r.BindingSHA256}
		return treeRetainedRecovery(ctx, retainedTreeTestFrames(t, r, commit), out, paths)
	}
	if err := call(request, io.Discard); err == nil {
		t.Fatal("proof accepted before rebind intent")
	}
	rebind := request
	rebind.Action = "rebind"
	if err := call(rebind, io.Discard); err != nil {
		t.Fatal("rebind", err)
	}
	var output bytes.Buffer
	if err := call(request, &output); err != nil {
		t.Fatal("verify installed Master", err)
	}
	if strings.Contains(output.String(), filepath.Base(blob)) || strings.Contains(output.String(), "fixture.mp3") {
		t.Fatal("local reply exposed a locator")
	}
	proof := retainedTreeTestReplies(t, request, &output).Local
	if proof == nil || !proof.Valid() || proof.Media != 1 || proof.Recordings != 0 || proof.LocalObjects != 1 || proof.LocalBytes != int64(len(body)) || proof.FollowerOwners != 0 || proof.S3Owners != 0 {
		t.Fatalf("unexpected local proof: %+v", proof)
	}
	wrong := request
	wrong.ArchiveSHA256 = strings.Repeat("f", 64)
	if err := call(wrong, io.Discard); err == nil {
		t.Fatal("different archive accepted")
	}
	if err := os.WriteFile(blob, bytes.Repeat([]byte{0x66}, len(body)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := call(request, io.Discard); err == nil {
		t.Fatal("same-size corrupted ciphertext accepted")
	}
	if err := os.WriteFile(blob, body, 0600); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(paths[0], ".native-runtime.lock")
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := call(request, io.Discard); err == nil {
		t.Fatal("verification created a missing native lock")
	}
	if _, err := os.Lstat(lock); !os.IsNotExist(err) {
		t.Fatal("verification recreated a missing native lock", err)
	}
	if held, err := gate.TreeRecoveryHeld(); err != nil || !held {
		t.Fatal("verification removed recovery hold", err)
	}
}

func retainedLocalOwnerFixture(t *testing.T, ctx context.Context, paths [2]string, id string) (string, []byte) {
	t.Helper()
	mediaRoot := filepath.Join(paths[0], "media")
	if err := os.MkdirAll(filepath.Join(mediaRoot, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mediaRoot, ".media-mutation.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(mediaRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	db, err := sqlitestore.OpenExisting(ctx, filepath.Join(paths[0], "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := db.Nodes().(*business.Repository)
	identity, err := node.OpenExisting(ctx, repo, paths[1])
	if err != nil {
		t.Fatal(err)
	}
	fence, err := ownerfence.Create(root, mediaRoot, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	tree, closeTree, err := sealedtree.OpenMasterSQLite(ctx, db.Database(), paths[0], paths[1], id)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTree()
	key, err := tree.CapacityKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if err := repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(128)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte{0x57}, int(meta.CiphertextSize))
	entry := sealedtree.Entry{ParentID: strings.Repeat("c", 64), ObjectID: strings.Repeat("1", 64), Kind: "audio", Name: "fixture.mp3"}
	placement := sealedtree.Placement{ObjectID: entry.ObjectID, NativeObjectID: entry.ObjectID, OwnerID: id, Bytes: int64(len(body)), SHA256: fmt.Sprintf("%x", sha256.Sum256(body)), State: "active", Encryption: &meta}
	pending, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, sealedtree.Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.PublishPending(ctx, pending.OperationID, pub, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	// The generic fixture publisher keeps its staging hard link. Model a
	// settled Owner by unlinking that fixture stage after publication commits.
	if err := root.Remove(filepath.Join("staging", pending.OperationID+".part")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().ExecContext(ctx, `INSERT INTO cluster_storage_members VALUES(?,NULL,'MasterLocal','Local',1,?,?,0,0,'online',1,1)`, id, store.GiB, len(body)); err != nil {
		t.Fatal(err)
	}
	blob, err := sealedtree.BlobPath(pending.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(mediaRoot, filepath.FromSlash(blob)), body
}
