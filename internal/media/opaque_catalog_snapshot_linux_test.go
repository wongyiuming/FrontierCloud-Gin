//go:build linux

package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	_ "modernc.org/sqlite"
)

// The callback is a synthetic authorization fixture. No runtime route uses
// this experiment; real catalog completeness and authorization remain gates.
func TestOpaqueCatalogSnapshotSortScopeAndFences(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, musicID, albumID := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, db, codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := sealedtree.InitializeFence(ctx, tree, root, dir); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []sealedtree.Entry{{ParentID: rootID, ObjectID: musicID, Kind: "directory", Name: "music"}, {ParentID: musicID, ObjectID: albumID, Kind: "directory", Name: "album"}} {
		if err := tree.CreateDirectoryWithFacts(ctx, entry, sealedtree.Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	pub, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(nil)
	for i, name := range []string{"z.mp3", "a.mp3", "hidden.mp3"} {
		id := fmt.Sprintf("%064x", i+10)
		entry := sealedtree.Entry{ParentID: albumID, ObjectID: id, Kind: "audio", Name: name}
		facts := sealedtree.Facts{ObjectID: id}
		if i == 2 {
			facts.Visibility = &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}
		}
		placement := sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: strings.Repeat("f", 32), Bytes: 0, ETag: `"fixture"`, SHA256: hex.EncodeToString(digest[:]), State: "active"}
		prepared, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, facts)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(nil)); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ctx, err = network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: strings.Repeat("d", 32), Generation: 1, PublicOrigin: "https://entry.test", ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, admission := network.WithPublicAdmission(ctx)
	defer admission.Abort()
	ctx = store.WithIngressPrerequisite(ctx, lease)
	authorize := func(_ context.Context, object sealedtree.ListingObject) (store.GlobalMedia, string, error) {
		p := object.Placement
		preference := 0
		if object.Entry.Name == "z.mp3" {
			preference = 5
		}
		return store.GlobalMedia{ID: object.Entry.ObjectID, ObjectID: p.NativeObjectID, MemberID: p.OwnerID, Path: object.Path, Kind: object.Entry.Kind, Bytes: p.Bytes, ETag: p.ETag, State: "active", Transport: "Direct", PlaybackStats: store.PlaybackStats{Preference: preference}}, "synthetic-handle", nil
	}
	items, err := collectOpaqueCatalog(ctx, tree, lease, "music/album", "music", false, opaqueCatalogMemoryBudget, authorize)
	if err != nil || len(items) != 2 || items[0].MediaPath != "music/album/z.mp3" || items[1].MediaPath != "music/album/a.mp3" || !items[0].NativeSource || items[0].SourceIdentityVersion != 1 || items[1].SourceIdentityVersion != 1 {
		t.Fatal("visible order", items, err)
	}
	items, err = collectOpaqueCatalog(ctx, tree, lease, "music/album", "music", true, opaqueCatalogMemoryBudget, authorize)
	if err != nil || len(items) != 3 || items[2].MediaPath != "music/album/hidden.mp3" {
		t.Fatal("explicit hidden scope", items, err)
	}
	if items, err = collectOpaqueCatalog(ctx, tree, lease, "music/album", "music", true, 1, authorize); !errors.Is(err, errOpaqueCatalogBudget) || items != nil {
		t.Fatal("budget returned partial catalog", items, err)
	}
	bad := func(c context.Context, object sealedtree.ListingObject) (store.GlobalMedia, string, error) {
		row, handle, err := authorize(c, object)
		row.Bytes++
		return row, handle, err
	}
	if items, err = collectOpaqueCatalog(ctx, tree, lease, "music/album", "music", false, opaqueCatalogMemoryBudget, bad); err == nil || items != nil {
		t.Fatal("placement mismatch accepted", items, err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if items, err = collectOpaqueCatalog(cancelled, tree, lease, "music/album", "music", false, opaqueCatalogMemoryBudget, authorize); err == nil || items != nil {
		t.Fatal("cancelled catalog returned", items, err)
	}
	lease.Release()
	if items, err = collectOpaqueCatalog(ctx, tree, lease, "music/album", "music", false, opaqueCatalogMemoryBudget, authorize); err == nil || items != nil {
		t.Fatal("released tree lease accepted", items, err)
	}
}

// This fixture exercises the real business repository and tree together, but
// remains synthetic: it does not prove migration completeness or authorize
// mounting the product route. Setup is excluded from the measured interval.
func exerciseOpaqueCatalogWithLegacy(t *testing.T, count int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	_, business, service := masterFixture(t)
	identity, err := service.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "catalog-tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, musicID, parentID := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, db, codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := sealedtree.InitializeFence(ctx, tree, root, dir); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []sealedtree.Entry{{ParentID: rootID, ObjectID: musicID, Kind: "directory", Name: "music"}, {ParentID: musicID, ObjectID: parentID, Kind: "directory", Name: "benchmark"}} {
		if err := tree.CreateDirectoryWithFacts(ctx, entry, sealedtree.Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	publisher, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := business.Database().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	digest := sha256.Sum256(nil)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("%064x", 100000+i)
		name := fmt.Sprintf("song-%06d.mp3", i)
		file := "music/benchmark/" + name
		locator := sha256.Sum256([]byte(file))
		preference, score := i%11-5, int64(i)
		if _, err := tx.ExecContext(ctx, `INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'audio',?,?,?,?)`, id, file, hex.EncodeToString(locator[:]), "2026-01-01", "2026-01-01"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO global_media_objects(media_id,storage_member_id,object_id,media_path,path_locator,object_kind,size_bytes,etag,state,created_at,updated_at) VALUES(?,?,?,?,?,'audio',0,?,'active',1,1)`, id, identity.ID, id, file, hex.EncodeToString(locator[:]), `"fixture"`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO media_playback_stats(media_id,media_path,play_score,preference,created_at,updated_at) VALUES(?,?,?,?,?,?)`, id, file, score, preference, "2026-01-01", "2026-01-01"); err != nil {
			t.Fatal(err)
		}
		entry := sealedtree.Entry{ParentID: parentID, ObjectID: id, Kind: "audio", Name: name}
		facts := sealedtree.Facts{ObjectID: id, Playback: &sealedtree.PlaybackFact{LegacyMediaPath: file, PlayScore: score, Preference: int64(preference), CreatedAt: "2026-01-01", UpdatedAt: "2026-01-01"}}
		placement := sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: identity.ID, Bytes: 0, ETag: `"fixture"`, SHA256: hex.EncodeToString(digest[:]), State: "active"}
		prepared, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, facts)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(nil)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	leaseStarted := time.Now()
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	current, ingressLease, err := business.Nodes().(store.PublicRoutingRepository).AcquireCurrentIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ingressLease.Release()
	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer readCancel()
	readCtx, admission := network.WithPublicAdmission(readCtx)
	defer admission.Abort()
	readCtx, err = network.WithLocalPublicIngress(readCtx, network.LocalPublicIngress{NodeID: current.NodeID, Generation: current.Generation, PublicOrigin: current.PublicOrigin})
	if err != nil {
		t.Fatal(err)
	}
	readCtx = store.WithIngressPrerequisite(readCtx, lease)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	items, err := collectOpaqueCatalog(readCtx, tree, lease, "music/benchmark", "music", false, opaqueCatalogMemoryBudget, service.authorizeOpaqueCatalogListing)
	elapsed := time.Since(started)
	runtime.ReadMemStats(&after)
	if err != nil || len(items) != count {
		t.Fatal("full real-repository catalog", len(items), count, err)
	}
	for i := 1; i < len(items); i++ {
		left, right := items[i-1], items[i]
		if left.Preference < right.Preference || left.Preference == right.Preference && left.MediaPath > right.MediaPath {
			t.Fatal("legacy comparator changed", i)
		}
	}
	if err := ingressLease.Commit(); err != nil || !admission.Commit() {
		t.Fatal("catalog admission", err)
	}
	lease.Release()
	t.Logf("catalog rows=%d collect=%s tree-lease-total=%s total-allocated=%d heap-before=%d heap-after=%d", count, elapsed, time.Since(leaseStarted), after.TotalAlloc-before.TotalAlloc, before.HeapAlloc, after.HeapAlloc)
}

func TestOpaqueCatalogSnapshotRealLegacyRepository(t *testing.T) {
	exerciseOpaqueCatalogWithLegacy(t, 3)
}

func TestOpaqueCatalogSnapshot2631RealLegacyRepository(t *testing.T) {
	if os.Getenv("FC_CATALOG_LARGE") != "1" {
		t.Skip("explicit isolated large-catalog fixture required")
	}
	exerciseOpaqueCatalogWithLegacy(t, 2631)
}
