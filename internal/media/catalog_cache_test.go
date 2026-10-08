package media

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud/internal/node"
	"github.com/wongyiuming/FrontierCloud/internal/store"
)

type countedCatalogRepository struct {
	store.MediaRepository
	generation catalogGeneration
	hidden     atomic.Int64
}

type countedCatalogPool struct {
	store.PoolRepository
	reads atomic.Int64
}

func (r *countedCatalogPool) Resources(ctx context.Context, prefix string, recursive bool) ([]store.GlobalMedia, error) {
	r.reads.Add(1)
	return r.PoolRepository.Resources(ctx, prefix, recursive)
}

type followerCatalogRole struct{ store.NodeRepository }

func (r followerCatalogRole) ReadIdentity(ctx context.Context) (store.NodeIdentity, error) {
	value, err := r.NodeRepository.ReadIdentity(ctx)
	value.Role = "Follower"
	return value, err
}

func TestMasterCatalogCacheSQLFactsFreshRoleAndRecoveryFence(t *testing.T) {
	_, db, svc := masterFixture(t)
	ctx := context.Background()
	pool := &countedCatalogPool{PoolRepository: db.Pool()}
	svc.pool = pool
	svc.ConfigureCatalogCache(time.Minute)
	for range 2 {
		tracks, err := svc.Catalog(ctx, "music", "music/artist", "session-a", false)
		if err != nil || len(tracks) != 1 {
			t.Fatal(tracks, err)
		}
	}
	before := pool.reads.Load()
	tracks, err := svc.Catalog(ctx, "music", "music/artist", "session-b", false)
	if err != nil || len(tracks) != 1 || pool.reads.Load() != before {
		t.Fatal("Master cache repeated catalog SQL", tracks, err)
	}
	object := store.MediaObject{Path: "music/artist/song.mp3", Kind: "audio"}
	if _, err := db.Media().SetPreference(ctx, object, 77, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	tracks, err = svc.Catalog(ctx, "music", "music/artist", "session-a", false)
	if err != nil || len(tracks) != 1 || tracks[0].Preference != 77 {
		t.Fatal("stale Master playback preference", tracks, err)
	}
	if err := db.Media().SetHidden(ctx, []string{object.Path}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	tracks, err = svc.Catalog(ctx, "music", "music/artist", "session-a", false)
	if err != nil || len(tracks) != 0 {
		t.Fatal("Master hidden cache leak", tracks, err)
	}
	tracks, err = svc.Catalog(ctx, "music", "music/artist", "session-a", true)
	if err != nil || len(tracks) != 1 {
		t.Fatal("Master Admin/public scope collision", tracks, err)
	}
	svc.nodes = followerCatalogRole{db.Nodes()}
	tracks, err = svc.Catalog(ctx, "music", "music/artist", "session-a", true)
	if !errors.Is(err, ErrCategory) || len(tracks) != 0 {
		t.Fatal("cached data bypassed fresh role", tracks, err)
	}
	svc.nodes = db.Nodes()
	svc.recoveryRequired = true
	if _, err := svc.Catalog(ctx, "music", "music/artist", "session-a", true); !errors.Is(err, ErrRecovery) {
		t.Fatal("cache bypassed recovery fence", err)
	}
}

func (r *countedCatalogRepository) CatalogGeneration() uint64 {
	return r.generation.CatalogGeneration()
}
func (r *countedCatalogRepository) HiddenPaths(ctx context.Context) (map[string]bool, error) {
	r.hidden.Add(1)
	return r.MediaRepository.HiddenPaths(ctx)
}

func TestCatalogCacheHitSkipsCatalogQueriesAndFilesystemScan(t *testing.T) {
	root, db, svc := deleteFixture(t)
	ctx := context.Background()
	identity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	svc.identity = identity
	name := "music/cache/track.mp3"
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name), []byte("ID3fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	repo := db.Media()
	counted := &countedCatalogRepository{MediaRepository: repo, generation: repo.(catalogGeneration)}
	svc.repository = counted
	svc.ConfigureCatalogCache(time.Minute)
	// The first catalog registers IDs; only a subsequent stable read may fill.
	for range 2 {
		if _, err := svc.Catalog(ctx, "music", "music/cache", "a", false); err != nil {
			t.Fatal(err)
		}
	}
	before := counted.hidden.Load()
	// This intentional fixture-only rename proves a hit does not scan disk.
	if err := os.Rename(filepath.Join(root, "music/cache"), filepath.Join(root, "music/held")); err != nil {
		t.Fatal(err)
	}
	tracks, err := svc.Catalog(ctx, "music", "music/cache", "b", false)
	if err != nil || len(tracks) != 1 || counted.hidden.Load() != before {
		t.Fatal("cache missed", tracks, err, counted.hidden.Load(), before)
	}
	*tracks[0].HasLyrics = false
	tracks[0].Title = "mutated caller"
	tracks, err = svc.Catalog(ctx, "music", "music/cache", "a", false)
	if err != nil || tracks[0].Title == "mutated caller" || !*tracks[0].HasLyrics {
		t.Fatal("cache escaped mutable references", tracks, err)
	}
	if err := os.Rename(filepath.Join(root, "music/held"), filepath.Join(root, "music/cache")); err != nil {
		t.Fatal(err)
	}
	// A mutation through another domain handle shares the same generation.
	if err := db.Media().SetHidden(ctx, []string{name}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	tracks, err = svc.Catalog(ctx, "music", "music/cache", "a", false)
	if err != nil || len(tracks) != 0 {
		t.Fatal("hidden content leaked from stale cache", tracks, err)
	}
	tracks, err = svc.Catalog(ctx, "music", "music/cache", "a", true)
	if err != nil || len(tracks) != 1 {
		t.Fatal("public and Admin scope collision", tracks, err)
	}
}

func TestCatalogCacheBoundsTTLFailureAndCancellation(t *testing.T) {
	_, db, svc := deleteFixture(t)
	svc.ConfigureCatalogCache(time.Minute)
	ctx := context.Background()
	var fills atomic.Int64
	build := func() (catalogEntry, error) {
		fills.Add(1)
		return catalogEntry{categories: []Category{{"name", "url"}}}, nil
	}
	for range 3 {
		if _, err := svc.cachedCatalog(ctx, "same", build); err != nil {
			t.Fatal(err)
		}
	}
	if fills.Load() != 1 {
		t.Fatal("stable miss not coalesced", fills.Load())
	}
	for i := 0; i < 100; i++ {
		if _, err := svc.cachedCatalog(ctx, fmt.Sprint(i), build); err != nil {
			t.Fatal(err)
		}
	}
	if len(svc.catalog.entries) > catalogMaxEntries || svc.catalog.bytes > catalogMaxBytes {
		t.Fatal("unbounded cache")
	}
	bad := errors.New("not cacheable")
	for range 2 {
		if _, err := svc.cachedCatalog(ctx, "failed", func() (catalogEntry, error) { return catalogEntry{}, bad }); !errors.Is(err, bad) {
			t.Fatal(err)
		}
	}
	if _, ok := svc.catalog.entries["failed"]; ok {
		t.Fatal("error cached")
	}
	svc.catalog.mu.Lock()
	svc.catalog.building = make(chan struct{})
	svc.catalog.mu.Unlock()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.cachedCatalog(cancelled, "new", build); !errors.Is(err, context.Canceled) {
		t.Fatal("wait ignored cancellation", err)
	}
	svc.catalog.mu.Lock()
	close(svc.catalog.building)
	svc.catalog.building = nil
	svc.catalog.mu.Unlock()
	svc.ConfigureCatalogCache(time.Nanosecond)
	beforeFills := fills.Load()
	for range 2 {
		if _, err := svc.cachedCatalog(ctx, "ttl", build); err != nil {
			t.Fatal(err)
		}
	}
	if fills.Load() != beforeFills+2 {
		t.Fatal("expired entry reused")
	}
	// Successful writes invalidate, failed transactions never publish a revision.
	g := db.Media().(catalogGeneration)
	before := g.CatalogGeneration()
	if err := db.Media().SetHidden(ctx, []string{"music/new/track.mp3"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if g.CatalogGeneration() <= before {
		t.Fatal("SQL mutation omitted invalidation")
	}
}

func TestCatalogCacheBytesOversizeUnknownStoreAndPanicRelease(t *testing.T) {
	_, db, svc := deleteFixture(t)
	svc.ConfigureCatalogCache(time.Minute)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		_, err := svc.cachedCatalog(ctx, fmt.Sprint(i), func() (catalogEntry, error) {
			return catalogEntry{categories: []Category{{Name: strings.Repeat("x", catalogMaxEntryBytes/2)}}}, nil
		})
		if err != nil || svc.catalog.bytes > catalogMaxBytes {
			t.Fatal("byte bound exceeded", err)
		}
	}
	_, err := svc.cachedCatalog(ctx, "oversized", func() (catalogEntry, error) {
		return catalogEntry{categories: []Category{{Name: strings.Repeat("x", catalogMaxEntryBytes)}}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.catalog.entries["oversized"]; ok {
		t.Fatal("oversized entry cached")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("fixture did not panic")
			}
		}()
		_, _ = svc.cachedCatalog(ctx, "panic", func() (catalogEntry, error) { panic("fixture") })
	}()
	if svc.catalog.building != nil {
		t.Fatal("panic stranded cache waiters")
	}
	var calls int
	svc.repository = struct{ store.MediaRepository }{db.Media()}
	for range 2 {
		_, err = svc.cachedCatalog(ctx, "unknown", func() (catalogEntry, error) { calls++; return catalogEntry{}, nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatal("unreliable repository cached")
	}
}

func TestCatalogCacheCategoryHitSkipsQueriesAndRecursiveScan(t *testing.T) {
	root, db, svc := deleteFixture(t)
	ctx := context.Background()
	repo := db.Media()
	counted := &countedCatalogRepository{MediaRepository: repo, generation: repo.(catalogGeneration)}
	svc.repository = counted
	svc.ConfigureCatalogCache(time.Minute)
	items, err := svc.Categories(ctx, "music", false)
	if err != nil || len(items) != 2 {
		t.Fatal(items, err)
	}
	before := counted.hidden.Load()
	if err := os.Rename(filepath.Join(root, "music/artist"), filepath.Join(root, "music/held")); err != nil {
		t.Fatal(err)
	}
	items, err = svc.Categories(ctx, "music", false)
	if err != nil || len(items) != 2 || items[0].Name != "artist" || counted.hidden.Load() != before {
		t.Fatal("category hit scanned", items, err)
	}
}

func TestCatalogCacheConcurrentFillAndRacingCommit(t *testing.T) {
	_, db, svc := deleteFixture(t)
	svc.ConfigureCatalogCache(time.Minute)
	ctx := context.Background()
	var fills atomic.Int64
	start, finish := make(chan struct{}), make(chan struct{})
	build := func() (catalogEntry, error) {
		if fills.Add(1) == 1 {
			close(start)
			<-finish
		}
		return catalogEntry{categories: []Category{{"name", "url"}}}, nil
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := svc.cachedCatalog(ctx, "same", build); err != nil {
				t.Error(err)
			}
		})
	}
	<-start
	if err := db.Media().SetHidden(ctx, []string{"music/race/track.mp3"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	close(finish)
	wg.Wait()
	if fills.Load() != 2 {
		t.Fatal("racing SQL commit cached an old generation", fills.Load())
	}
}

func TestCatalogCacheCategoryPriorityAndFilesystemMutationFence(t *testing.T) {
	_, _, svc := deleteFixture(t)
	ctx := context.Background()
	svc.ConfigureCatalogCache(time.Minute)
	items, err := svc.Categories(ctx, "music", false)
	if err != nil || len(items) != 2 {
		t.Fatal(items, err)
	}
	if _, err := svc.Preference(ctx, "music/other", 80, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	items, err = svc.Categories(ctx, "music", false)
	if err != nil || items[0].Name != "other" {
		t.Fatal("stale directory priority", items, err)
	}
	if err := svc.Hide(ctx, []string{"music/other"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	items, err = svc.Categories(ctx, "music", false)
	if err != nil || len(items) != 1 || items[0].Name != "artist" {
		t.Fatal("hidden category leaked", items, err)
	}
	if len(svc.catalog.entries) == 0 {
		t.Fatal("cache never filled")
	}
	release, err := svc.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if len(svc.catalog.entries) != 0 {
		t.Fatal("filesystem mutation fence did not invalidate")
	}
	svc.ConfigureCatalogCache(0)
	if svc.catalog != nil {
		t.Fatal("cache disable ignored")
	}
}
