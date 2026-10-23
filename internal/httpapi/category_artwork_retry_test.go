package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type deadlineArtworkRepository struct {
	store.MediaRepository
	store.EncryptionBatchRepository
	blocked bool
	queries int
	lastErr error
}

type deadlineArtworkPool struct {
	store.PoolRepository
	blocked bool
	lastErr error
	budget  time.Duration
}

func (p *deadlineArtworkPool) Resources(ctx context.Context, name string, recursive bool) ([]store.GlobalMedia, error) {
	if p.blocked {
		deadline, bounded := ctx.Deadline()
		if !bounded {
			return nil, errors.New("category lookup has no deadline")
		}
		p.budget = time.Until(deadline)
		<-ctx.Done()
		p.lastErr = ctx.Err()
		return nil, p.lastErr
	}
	return p.PoolRepository.Resources(ctx, name, recursive)
}

func TestDirectoryArtworkDeadlineIncludesMasterCategoryLookup(t *testing.T) {
	ctx := context.Background()
	wire := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, db, _, public, master := clusterFixture(t, "https://artwork-master.test", wire, false)
	if _, err := master.Promote(ctx, "Master", "https://artwork-master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	pool := &deadlineArtworkPool{PoolRepository: db.Pool(), blocked: true}
	public.media.ConfigureCluster(db.Nodes(), pool, master)
	target := "/api/v1/media/catalog/artwork?path=music/artist"
	first := request(router, "GET", target, "")
	if !errors.Is(pool.lastErr, context.DeadlineExceeded) || pool.budget <= 0 || pool.budget > 2*time.Second || first.Code != 503 || first.Header().Get("Retry-After") != "2" || first.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("Master existence lookup escaped the shared deadline", first.Code, first.Header(), pool.lastErr, pool.budget)
	}
	pool.blocked = false
	second := request(router, "GET", target, "")
	var artwork media.CategoryArtwork
	if second.Code != 200 || json.Unmarshal(second.Body.Bytes(), &artwork) != nil || len(artwork.MetadataTracks) != 1 || !artwork.MetadataTracks[0].NativeMetadata {
		t.Fatal("Master category did not recover after deadline", second.Code, second.Body.String())
	}
}

func (r *deadlineArtworkRepository) CatalogGeneration() uint64 {
	return r.MediaRepository.(interface{ CatalogGeneration() uint64 }).CatalogGeneration()
}

func (r *deadlineArtworkRepository) HiddenPaths(ctx context.Context) (map[string]bool, error) {
	r.queries++
	if r.blocked {
		<-ctx.Done()
		r.lastErr = ctx.Err()
		return nil, r.lastErr
	}
	return r.MediaRepository.HiddenPaths(ctx)
}

func TestDirectoryArtworkDeadlineIsRetryableAndNeverCachedAsEmpty(t *testing.T) {
	router, db, directory, public := publicFixture(t, false)
	identity, err := node.Initialize(context.Background(), db.Nodes(), filepath.Join(directory, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	repo := &deadlineArtworkRepository{MediaRepository: db.Media(), EncryptionBatchRepository: db.Media().(store.EncryptionBatchRepository), blocked: true}
	service, err := media.New(filepath.Join(directory, "media"), repo, identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { service.Close() })
	public.media = service
	target := "/api/v1/media/catalog/artwork?path=music/artist"
	first := request(router, "GET", target, "")
	if !errors.Is(repo.lastErr, context.DeadlineExceeded) || first.Code != 503 || first.Header().Get("Retry-After") != "2" || first.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("real lookup deadline became a completed empty result", first.Code, first.Header(), first.Body.String(), repo.lastErr)
	}
	repo.blocked = false
	second := request(router, "GET", target, "")
	var artwork media.CategoryArtwork
	if second.Code != 200 || json.Unmarshal(second.Body.Bytes(), &artwork) != nil || len(artwork.MetadataTracks) != 1 || !artwork.MetadataTracks[0].NativeMetadata || repo.queries != 2 {
		t.Fatal("retry did not repeat the lookup and recover a candidate", second.Code, second.Body.String(), repo.queries)
	}
}
