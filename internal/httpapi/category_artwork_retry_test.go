package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

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
