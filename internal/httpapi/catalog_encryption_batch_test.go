package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type countedEncryptionCatalogRepository struct {
	store.MediaRepository
	store.EncryptionRepository
	store.EncryptionBatchRepository
	generation            interface{ CatalogGeneration() uint64 }
	batch, single, hidden int
}

func (r *countedEncryptionCatalogRepository) CatalogGeneration() uint64 {
	return r.generation.CatalogGeneration()
}
func (r *countedEncryptionCatalogRepository) HiddenPaths(ctx context.Context) (map[string]bool, error) {
	r.hidden++
	return r.MediaRepository.HiddenPaths(ctx)
}
func (r *countedEncryptionCatalogRepository) Encryption(ctx context.Context, id string) (*mediacrypto.Metadata, error) {
	r.single++
	return r.EncryptionRepository.Encryption(ctx, id)
}
func (r *countedEncryptionCatalogRepository) Encryptions(ctx context.Context, ids []string) (map[string]*mediacrypto.Metadata, error) {
	r.batch++
	return r.EncryptionBatchRepository.Encryptions(ctx, ids)
}

func TestCatalogEncryptionUsesBatchOnWarmCacheAndRejectsCorruptDescriptor(t *testing.T) {
	router, db, dir, p := publicFixture(t, false)
	ctx := context.Background()
	repo := db.Media()
	counted := &countedEncryptionCatalogRepository{MediaRepository: repo, EncryptionRepository: repo.(store.EncryptionRepository), EncryptionBatchRepository: repo.(store.EncryptionBatchRepository), generation: repo.(interface{ CatalogGeneration() uint64 })}
	identity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := media.New(filepath.Join(dir, "media"), counted, identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	svc.ConfigureCatalogCache(time.Minute)
	p.media = svc
	metadata, _ := mediacrypto.NewMetadata(10)
	encrypted := "music/artist/encrypted.mp3"
	for i := 0; i < 23; i++ {
		name := fmt.Sprintf("music/artist/batch-%02d.mp3", i)
		if i == 0 {
			name = encrypted
		}
		if err := os.WriteFile(filepath.Join(dir, "media", name), []byte("ID3fixture"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.CompleteUpload(ctx, store.MediaObject{Path: encrypted, Kind: "audio", Encryption: &metadata}, "11111111111111111111111111111111", store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	target := "/api/v1/media/catalog/media?media_type=music&path=music/artist&playback_session_id=batch"
	for range 3 {
		w := request(router, "GET", target, "")
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var result struct{ Entries []media.Track }
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, entry := range result.Entries {
			if entry.Encryption != nil {
				found++
				if *entry.Encryption != metadata {
					t.Fatal("catalog changed descriptor")
				}
			}
		}
		if len(result.Entries) != 24 || found != 1 {
			t.Fatal("plain/encrypted catalog decoration changed", len(result.Entries), found)
		}
	}
	before := counted.hidden
	if w := request(router, "GET", target, ""); w.Code != 200 || counted.hidden != before {
		t.Fatal("expected warm catalog cache", w.Code, counted.hidden, before)
	}
	if counted.batch != 4 || counted.single != 0 {
		t.Fatal("warm catalogs made per-track encryption queries", counted.batch, counted.single)
	}
	ids, err := repo.EnsureObjects(ctx, []store.MediaObject{{Path: encrypted, Kind: "audio"}})
	if err != nil {
		t.Fatal(err)
	}
	// A cached catalog cannot hide corrupt current SQL encryption state.
	if _, err := db.Database().Exec("UPDATE media_encryption SET descriptor_json='{}' WHERE object_kind='media' AND object_id=?", ids[encrypted]); err != nil {
		t.Fatal(err)
	}
	if w := request(router, "GET", target, ""); w.Code != 500 {
		t.Fatal("corrupt descriptor silently returned plaintext", w.Code, w.Body.String())
	}
}
