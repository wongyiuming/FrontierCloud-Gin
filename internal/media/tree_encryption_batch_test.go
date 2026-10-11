package media

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type adminTreeEncryptionCounter struct {
	store.MediaRepository
	store.EncryptionRepository
	store.EncryptionBatchRepository
	ensure, single int
	batches        [][]string
}

func (r *adminTreeEncryptionCounter) EnsureObjects(ctx context.Context, objects []store.MediaObject) (map[string]string, error) {
	r.ensure++
	return r.MediaRepository.EnsureObjects(ctx, objects)
}

func (r *adminTreeEncryptionCounter) Encryption(ctx context.Context, id string) (*mediacrypto.Metadata, error) {
	r.single++
	return r.EncryptionRepository.Encryption(ctx, id)
}

func (r *adminTreeEncryptionCounter) Encryptions(ctx context.Context, ids []string) (map[string]*mediacrypto.Metadata, error) {
	r.batches = append(r.batches, append([]string(nil), ids...))
	return r.EncryptionBatchRepository.Encryptions(ctx, ids)
}

func (r *adminTreeEncryptionCounter) reset() {
	r.ensure, r.single, r.batches = 0, 0, nil
}

func (r *adminTreeEncryptionCounter) check(t *testing.T, items []TreeItem) {
	t.Helper()
	if r.ensure != 0 || r.single != 0 {
		t.Fatal("global identities were recreated or descriptors queried per row", r.ensure, r.single)
	}
	want := map[string]bool{}
	for _, item := range items {
		if item.Kind == "file" {
			if !ownedObjectID.MatchString(item.MediaID) {
				t.Fatal("response lost its global identity", item.Path, item.MediaID)
			}
			want[item.MediaID] = true
		}
	}
	if len(want) == 0 {
		if len(r.batches) != 0 {
			t.Fatal("an empty response looked up descriptors", r.batches)
		}
		return
	}
	if len(r.batches) != 1 || len(r.batches[0]) != len(want) {
		t.Fatal("descriptor query included nonmatching, nested or truncated files", len(want), r.batches)
	}
	for _, id := range r.batches[0] {
		if !want[id] {
			t.Fatal("descriptor query escaped the response", id)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatal("response descriptors were omitted", want)
	}
}

type invalidAdminTreeIdentityPool struct {
	store.PoolRepository
	id string
}

func (p *invalidAdminTreeIdentityPool) ManagementResources(ctx context.Context, scope string, exact bool) ([]store.GlobalMedia, error) {
	rows, err := p.PoolRepository.ManagementResources(ctx, scope, exact)
	if err == nil && len(rows) != 0 {
		rows[0].ID = p.id
	}
	return rows, err
}

func TestAdminGlobalTreeEncryptionUsesResponseBatchAndSearchCap(t *testing.T) {
	_, db, svc := masterFixture(t)
	ctx := context.Background()
	repo := db.Media()
	objects := make([]store.MediaObject, 1001)
	for i := range objects {
		directory := "music/batch/inner"
		if i < 10 {
			directory = "music/batch"
		}
		objects[i] = store.MediaObject{Path: fmt.Sprintf("%s/item-%04d.mp3", directory, i), Kind: "audio"}
	}
	ids, err := repo.EnsureObjects(ctx, objects)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := mediacrypto.NewMetadata(34)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := mediacrypto.NewMetadata(34)
	if err != nil {
		t.Fatal(err)
	}
	for index, encryption := range map[int]*mediacrypto.Metadata{0: &metadata, 2: &retired} {
		object := objects[index]
		object.Encryption = encryption
		if err := repo.CompleteUpload(ctx, object, fmt.Sprintf("%032x", index+1), store.AdminAudit{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Database().Exec("UPDATE media_encryption SET descriptor_json=NULL WHERE object_kind='media' AND object_id=?", ids[objects[2].Path]); err != nil {
		t.Fatal(err)
	}
	manifest := make([]store.LocalMedia, len(objects))
	for i, object := range objects {
		object.ID = ids[object.Path]
		manifest[i] = store.LocalMedia{MediaObject: object, Bytes: metadata.CiphertextSize, ETag: `"` + strings.Repeat("1", 64) + `"`}
	}
	if err := db.Pool().AdoptMasterLocal(ctx, int64(len(manifest))*metadata.CiphertextSize, 10*store.GiB, manifest); err != nil {
		t.Fatal(err)
	}
	// Logical global identity and owner storage-object identity need not match.
	// The encryption registry is indexed by the former, even for remote media.
	if _, err := db.Database().Exec("UPDATE global_media_objects SET object_id=? WHERE media_id=?", strings.Repeat("e", 64), ids[objects[0].Path]); err != nil {
		t.Fatal(err)
	}
	if err := svc.Hide(ctx, []string{"music/batch"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	counted := &adminTreeEncryptionCounter{MediaRepository: repo,
		EncryptionRepository: repo.(store.EncryptionRepository), EncryptionBatchRepository: repo.(store.EncryptionBatchRepository)}
	svc.repository = counted

	tree, err := svc.Tree(ctx, "music/batch")
	if err != nil || len(tree.Items) != 11 {
		t.Fatal("current layer changed", len(tree.Items), err)
	}
	counted.check(t, tree.Items)
	for _, item := range tree.Items {
		if !item.Hidden {
			t.Fatal("batch decoration lost inherited hidden state", item.Path)
		}
		if item.Path == objects[0].Path {
			if item.Encryption == nil || *item.Encryption != metadata || item.MediaID != ids[item.Path] {
				t.Fatal("encrypted descriptor or identity changed", item)
			}
		} else if item.Encryption != nil {
			t.Fatal("plain, retired or directory entry gained an active descriptor", item.Path)
		}
	}

	counted.reset()
	search, err := svc.Search(ctx, "item", "music/batch")
	if err != nil || len(search.Items) != 200 || !search.Truncated {
		t.Fatal("search result cap changed", len(search.Items), search.Truncated, err)
	}
	counted.check(t, search.Items)
	counted.reset()
	search, err = svc.Search(ctx, "item-0000", "music/batch")
	if err != nil || len(search.Items) != 1 || search.Items[0].Encryption == nil || *search.Items[0].Encryption != metadata {
		t.Fatal("matched encrypted descriptor missing", search, err)
	}
	counted.check(t, search.Items)
	counted.reset()
	search, err = svc.Search(ctx, "never-matches-any-file", "music/batch")
	if err != nil || len(search.Items) != 0 || search.Truncated {
		t.Fatal("empty search changed", search, err)
	}
	counted.check(t, search.Items)

	// The identity-only scan consumers do not read media content or consume
	// encryption descriptors. Their relation/stat repositories retain identity
	// checks, independently of Tree/Search response decoration.
	for name, operation := range map[string]func() error{
		"priorities":    func() error { _, err := svc.Priorities(ctx, "music/batch", "item", "audio", 1, 100); return err },
		"lyric_catalog": func() error { _, err := svc.LyricCatalog(ctx, "music", "lyrics", "item", "song"); return err },
		"auto_lyrics":   func() error { _, err := svc.AutoLyrics(ctx, store.AdminAudit{}); return err },
	} {
		counted.reset()
		if err := operation(); err != nil || counted.single != 0 || len(counted.batches) != 0 {
			t.Fatal("identity-only consumer queried encryption descriptors", name, err, counted.single, counted.batches)
		}
	}

	if _, err := db.Database().Exec("UPDATE media_encryption SET descriptor_json='{}' WHERE object_kind='media' AND object_id=?", ids[objects[0].Path]); err != nil {
		t.Fatal(err)
	}
	counted.reset()
	search, err = svc.Search(ctx, "never-matches-any-file", "music/batch")
	if err != nil || len(search.Items) != 0 {
		t.Fatal("unselected descriptor was queried during an empty search", search, err)
	}
	counted.check(t, search.Items)
	for name, operation := range map[string]func() error{
		"tree":   func() error { _, err := svc.Tree(ctx, "music/batch"); return err },
		"search": func() error { _, err := svc.Search(ctx, "item-0000", "music/batch"); return err },
	} {
		counted.reset()
		if err := operation(); !errors.Is(err, mediacrypto.ErrMetadata) || counted.ensure != 0 || counted.single != 0 || len(counted.batches) != 1 {
			t.Fatal("selected corrupt descriptor did not fail closed in one batch", name, err, counted.ensure, counted.single, counted.batches)
		}
	}

	// Fault injection changes only the rows returned by the real pool. A broken
	// global identity must never fall back to creating a local object identity.
	realPool := svc.pool
	for _, invalid := range []string{"", "not-a-valid-global-id"} {
		svc.pool = &invalidAdminTreeIdentityPool{PoolRepository: realPool, id: invalid}
		for name, operation := range map[string]func() error{
			"tree":   func() error { _, err := svc.Tree(ctx, "music/batch"); return err },
			"search": func() error { _, err := svc.Search(ctx, "item", "music/batch"); return err },
		} {
			counted.reset()
			if err := operation(); !errors.Is(err, mediacrypto.ErrMetadata) || counted.ensure != 0 || counted.single != 0 || len(counted.batches) != 0 {
				t.Fatal("invalid global identity was repaired or queried", invalid, name, err, counted.ensure, counted.single, counted.batches)
			}
		}
	}
}
