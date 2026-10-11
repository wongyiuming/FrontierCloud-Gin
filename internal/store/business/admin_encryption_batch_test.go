package business_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Counts service calls while all identity and descriptor queries still use the
// selected native SQLite/MySQL repository.
type adminEncryptionCounter struct {
	store.MediaRepository
	store.EncryptionRepository
	store.EncryptionBatchRepository
	scope                         string
	single, batches, ensures, ids int
}

func (r *adminEncryptionCounter) Encryption(ctx context.Context, id string) (*mediacrypto.Metadata, error) {
	r.single++
	return r.EncryptionRepository.Encryption(ctx, id)
}
func (r *adminEncryptionCounter) Encryptions(ctx context.Context, ids []string) (map[string]*mediacrypto.Metadata, error) {
	r.batches++
	r.ids += len(ids)
	return r.EncryptionBatchRepository.Encryptions(ctx, ids)
}
func (r *adminEncryptionCounter) EnsureObjects(ctx context.Context, objects []store.MediaObject) (map[string]string, error) {
	r.ensures++
	return r.MediaRepository.EnsureObjects(ctx, objects)
}
func (r *adminEncryptionCounter) reset() { r.single, r.batches, r.ensures, r.ids = 0, 0, 0, 0 }

// MySQL's business suite shares its database, but this rooted filesystem owns
// only one path namespace. Its startup must not reconcile another test's delete.
func (r *adminEncryptionCounter) DeleteOperations(ctx context.Context) ([]store.DeleteOperation, error) {
	operations, err := r.MediaRepository.DeleteOperations(ctx)
	if err != nil {
		return nil, err
	}
	result := []store.DeleteOperation{}
	for _, operation := range operations {
		if len(operation.Items) != 0 && strings.HasPrefix(operation.Items[0].Path, r.scope+"/") {
			result = append(result, operation)
		}
	}
	return result, nil
}

func TestAdminLocalTreeAndSearchUseNativeEncryptionBatches(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	raw := db.(interface{ Database() *sql.DB }).Database()
	repository := db.Media()
	scope := "music/" + t.Name()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(scope)), 0755); err != nil {
		t.Fatal(err)
	}
	objects := make([]store.MediaObject, 1001)
	for i := range objects {
		objects[i] = store.MediaObject{Path: fmt.Sprintf("%s/track%04d.mp3", scope, i), Kind: "audio"}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(objects[i].Path)), []byte("ID3batch"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	identities, err := repository.EnsureObjects(ctx, objects)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(objects))
	for i, object := range objects {
		ids[i] = identities[object.Path]
	}
	// Clean only our own rows, including synthetic tombstones, before the shared
	// MySQL suite's later startup-verifier and backup assertions.
	t.Cleanup(func() {
		for start := 0; start < len(ids); start += 500 {
			batch := ids[start:min(start+500, len(ids))]
			args := make([]any, len(batch))
			for i, id := range batch {
				args[i] = id
			}
			where := " IN (" + strings.TrimSuffix(strings.Repeat("?,", len(batch)), ",") + ")"
			for _, statement := range []string{"DELETE FROM media_encryption WHERE object_kind='media' AND object_id", "DELETE FROM media_objects WHERE media_id"} {
				if _, err := raw.Exec(statement+where, args...); err != nil {
					t.Error(err)
				}
			}
		}
	})
	expected := map[string]mediacrypto.Metadata{}
	for _, index := range []int{0, 499, 1000, 500} {
		meta, err := mediacrypto.NewMetadata(int64(index + 1))
		if err != nil {
			t.Fatal(err)
		}
		var descriptor any
		if index != 500 {
			encoded, _ := json.Marshal(meta)
			descriptor = string(encoded)
			expected[ids[index]] = meta
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(objects[index].Path)), make([]byte, meta.CiphertextSize), 0644); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = raw.Exec("INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES ('media',?,?,?,1)", ids[index], meta.FileID, descriptor); err != nil {
			t.Fatal(err)
		}
	}
	counted := &adminEncryptionCounter{MediaRepository: repository, EncryptionRepository: repository.(store.EncryptionRepository), EncryptionBatchRepository: repository.(store.EncryptionBatchRepository), scope: scope}
	svc, err := media.New(root, counted, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	assertCalls := func(batches, identities int) {
		t.Helper()
		if counted.single != 0 || counted.batches != batches || counted.ids != identities || counted.ensures != batches {
			t.Fatalf("per-file or unbounded descriptor queries: single=%d batch=%d ids=%d ensure=%d", counted.single, counted.batches, counted.ids, counted.ensures)
		}
	}
	for range 2 {
		counted.reset()
		tree, err := svc.Tree(ctx, scope)
		if err != nil || len(tree.Items) != len(objects) {
			t.Fatal("large native tree", len(tree.Items), err)
		}
		assertCalls(1, 1001)
		for _, item := range tree.Items {
			meta, encrypted := expected[item.MediaID]
			if encrypted && (item.Encryption == nil || *item.Encryption != meta) || !encrypted && item.Encryption != nil {
				t.Fatal("tree changed missing/tombstone/encrypted metadata", item)
			}
		}
	}
	// Duplicate identities cross the native 500-parameter chunk boundary without
	// duplicating descriptors or turning retired identities into active ones.
	actual, err := counted.EncryptionBatchRepository.Encryptions(ctx, append(append([]string{}, ids...), ids[0], ids[1000]))
	if err != nil || len(actual) != 3 || actual[ids[500]] != nil {
		t.Fatal("native duplicates or tombstones", actual, err)
	}
	if _, err := raw.Exec("UPDATE media_encryption SET descriptor_json='{}' WHERE object_kind='media' AND object_id=?", ids[1000]); err != nil {
		t.Fatal(err)
	}
	counted.reset()
	result, err := svc.Search(ctx, "track", scope)
	if err != nil || len(result.Items) != 200 || !result.Truncated || result.Items[0].Encryption == nil || *result.Items[0].Encryption != expected[ids[0]] {
		t.Fatal("search queried corrupt, truncated-away rows or lost its descriptor", len(result.Items), err)
	}
	assertCalls(1, 200)
	counted.reset()
	if result, err := svc.Search(ctx, "not-found", scope); err != nil || len(result.Items) != 0 {
		t.Fatal("empty search", result, err)
	}
	assertCalls(0, 0)
	counted.reset()
	if result, err := svc.Search(ctx, "track1000", scope); !errors.Is(err, mediacrypto.ErrMetadata) || len(result.Items) != 0 {
		t.Fatal("corrupt selected descriptor became plaintext", result, err)
	}
	assertCalls(1, 1)
	if _, err := svc.Tree(ctx, scope); !errors.Is(err, mediacrypto.ErrMetadata) {
		t.Fatal("corrupt late batch returned partial tree", err)
	}
}
