package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"testing"
)

type contentRepository struct {
	store.MediaRepository
	object store.MediaObject
}

func (r *contentRepository) ObjectByID(context.Context, string) (*store.MediaObject, error) {
	object := r.object
	return &object, nil
}

func TestManagedContentNativeMediaRootAndMetadataRecheck(t *testing.T) {
	mounted := t.TempDir()
	data := []byte("native mounted media bytes")
	if e := os.WriteFile(filepath.Join(mounted, "track.mp3"), data, 0600); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(mounted)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	repo := &contentRepository{object: store.MediaObject{ID: "identity", Path: "track.mp3", Kind: "audio"}}
	service := &Service{root: root, repository: repo}
	digest, e := store.MigrationDigest(repo.object)
	if e != nil {
		t.Fatal(e)
	}
	item := store.ExpectedPhysicalItem{ObjectID: repo.object.ID, Path: "media/track.mp3", MetadataSHA256: digest}
	calls := 0
	result, e := service.ObserveManagedContent(context.Background(), item, int64(len(data)), func() error { calls++; return nil })
	sum := sha256.Sum256(data)
	if e != nil || result.SHA256 != hex.EncodeToString(sum[:]) || calls != 2 {
		t.Fatal(result, calls, e)
	}
	calls = 0
	if _, e = service.ObserveManagedContent(context.Background(), item, int64(len(data)), func() error {
		calls++
		if calls == 2 {
			return errors.New("metadata changed")
		}
		return nil
	}); e == nil {
		t.Fatal("changed metadata published")
	}
	repo.object.Path = "other.mp3"
	if _, e = service.ObserveManagedContent(context.Background(), item, int64(len(data)), func() error { return nil }); e == nil {
		t.Fatal("stale locator")
	}
}

func (r *contentRepository) DeleteOperations(context.Context) ([]store.DeleteOperation, error) {
	return nil, nil
}

func TestManagedContentEncryptedDescriptorAndOpaqueBytes(t *testing.T) {
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	descriptor, e := mediacrypto.NewMetadata(24)
	if e != nil {
		t.Fatal(e)
	}
	data := make([]byte, descriptor.CiphertextSize)
	for i := range data {
		data[i] = byte(i)
	}
	f, e := root.Create("encrypted.mp3")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(data); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	repo := &contentRepository{object: store.MediaObject{ID: "fixture", Path: "encrypted.mp3", Kind: "audio", Encryption: &descriptor}}
	service := &Service{root: root, repository: repo}
	digest, e := store.MigrationDigest(repo.object)
	if e != nil {
		t.Fatal(e)
	}
	item := store.ExpectedPhysicalItem{ObjectID: repo.object.ID, Path: "media/encrypted.mp3", MetadataSHA256: digest}
	result, e := service.ObserveManagedContent(context.Background(), item, int64(len(data)), func() error { return nil })
	sum := sha256.Sum256(data)
	if e != nil || result.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal(result, e)
	}
	descriptor.CiphertextSize++
	item.MetadataSHA256, e = store.MigrationDigest(repo.object)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = service.ObserveManagedContent(context.Background(), item, int64(len(data)), func() error { return nil }); e == nil {
		t.Fatal("malformed descriptor")
	}
}
