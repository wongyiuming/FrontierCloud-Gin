package business_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestEncryptedPremasterIdentityIsDurableAndCannotBeRebound(t *testing.T) {
	db := database(t)
	repo := db.Media()
	encryption := repo.(store.EncryptionRepository)
	ctx := context.Background()
	id, err := encryption.EncryptionKeyID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		id = strings.Repeat("f", 64)
	}
	if err = encryption.CheckEncryptionKey(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = encryption.CheckEncryptionKey(ctx, id); err != nil {
		t.Fatal("same key failed restart check", err)
	}
	wrong := strings.Repeat("0", 64)
	if wrong == id {
		wrong = strings.Repeat("1", 64)
	}
	if err = encryption.CheckEncryptionKey(ctx, wrong); !errors.Is(err, mediacrypto.ErrPremaster) {
		t.Fatal("wrong structurally valid key rebound database", err)
	}
	actual, err := encryption.EncryptionKeyID(ctx)
	if err != nil || actual != id {
		t.Fatal("failed check changed verifier", actual, err)
	}
	meta, err := mediacrypto.NewMetadata(100)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.CompleteUpload(ctx, store.MediaObject{Path: "music/" + t.Name() + "/key.mp3", Kind: "audio", Encryption: &meta}, strings.Repeat("6", 32), store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, err = raw.Exec("DELETE FROM media_crypto_keys WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := raw.Exec("INSERT INTO media_crypto_keys(singleton,key_id,created_at) VALUES (1,?,1)", id); err != nil {
			t.Error(err)
		}
	})
	if err = encryption.CheckEncryptionKey(ctx, id); !errors.Is(err, mediacrypto.ErrPremaster) {
		t.Fatal("encrypted data missing verifier was silently adopted", err)
	}
}

func TestEncryptedMetadataAtomicImmutableAndFollowsStableIdentity(t *testing.T) {
	db := database(t)
	repo := db.Media()
	encryption := repo.(store.EncryptionRepository)
	ctx := context.Background()
	meta, err := mediacrypto.NewMetadata(100)
	if err != nil {
		t.Fatal(err)
	}
	base := "music/" + t.Name()
	object := store.MediaObject{Path: base + "/secure.mp3", Kind: "audio", Encryption: &meta}
	if err = repo.CompleteUpload(ctx, object, strings.Repeat("7", 32), store.AdminAudit{Action: "upload_item"}); err != nil {
		t.Fatal(err)
	}
	ids, err := repo.EnsureObjects(ctx, []store.MediaObject{object})
	if err != nil {
		t.Fatal(err)
	}
	id := ids[object.Path]
	if actual, err := encryption.Encryption(ctx, id); err != nil || actual == nil || *actual != meta {
		t.Fatal("descriptor not stored", err)
	}
	if err = repo.CompleteRename(ctx, base, base+"-new", strings.Repeat("8", 32), store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if actual, err := repo.ObjectByID(ctx, id); err != nil || actual == nil || actual.Encryption == nil || *actual.Encryption != meta || actual.Path != base+"-new/secure.mp3" {
		t.Fatal("rename changed encryption identity", actual, err)
	}
	duplicate := object
	duplicate.Path = base + "-new/duplicate.mp3"
	if err = repo.CompleteUpload(ctx, duplicate, strings.Repeat("9", 32), store.AdminAudit{Action: "upload_item"}); err == nil {
		t.Fatal("duplicate prepared key/nonce accepted")
	}
	var count int
	if err = db.(interface{ Database() *sql.DB }).Database().QueryRow("SELECT COUNT(*) FROM media_objects WHERE media_path=?", duplicate.Path).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed metadata commit retained plaintext-looking object", err)
	}
	changed := meta
	changed.PlaintextSize++
	changed.CiphertextSize++
	current := store.MediaObject{Path: base + "-new/secure.mp3", Kind: "audio", Encryption: &changed}
	if err = repo.CompleteUpload(ctx, current, strings.Repeat("a", 32), store.AdminAudit{Action: "upload_item"}); err == nil {
		t.Fatal("immutable descriptor changed")
	}
	operation := store.DeleteOperation{ID: strings.Repeat("b", 32), Items: []store.DeleteItem{{Path: current.Path, Slot: "0"}}}
	if err = repo.PrepareDelete(ctx, operation, store.AdminAudit{Action: "delete"}); err != nil {
		t.Fatal(err)
	}
	if err = repo.CommitDelete(ctx, operation.ID, store.AdminAudit{Action: "delete"}); err != nil {
		t.Fatal(err)
	}
	if actual, err := encryption.Encryption(ctx, id); err != nil || actual != nil {
		t.Fatal("deletion retained active crypto metadata", err)
	}
	if used, err := encryption.EncryptionUsed(ctx, meta.FileID); err != nil || !used {
		t.Fatal("deletion allowed nonce reuse", err)
	}
}
