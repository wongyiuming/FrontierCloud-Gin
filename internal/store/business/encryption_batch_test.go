package business_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestEncryptionBatchNativeRepositoryPreservesPlainAndFailsClosed(t *testing.T) {
	db := database(t)
	repo := db.Media()
	batch := repo.(store.EncryptionBatchRepository)
	ctx := context.Background()
	metadata, _ := mediacrypto.NewMetadata(25)
	encrypted := store.MediaObject{Path: "music/" + t.Name() + "/encrypted.mp3", Kind: "audio", Encryption: &metadata}
	plain := store.MediaObject{Path: "music/" + t.Name() + "/plain.mp3", Kind: "audio"}
	if err := repo.CompleteUpload(ctx, encrypted, strings.Repeat("1", 32), store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	ids, err := repo.EnsureObjects(ctx, []store.MediaObject{encrypted, plain})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := batch.Encryptions(ctx, []string{ids[encrypted.Path], ids[plain.Path], ids[encrypted.Path]})
	if err != nil || len(actual) != 1 || actual[ids[encrypted.Path]] == nil || *actual[ids[encrypted.Path]] != metadata {
		t.Fatal("native batch result mismatch", actual, err)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	// MySQL tests share one database. Retire this test's synthetic objects before
	// a later startup-verifier test checks for encrypted data without a key ID.
	t.Cleanup(func() {
		if _, err := raw.Exec("DELETE FROM media_encryption WHERE object_kind='media' AND object_id=? AND file_id=?", ids[encrypted.Path], metadata.FileID); err != nil {
			t.Error(err)
		}
		if _, err := raw.Exec("DELETE FROM media_objects WHERE media_id IN (?,?)", ids[encrypted.Path], ids[plain.Path]); err != nil {
			t.Error(err)
		}
	})
	encoded, _ := json.Marshal(metadata)
	if _, err := raw.Exec("UPDATE media_encryption SET descriptor_json='{}' WHERE object_kind='media' AND object_id=?", ids[encrypted.Path]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := raw.Exec("UPDATE media_encryption SET descriptor_json=? WHERE object_kind='media' AND object_id=?", string(encoded), ids[encrypted.Path]); err != nil {
			t.Error(err)
		}
	})
	if actual, err := batch.Encryptions(ctx, []string{ids[plain.Path], ids[encrypted.Path]}); !errors.Is(err, mediacrypto.ErrMetadata) || actual != nil {
		t.Fatal("corrupt native descriptor became plaintext", actual, err)
	}
}
