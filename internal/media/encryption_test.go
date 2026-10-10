package media

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func encryptedFixtureBytes(t *testing.T, plain string) (mediacrypto.Metadata, []byte) {
	t.Helper()
	meta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	manager, _ := mediacrypto.New(bytes.Repeat([]byte{1}, 32))
	key, _ := manager.FileKey(meta)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce, _ := meta.ChunkNonce(0)
	return meta, aead.Seal(nil, nonce, []byte(plain), meta.ChunkAAD(0))
}

func TestEncryptedLocalUploadRenameDeleteRollbackAndNonceTombstone(t *testing.T) {
	root, db, svc := deleteFixture(t)
	ctx := context.Background()
	meta, payload := encryptedFixtureBytes(t, "ID3encrypted-payload")
	stage, err := svc.Stage(ctx, bytes.NewReader(payload), meta.CiphertextSize)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	name, err := svc.PublishEncrypted(ctx, stage, "secure.mp3", "music/artist", "", false, 255, store.AdminAudit{}, &meta)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: name, Kind: "audio"}})
	if err != nil {
		t.Fatal(err)
	}
	id := ids[name]
	check := func(name string) {
		t.Helper()
		actual, err := svc.Encryption(ctx, id)
		if err != nil || actual == nil || *actual != meta {
			t.Fatal("descriptor changed", actual, err)
		}
		actualBytes, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(actualBytes, payload) {
			t.Fatal("ciphertext changed", err)
		}
	}
	if _, err = svc.Rename(ctx, "music/artist", "encrypted", store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	name = "music/encrypted/secure.mp3"
	check(name)
	if _, err = db.Database().Exec("CREATE TRIGGER reject_encrypted_delete BEFORE INSERT ON admin_audit_log WHEN NEW.action='delete' AND NEW.result='success' BEGIN SELECT RAISE(ABORT,'audit offline'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Delete(ctx, []string{name}, store.AdminAudit{Action: "delete"}); err == nil {
		t.Fatal("failed deletion committed")
	}
	check(name)
	if _, err = db.Database().Exec("DROP TRIGGER reject_encrypted_delete"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Delete(ctx, []string{name}, store.AdminAudit{Action: "delete"}); err != nil {
		t.Fatal(err)
	}
	if actual, err := svc.Encryption(ctx, id); err != nil || actual != nil {
		t.Fatal("deleted descriptor remains active", err)
	}
	repository := db.Media().(store.EncryptionRepository)
	if used, err := repository.EncryptionUsed(ctx, meta.FileID); err != nil || !used {
		t.Fatal("nonce consumption forgotten", err)
	}
	retry, err := svc.Stage(ctx, bytes.NewReader(payload), meta.CiphertextSize)
	if err != nil {
		t.Fatal(err)
	}
	defer retry.Close()
	if _, err = svc.PublishEncrypted(ctx, retry, "secure.mp3", "music/encrypted", "", false, 255, store.AdminAudit{}, &meta); !errors.Is(err, mediacrypto.ErrMetadata) {
		t.Fatal("consumed nonce reused", err)
	}
}

func TestEncryptedLocalPublicationRecoveryPreservesDescriptor(t *testing.T) {
	root, db, svc := deleteFixture(t)
	ctx := context.Background()
	meta, payload := encryptedFixtureBytes(t, "ID3crash-recovery")
	stage, err := svc.Stage(ctx, bytes.NewReader(payload), meta.CiphertextSize)
	if err != nil {
		t.Fatal(err)
	}
	object := store.MediaObject{Path: "music/artist/recovery.mp3", Kind: "audio", Encryption: &meta}
	journal := uploadJournal{Format: "frontiercloud-local-upload", Version: 1, ID: stage.id, Object: object, Bytes: stage.Bytes, SHA256: stage.Digest, Audit: store.AdminAudit{Action: "upload_item"}}
	if err = svc.writeUploadJournal(journal); err != nil {
		t.Fatal(err)
	}
	stage.retain = true
	stage.Close()
	svc.Close()
	restarted, err := New(root, db.Media(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	ids, err := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: object.Path, Kind: "audio"}})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := restarted.Encryption(ctx, ids[object.Path])
	if err != nil || actual == nil || *actual != meta {
		t.Fatal("recovery lost descriptor", err)
	}
	data, err := os.ReadFile(filepath.Join(root, object.Path))
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatal("recovery changed cipher", err)
	}
}

func TestEncryptedMasterAndOwnedStoragePublication(t *testing.T) {
	t.Run("MasterLocal", func(t *testing.T) {
		root, db, svc := masterFixture(t)
		ctx := context.Background()
		meta, payload := encryptedFixtureBytes(t, "ID3master-encrypted")
		ticket, err := svc.ReserveMasterEncryptedUpload(ctx, "secure.mp3", "music/EncryptedMaster", "", "primary", meta.CiphertextSize, 255, store.AdminAudit{}, &meta)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := db.Pool().Upload(ctx, ticket.ID)
		if err != nil || reservation.Encryption == nil || *reservation.Encryption != meta {
			t.Fatal("reserve lost descriptor", err)
		}
		if _, err = svc.UploadMasterBytes(ctx, ticket.ID, bytes.NewReader(payload), store.AdminAudit{}); err != nil {
			t.Fatal(err)
		}
		object, err := db.Media().ObjectByID(ctx, ticket.MediaID)
		if err != nil || object == nil || object.Encryption == nil || *object.Encryption != meta {
			t.Fatal("publication lost descriptor", err)
		}
		data, err := os.ReadFile(filepath.Join(root, ticket.Path))
		if err != nil || !bytes.Equal(data, payload) {
			t.Fatal("not ciphertext", err)
		}
		if _, err = svc.ReserveMasterEncryptedUpload(ctx, "reuse.mp3", "music/EncryptedMaster", "", "primary", meta.CiphertextSize, 255, store.AdminAudit{}, &meta); err == nil {
			t.Fatal("same key/nonce reserved twice")
		}
		cancelMeta, _ := mediacrypto.NewMetadata(10)
		cancel, err := svc.ReserveMasterEncryptedUpload(ctx, "cancel.mp3", "music/EncryptedMaster", "", "primary", cancelMeta.CiphertextSize, 255, store.AdminAudit{}, &cancelMeta)
		if err != nil {
			t.Fatal(err)
		}
		if err = svc.CancelMasterUpload(ctx, cancel.ID, store.AdminAudit{}); err != nil {
			t.Fatal(err)
		}
		if actual, err := svc.Encryption(ctx, cancel.MediaID); err != nil || actual != nil {
			t.Fatal("cancel retained active descriptor", err)
		}
	})
	t.Run("OwnedStorage", func(t *testing.T) {
		root, db, svc, relationship := ownedFixture(t)
		ctx := context.Background()
		meta, payload := encryptedFixtureBytes(t, "ID3owned-encrypted")
		object := store.MediaObject{ID: strings.Repeat("8", 64), Path: "music/EncryptedOwned/secure.mp3", Kind: "audio", Encryption: &meta}
		if _, err := svc.OwnedUpload(ctx, relationship, object, meta.CiphertextSize, bytes.NewReader(payload[:len(payload)-1]), store.NodeAudit{}); err == nil {
			t.Fatal("partial cipher accepted")
		}
		ownedFunds(t, db, 0, 0)
		if _, err := svc.OwnedUpload(ctx, relationship, object, meta.CiphertextSize, bytes.NewReader(payload), store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		stored, err := db.Media().ObjectByID(ctx, object.ID)
		if err != nil || stored == nil || stored.Encryption == nil || *stored.Encryption != meta {
			t.Fatal("owned descriptor missing", err)
		}
		data, err := os.ReadFile(filepath.Join(root, object.Path))
		if err != nil || !bytes.Equal(data, payload) {
			t.Fatal("owned plaintext", err)
		}
		wrong := object
		wrong.Encryption = nil
		if _, err = svc.OwnedUpload(ctx, relationship, wrong, meta.CiphertextSize, bytes.NewReader(payload), store.NodeAudit{}); err == nil {
			t.Fatal("retry downgraded encryption")
		}
		ownedFunds(t, db, meta.CiphertextSize, 0)
	})
}

func TestEncryptedUploadSizeAndLyricsMustNotParseCiphertext(t *testing.T) {
	_, db, svc := deleteFixture(t)
	ctx := context.Background()
	meta, payload := encryptedFixtureBytes(t, "[00:00.00] encrypted lyric\n")
	stage, err := svc.Stage(ctx, bytes.NewReader(payload[:len(payload)-1]), meta.CiphertextSize)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if _, err = svc.PublishEncrypted(ctx, stage, "bad.lrc", "", "", true, 255, store.AdminAudit{}, &meta); !errors.Is(err, mediacrypto.ErrMetadata) {
		t.Fatal("truncated cipher accepted", err)
	}
	stage, err = svc.Stage(ctx, bytes.NewReader(payload), meta.CiphertextSize)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	name, err := svc.PublishEncrypted(ctx, stage, "secure.lrc", "", "", true, 255, store.AdminAudit{}, &meta)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Media().BindLyric(ctx, store.MediaObject{Path: "music/artist/song.mp3", Kind: "audio"}, store.MediaObject{Path: name, Kind: "lyric"}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Lyrics(ctx, "music/artist/song.mp3"); !errors.Is(err, ErrEncryptedLyric) {
		t.Fatal("cipher treated as lyric text", err)
	}
}
