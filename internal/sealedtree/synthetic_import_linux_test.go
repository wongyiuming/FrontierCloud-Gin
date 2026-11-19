//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

// This only exercises synthetic local files and SQLite. It is not a snapshot
// exporter, a node receipt, a permission/visibility migration, or activation.
func TestSyntheticImportPreservesPayloadSemanticsWithoutTreePlaintext(t *testing.T) {
	ctx := context.Background()
	masterSecret, err := NewMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(masterSecret)
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	tree, err := New(masterSecret, salt)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "synthetic.sqlite")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filename)+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rootID := strings.Repeat("1", 64)
	store, err := InitializeSQLite(ctx, db, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	store.unsafePrototype = true // synthetic fixture only; not a runtime activation
	directRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directRoot.Close()
	masterRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer masterRoot.Close()
	directPub, _ := NewBlobPublisher(directRoot)
	masterPub, _ := NewBlobPublisher(masterRoot)
	directory := Entry{ParentID: rootID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "合成专辑"}
	empty := Entry{ParentID: directory.ObjectID, ObjectID: strings.Repeat("3", 64), Kind: "directory", Name: "空目录"}
	dirFacts := Facts{ObjectID: directory.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}
	if err = store.CreateDirectoryWithFacts(ctx, directory, dirFacts); err != nil {
		t.Fatal(err)
	}
	if err = store.Create(ctx, empty); err != nil {
		t.Fatal(err)
	}
	mediaMaster := bytes.Repeat([]byte{0x52}, 32)
	manager, err := mediacrypto.New(mediaMaster)
	if err != nil {
		t.Fatal(err)
	}
	cleartext := []byte("independent plaintext content")
	protected := []byte("independent encrypted content")
	metadata, err := mediacrypto.NewMetadata(int64(len(protected)))
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := manager.FileKey(metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fileKey)
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := metadata.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, protected, metadata.ChunkAAD(0))
	type item struct {
		entry      Entry
		data       []byte
		encryption *mediacrypto.Metadata
		owner      string
		pub        *BlobPublisher
		root       *os.Root
	}
	items := []item{
		{Entry{ParentID: directory.ObjectID, ObjectID: strings.Repeat("4", 64), Kind: "audio", Name: "明文歌曲.mp3"}, cleartext, nil, strings.Repeat("a", 32), directPub, directRoot},
		{Entry{ParentID: directory.ObjectID, ObjectID: strings.Repeat("5", 64), Kind: "audio", Name: "密文歌曲.mp3"}, ciphertext, &metadata, strings.Repeat("b", 32), masterPub, masterRoot},
	}
	var secrets = []string{directory.Name, empty.Name, directory.ObjectID, empty.ObjectID, rootID}
	for _, v := range items {
		blob, err := NewBlobID()
		if err != nil {
			t.Fatal(err)
		}
		alias, err := NewBlobID()
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(v.data)
		loc := Placement{ObjectID: v.entry.ObjectID, NativeObjectID: v.entry.ObjectID, OwnerID: v.owner, BlobID: blob, ReadAlias: alias, Bytes: int64(len(v.data)), SHA256: hex.EncodeToString(sum[:]), ETag: "synthetic-version", State: "active", CreatedAt: 123, UpdatedAt: 124, Encryption: v.encryption}
		facts := fixtureFacts(v.entry.ObjectID)
		facts.Playback.LegacyMediaPath = "music/合成专辑/" + v.entry.Name
		facts.Lyric.LegacyMediaPath = facts.Playback.LegacyMediaPath
		op, err := store.PrepareFileWithFacts(ctx, v.entry, loc, facts)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.PublishPending(ctx, op, v.pub, bytes.NewReader(v.data)); err != nil {
			t.Fatal(err)
		}
		entry, _, err := store.Get(ctx, v.entry.ObjectID)
		if err != nil || entry != v.entry {
			t.Fatalf("identity lost: %v", err)
		}
		got, err := store.GetPlacement(ctx, v.entry.ObjectID)
		if err != nil || !reflect.DeepEqual(got, loc) {
			t.Fatalf("placement changed: %v", err)
		}
		gotFacts, _, err := store.GetFacts(ctx, v.entry.ObjectID)
		if err != nil || !reflect.DeepEqual(gotFacts, facts) {
			t.Fatal("synthetic visibility, statistics or lyric fact changed", err)
		}
		physical, err := BlobPath(blob)
		if err != nil {
			t.Fatal(err)
		}
		f, err := v.root.Open(physical)
		if err != nil {
			t.Fatal(err)
		}
		buf := new(bytes.Buffer)
		if _, err = buf.ReadFrom(f); err != nil {
			f.Close()
			t.Fatal(err)
		}
		_ = f.Close()
		if !bytes.Equal(buf.Bytes(), v.data) {
			t.Fatal("stored content changed")
		}
		if v.encryption != nil {
			decoded, err := aead.Open(nil, nonce, buf.Bytes(), metadata.ChunkAAD(0))
			if err != nil || !bytes.Equal(decoded, protected) {
				t.Fatal("encrypted content not preserved")
			}
		}
		secrets = append(secrets, v.entry.Name, v.entry.ObjectID, v.owner, blob, alias, loc.SHA256, facts.Playback.LegacyMediaPath, facts.Lyric.LegacyLyricPath)
	}
	if got, _, err := store.GetFacts(ctx, directory.ObjectID); err != nil || !reflect.DeepEqual(got, dirFacts) {
		t.Fatal("directory visibility changed", err)
	}
	if _, _, err = store.Get(ctx, empty.ObjectID); err != nil {
		t.Fatal("empty directory lost")
	}
	if count, err := store.Check(ctx); err != nil || count != 4 {
		t.Fatalf("synthetic catalog invalid: %d %v", count, err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(filename + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatalf("synthetic metadata plaintext in %s", suffix)
			}
		}
	}
}
