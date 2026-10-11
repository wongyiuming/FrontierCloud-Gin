package media

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestAdminTreeAndSearchPreserveEncryptionAcrossRename(t *testing.T) {
	for _, role := range []string{"Standalone", "Master"} {
		t.Run(role, func(t *testing.T) {
			fixture := deleteFixture
			if role == "Master" {
				fixture = masterFixture
			}
			_, db, svc := fixture(t)
			ctx := context.Background()
			meta, payload := encryptedFixtureBytes(t, "ID3encrypted-admin-tree")
			name := "music/artist/encrypted.mp3"
			if role == "Master" {
				ticket, err := svc.ReserveMasterEncryptedUpload(ctx, "encrypted.mp3", "music/artist", "", "primary", meta.CiphertextSize, 255, store.AdminAudit{}, &meta)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = svc.UploadMasterBytes(ctx, ticket.ID, bytes.NewReader(payload), store.AdminAudit{}); err != nil {
					t.Fatal(err)
				}
			} else {
				stage, err := svc.Stage(ctx, bytes.NewReader(payload), meta.CiphertextSize)
				if err != nil {
					t.Fatal(err)
				}
				defer stage.Close()
				if _, err = svc.PublishEncrypted(ctx, stage, "encrypted.mp3", "music/artist", "", false, 255, store.AdminAudit{}, &meta); err != nil {
					t.Fatal(err)
				}
			}
			ids, err := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: name, Kind: "audio"}})
			if err != nil {
				t.Fatal(err)
			}
			check := func(scope, name string, expected *mediacrypto.Metadata) {
				t.Helper()
				tree, err := svc.Tree(ctx, scope)
				if err != nil {
					t.Fatal(err)
				}
				search, err := svc.Search(ctx, "encrypted", scope)
				if err != nil {
					t.Fatal(err)
				}
				for _, items := range [][]TreeItem{tree.Items, search.Items} {
					found := false
					for _, item := range items {
						if item.Path != name {
							continue
						}
						found = true
						if item.Encryption == nil || *item.Encryption != *expected || item.MediaID == "" {
							t.Fatalf("encrypted item lacks its descriptor: %+v", item)
						}
						encoded, err := json.Marshal(item)
						if err != nil || !bytes.Contains(encoded, []byte(`"encryption":`)) {
							t.Fatal("Admin JSON omitted encryption", err)
						}
					}
					if !found {
						t.Fatal("encrypted item missing", name)
					}
				}
				for _, item := range tree.Items {
					if item.Name == "song.mp3" && item.Encryption != nil {
						t.Fatal("plaintext sibling marked encrypted")
					}
				}
			}
			check("music/artist", name, &meta)
			if _, err = svc.Rename(ctx, "music/artist", "tree-renamed", store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			name = "music/tree-renamed/encrypted.mp3"
			check("music/tree-renamed", name, &meta)
			if _, err = db.Database().Exec("UPDATE media_encryption SET descriptor_json='invalid' WHERE object_kind='media' AND object_id=?", ids["music/artist/encrypted.mp3"]); err != nil {
				t.Fatal(err)
			}
			if _, err = svc.Tree(ctx, "music/tree-renamed"); err == nil {
				t.Fatal("corrupt descriptor presented as plaintext")
			}
		})
	}
}

func TestAdminLyricTreeAndSearchIncludeEncryption(t *testing.T) {
	_, _, svc := deleteFixture(t)
	ctx := context.Background()
	meta, payload := encryptedFixtureBytes(t, "[00:00.00] encrypted-admin-lyric")
	stage, err := svc.Stage(ctx, bytes.NewReader(payload), meta.CiphertextSize)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	name, err := svc.PublishEncrypted(ctx, stage, "encrypted.lrc", "", "", true, 255, store.AdminAudit{}, &meta)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := svc.Tree(ctx, "lyrics")
	if err != nil {
		t.Fatal(err)
	}
	search, err := svc.Search(ctx, "encrypted", "lyrics")
	if err != nil {
		t.Fatal(err)
	}
	for _, items := range [][]TreeItem{tree.Items, search.Items} {
		found := false
		for _, item := range items {
			if item.Path == name {
				found = true
				if item.Encryption == nil || *item.Encryption != meta || item.Media || item.MediaID == "" {
					t.Fatalf("lyric descriptor missing: %+v", item)
				}
			}
		}
		if !found {
			t.Fatal("encrypted lyric missing")
		}
	}
}
