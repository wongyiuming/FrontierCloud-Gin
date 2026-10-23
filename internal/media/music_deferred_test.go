package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestColdMusicCatalogAndArtworkDoNotReadTags(t *testing.T) {
	root, db, service := deleteFixture(t)
	identity, err := node.Initialize(context.Background(), db.Nodes(), filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	service.identity = identity
	for i := 0; i < 120; i++ {
		file := filepath.Join(root, "music/artist", fmt.Sprintf("%03d.mp3", i))
		if err := os.WriteFile(file, tagFixture(3, tagFrame(3, "TIT2", []byte("\x03Embedded title"))), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	tracks, err := service.Catalog(ctx, "music", "music/artist", "cold", false)
	if err != nil {
		t.Fatal(err)
	}
	service.DecorateMusicTracks(ctx, tracks)
	if len(tracks) != 121 || len(service.tagsCache) != 0 {
		t.Fatal("cold catalog eagerly extracted tags", len(tracks), len(service.tagsCache))
	}
	for _, track := range tracks {
		if !track.NativeMetadata || track.Title == "Embedded title" || track.Cover != "/favicon.ico" {
			t.Fatal(track)
		}
	}
	art, err := service.DirectoryArtwork(ctx, "music/artist", false)
	if err != nil {
		t.Fatal(err)
	}
	if art.Cover != "" || len(art.MetadataTracks) != 8 || len(service.tagsCache) != 0 {
		t.Fatal("artwork exceeded its cheap candidate budget", art, len(service.tagsCache))
	}
	for _, track := range art.MetadataTracks {
		if !track.NativeMetadata {
			t.Fatal(track)
		}
	}
	if _, err := service.MusicMetadata(ctx, tracks[0].MediaPath, ""); err != nil {
		t.Fatal(err)
	}
	if len(service.tagsCache) != 1 {
		t.Fatal("single selected metadata did not fill one cache entry", len(service.tagsCache))
	}
}

func TestMusicArtworkUsesOneCandidateBudgetAcrossChildren(t *testing.T) {
	root, db, service := deleteFixture(t)
	identity, err := node.Initialize(context.Background(), db.Nodes(), filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	service.identity = identity
	for dir := 0; dir < 12; dir++ {
		folder := filepath.Join(root, "music/Many", fmt.Sprintf("%02d", dir))
		if err := os.MkdirAll(folder, 0700); err != nil {
			t.Fatal(err)
		}
		for file := 0; file < 2; file++ {
			if err := os.WriteFile(filepath.Join(folder, fmt.Sprintf("%02d.mp3", file)), []byte("ID3payload"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	art, err := service.DirectoryArtwork(context.Background(), "music/Many", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(art.MetadataTracks) != 8 || len(service.tagsCache) != 0 {
		t.Fatal("per-child budget caused unbounded metadata work", len(art.MetadataTracks), len(service.tagsCache))
	}
}

func TestDeferredMusicMetadataPreservesEncryptionAndNonQueuingAdmission(t *testing.T) {
	_, _, service := deleteFixture(t)
	tracks := []Track{{Type: "audio", MediaPath: "music/a/plain.mp3"}, {Type: "audio", MediaPath: "music/a/encrypted.mp3", Encryption: &mediacrypto.Metadata{}}, {Type: "video", MediaPath: "vido/a/video.mp4"}, {Type: "audio", MediaPath: "music/a/other.flac"}}
	service.DecorateMusicTracks(context.Background(), tracks)
	for i, track := range tracks {
		if track.NativeMetadata != (i == 0) {
			t.Fatal("server metadata enabled outside plain MP3 boundary", track)
		}
	}
	service.metadataSlots = make(chan struct{}, 2)
	service.metadataSlots <- struct{}{}
	service.metadataSlots <- struct{}{}
	if _, err := service.MusicMetadata(context.Background(), "music/artist/song.mp3", ""); !errors.Is(err, ErrMetadataBusy) {
		t.Fatal("busy metadata queued a tag read", err)
	}
	<-service.metadataSlots
	if _, err := service.MusicMetadata(context.Background(), "music/artist/song.mp3", "invalid"); !errors.Is(err, ErrPath) {
		t.Fatal("invalid identity accepted", err)
	}
	if len(service.metadataSlots) != 1 {
		t.Fatal("failed read leaked metadata admission")
	}
}

func TestAuthorizedWarmMusicMetadataBypassesBusyHeavySlots(t *testing.T) {
	root, _, service := deleteFixture(t)
	ctx := context.Background()
	name := "music/artist/song.mp3"
	if err := os.WriteFile(filepath.Join(root, name), tagFixture(3, tagFrame(3, "TIT2", []byte("\x03Cached title"))), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := service.MusicMetadata(ctx, name, "")
	if err != nil || first.Title != "Cached title" {
		t.Fatal(first, err)
	}
	service.metadataSlots <- struct{}{}
	service.metadataSlots <- struct{}{}
	if cached, err := service.MusicMetadata(ctx, name, ""); err != nil || cached.Title != first.Title {
		t.Fatal("cached original artwork competed with heavy reads", cached, err)
	}
	if err := os.Remove(filepath.Join(root, name)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.MusicMetadata(ctx, name, ""); err == nil {
		t.Fatal("cache bypassed current source authorization")
	}
}

func TestSelectedMusicMetadataNeverReadsEncryptedPayload(t *testing.T) {
	_, db, service := deleteFixture(t)
	ctx := context.Background()
	meta, payload := encryptedFixtureBytes(t, "ID3encrypted music tags remain browser-only")
	stage, err := service.Stage(ctx, bytes.NewReader(payload), meta.CiphertextSize)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	name, err := service.PublishEncrypted(ctx, stage, "private.mp3", "music/artist", "", false, 255, store.AdminAudit{}, &meta)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: name, Kind: "audio"}})
	if err != nil {
		t.Fatal(err)
	}
	tags, err := service.MusicMetadata(ctx, name, ids[name])
	if err != nil || tags.Title != "" || tags.Artist != "" || tags.Album != "" || len(tags.Picture) != 0 || len(service.tagsCache) != 0 {
		t.Fatal("encrypted bytes entered native metadata cache", tags, err)
	}
	object, err := db.Media().(store.EncryptionRepository).Encryption(ctx, ids[name])
	if err != nil || object == nil || *object != meta {
		t.Fatal("descriptor changed", object, err)
	}
}
