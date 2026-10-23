package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func musicArtworkFixture() ([]byte, []byte) {
	frame := func(name string, data []byte) []byte {
		n := len(data)
		return append(append([]byte(name), 0, 0, byte(n>>7), byte(n&127), 0, 0), data...)
	}
	jpeg := append([]byte{255, 216, 255, 224, 0, 16, 'J', 'F', 'I', 'F', 0}, make([]byte, 100)...)
	picture := append([]byte{3}, []byte("image/jpeg\x00\x03\x00")...)
	picture = append(picture, jpeg...)
	body := bytes.Join([][]byte{frame("TIT2", append([]byte{3}, []byte("测试曲目")...)), frame("TPE1", append([]byte{3}, []byte("達明一派")...)), frame("TALB", []byte{3, 'M', 'o', 'r', 'e'}), frame("APIC", picture)}, nil)
	n := len(body)
	data := append([]byte{'I', 'D', '3', 4, 0, 0, 0, 0, byte(n >> 7), byte(n & 127)}, body...)
	return data, jpeg
}

func TestMusicCatalogTagsCoverAndCategoryArtwork(t *testing.T) {
	router, _, dir, _ := publicFixture(t, false)
	data, jpeg := musicArtworkFixture()
	file := filepath.Join(dir, "media/music/artist/song.mp3")
	if err := os.WriteFile(file, data, 0644); err != nil {
		t.Fatal(err)
	}
	w := request(router, "GET", "/api/v1/media/catalog/media?media_type=music&path=music/artist&playback_session_id=tags", "")
	var catalog struct{ Entries []media.Track }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &catalog) != nil || len(catalog.Entries) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	track := catalog.Entries[0]
	if track.Title == "测试曲目" || track.Artist == "達明一派" || track.Album != "" || track.Cover != "/favicon.ico" || !track.NativeMetadata {
		t.Fatal(track)
	}
	metadata := request(router, "GET", "/api/v1/media/metadata?"+url.Values{"file_path": {track.MediaPath}, "resource_id": {track.ResourceID}}.Encode(), "")
	var tags map[string]string
	if metadata.Code != 200 || json.Unmarshal(metadata.Body.Bytes(), &tags) != nil || tags["title"] != "测试曲目" || tags["artist"] != "達明一派" || tags["album"] != "More" || tags["cover"] == "" || metadata.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal(metadata.Code, metadata.Body.String())
	}
	track.Cover = tags["cover"]
	cover := request(router, "GET", track.Cover, "")
	if cover.Code != 200 || cover.Header().Get("Content-Type") != "image/jpeg" || !bytes.Equal(cover.Body.Bytes(), jpeg) {
		t.Fatal(cover.Code, cover.Header())
	}
	etag := cover.Header().Get("ETag")
	if etag == "" {
		t.Fatal("original artwork needs a stable conditional cache validator")
	}
	conditional := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", track.Cover, nil)
		r.Header.Set("If-None-Match", etag)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if cached := conditional(); cached.Code != 304 || cached.Body.Len() != 0 {
		t.Fatal("unchanged original artwork was transferred again", cached.Code)
	}
	w = request(router, "GET", "/api/v1/media/catalog/categories?media_type=music", "")
	var categories struct{ Entries []media.CategoryArtwork }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &categories) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	found := false
	for _, entry := range categories.Entries {
		if entry.Name == "artist" && entry.ArtworkURL != "" {
			if len(entry.MetadataTracks) != 0 || entry.Cover != "" {
				t.Fatal("listing eagerly embedded artwork", entry)
			}
			response := request(router, "GET", entry.ArtworkURL, "")
			var artwork media.CategoryArtwork
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &artwork) != nil || artwork.Cover != "" || len(artwork.MetadataTracks) != 1 || !artwork.MetadataTracks[0].NativeMetadata {
				t.Fatal(response.Code, response.Body.String())
			}
			found = true
		}
	}
	if !found {
		t.Fatal(categories)
	}
	for _, target := range []string{"/api/v1/media/catalog/artwork?path=music/missing", "/api/v1/media/catalog/artwork?path=video/artist", "/api/v1/media/catalog/artwork?path=../music/artist"} {
		if response := request(router, "GET", target, ""); response.Code != 404 {
			t.Fatal("invalid artwork path accepted", target, response.Code)
		}
	}
	// A deleted file must not be disclosed from the derived-picture cache.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if cover = request(router, "GET", track.Cover, ""); cover.Code != 404 {
		t.Fatal("cached cover survived deletion", cover.Code)
	}
	if cached := conditional(); cached.Code != 404 {
		t.Fatal("conditional cache bypassed source deletion", cached.Code)
	}
}

func TestMusicArtworkPrimaryDirectRelay(t *testing.T) {
	ctx := context.Background()
	wire := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, db, _, public, master := clusterFixture(t, "https://music-master.test", wire, false)
	_, _, _, _, follower := clusterFixture(t, "https://music-storage.test", wire, true)
	if _, err := master.Promote(ctx, "Master", "https://music-master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := follower.Promote(ctx, "Follower", "https://music-storage.test", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	pack, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relID, err := master.ImportPair(ctx, pack, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := db.Nodes().Relationship(ctx, relID)
	if err != nil {
		t.Fatal(err)
	}
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 5*store.GiB
	if err := db.Pool().ConfigureMember(ctx, relation.PeerID, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := master.Tick(ctx, relation); err != nil {
		t.Fatal(err)
	}
	data, jpeg := musicArtworkFixture()
	for _, site := range []string{"primary", "direct", "relay"} {
		t.Run(site, func(t *testing.T) {
			if site != "primary" {
				mode := "Direct"
				if site == "relay" {
					mode = "Relay"
				}
				if err := db.Nodes().SetRelationshipMode(ctx, relID, mode, false, store.NodeAudit{}); err != nil {
					t.Fatal(err)
				}
			}
			folder := "music/Artwork-" + site
			ticket, err := public.media.ReserveMasterUpload(ctx, "tagged.mp3", folder, "", site, int64(len(data)), 255, store.AdminAudit{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := public.media.UploadMasterBytes(ctx, ticket.ID, bytes.NewReader(data), store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			w := request(router, "GET", "/api/v1/media/catalog/media?media_type=music&path="+folder+"&playback_session_id=tags", "")
			var result struct{ Entries []media.Track }
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Entries) != 1 {
				t.Fatal(w.Code, w.Body.String())
			}
			track := result.Entries[0]
			if !track.NativeMetadata || track.Artist == "達明一派" || track.Cover != "/favicon.ico" {
				t.Fatal(track)
			}
			metadata := request(router, "GET", "/api/v1/media/metadata?"+url.Values{"file_path": {track.MediaPath}, "resource_id": {track.ResourceID}}.Encode(), "")
			var tags map[string]string
			if metadata.Code != 200 || json.Unmarshal(metadata.Body.Bytes(), &tags) != nil || tags["artist"] != "達明一派" || tags["album"] != "More" {
				t.Fatal(metadata.Code, metadata.Body.String())
			}
			track.Cover = tags["cover"]
			cover := request(router, "GET", track.Cover, "")
			if cover.Code != 200 || !bytes.Equal(cover.Body.Bytes(), jpeg) {
				t.Fatal(site, cover.Code, cover.Body.String())
			}
		})
	}
	// A remote ID3v1-only track needs only its ten-byte prefix and final 128
	// bytes. Cold catalog/artwork reads must not reach the peer media endpoint.
	payload := make([]byte, 512)
	copy(payload, "ID3")
	copy(payload[384:], "TAG")
	copy(payload[387:417], "Legacy title")
	copy(payload[417:447], "Legacy artist")
	copy(payload[447:477], "Legacy album")
	ticket, err := public.media.ReserveMasterUpload(ctx, "legacy.mp3", "music/Legacy", "", "relay", int64(len(payload)), 255, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = public.media.UploadMasterBytes(ctx, ticket.ID, bytes.NewReader(payload), store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	ranges := []string{}
	wire.mediaReadHook = func(value string) { ranges = append(ranges, value) }
	for _, target := range []string{"/api/v1/media/catalog/media?media_type=music&path=music/Legacy&playback_session_id=cold", "/api/v1/media/catalog/artwork?path=music/Legacy"} {
		if result := request(router, "GET", target, ""); result.Code != 200 {
			t.Fatal(result.Code, result.Body.String())
		}
	}
	if len(ranges) != 0 {
		t.Fatal("cold directory read remote bytes", ranges)
	}
	metadata := request(router, "GET", "/api/v1/media/metadata?"+url.Values{"file_path": {ticket.Path}, "resource_id": {ticket.MediaID}}.Encode(), "")
	var tags map[string]string
	if metadata.Code != 200 || json.Unmarshal(metadata.Body.Bytes(), &tags) != nil || tags["title"] != "Legacy title" || tags["artist"] != "Legacy artist" || tags["album"] != "Legacy album" || strings.Join(ranges, ",") != "bytes=0-9,bytes=384-511" {
		t.Fatal(metadata.Code, metadata.Body.String(), ranges)
	}
	for _, target := range []string{
		"/api/v1/media/metadata?file_path=" + url.QueryEscape(ticket.Path) + "&resource_id=" + strings.Repeat("f", 64),
		"/api/v1/media/metadata?file_path=music/elsewhere/wrong.mp3&resource_id=" + ticket.MediaID,
		"/api/v1/media/metadata?file_path=" + url.QueryEscape(ticket.Path) + "&resource_id=invalid",
	} {
		if result := request(router, "GET", target, ""); result.Code != 404 {
			t.Fatal("metadata ignored exact path/identity", target, result.Code)
		}
	}
}
