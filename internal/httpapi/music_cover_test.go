package httpapi

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
)

func TestMusicCatalogTagsCoverAndCategoryArtwork(t *testing.T) {
	router, _, dir, _ := publicFixture(t, false)
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
	if track.Title != "测试曲目" || track.Artist != "達明一派" || track.Album != "More" || track.Cover == "/favicon.ico" {
		t.Fatal(track)
	}
	cover := request(router, "GET", track.Cover, "")
	if cover.Code != 200 || cover.Header().Get("Content-Type") != "image/jpeg" || !bytes.Equal(cover.Body.Bytes(), jpeg) {
		t.Fatal(cover.Code, cover.Header())
	}
	w = request(router, "GET", "/api/v1/media/catalog/categories?media_type=music", "")
	var categories struct{ Entries []media.CategoryArtwork }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &categories) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	found := false
	for _, entry := range categories.Entries {
		if entry.Name == "artist" && entry.Cover == track.Cover {
			found = true
		}
	}
	if !found {
		t.Fatal(categories)
	}
	// A deleted file must not be disclosed from the derived-picture cache.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if cover = request(router, "GET", track.Cover, ""); cover.Code != 404 {
		t.Fatal("cached cover survived deletion", cover.Code)
	}
}
