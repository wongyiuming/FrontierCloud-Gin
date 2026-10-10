package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
)

func TestPublicCryptoRoutesShipCompiledAssets(t *testing.T) {
	router, _, _, public := publicFixture(t, false)
	for _, name := range []string{"media-crypto-common.js", "media-crypto.js", "media-crypto-sw.js"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			if w := request(router, method, "/static/js/"+name, ""); w.Code != http.StatusNotFound {
				t.Fatalf("source module served: %s %s status=%d", method, name, w.Code)
			}
		}
		compiled, err := os.ReadFile(filepath.Join(public.settings.StaticRoot, "js", "compiled", name))
		if err != nil {
			t.Fatal(err)
		}
		w := request(router, http.MethodGet, public.assets["js/compiled/"+name], "")
		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), compiled) {
			t.Fatalf("compiled asset bytes changed: %s status=%d", name, w.Code)
		}
		if name == "media-crypto-sw.js" {
			w = request(router, http.MethodGet, "/media-crypto-sw.js", "")
			if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), compiled) || w.Header().Get("Service-Worker-Allowed") != "/" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
				t.Fatal("root worker did not ship the compiled scoped script", w.Code, w.Header())
			}
		}
	}
	for _, target := range []string{"/api/v1/media", "/api/v1/media/music", "/api/v1/media/music/category?path=music/artist", "/api/v1/media/video/category?path=vido/director", "/api/v1/media/lyrics?track=music/artist/song.mp3"} {
		w := request(router, http.MethodGet, target, "")
		if w.Code != http.StatusOK {
			t.Fatalf("crypto page %s: status=%d", target, w.Code)
		}
		for _, name := range []string{"media-crypto-common.js", "media-crypto.js"} {
			if !strings.Contains(w.Body.String(), public.assets["js/compiled/"+name]) || strings.Contains(w.Body.String(), "/static/js/"+name) {
				t.Fatalf("page %s did not select compiled %s", target, name)
			}
		}
	}
}

func TestPublicStartupRequiresEachCompiledCryptoModule(t *testing.T) {
	required := []string{"js/player.js", "css/player.css", "js/lyrics.js", "css/lyrics.css", "js/media-browser.js", "js/network-observation.js", "js/player-directory-label.js", "js/audio-continuous-stream.js", "css/karaoke.css", "js/karaoke.js", "js/compiled/media-crypto-common.js", "js/compiled/media-crypto.js", "js/compiled/media-crypto-sw.js"}
	for _, missing := range required[10:] {
		t.Run(filepath.Base(missing), func(t *testing.T) {
			staticRoot := t.TempDir()
			for _, name := range required {
				if name == missing {
					continue
				}
				destination := filepath.Join(staticRoot, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(destination, []byte("fixture"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			_, err := RegisterPublic(New(pass, pass), config.Config{StaticRoot: staticRoot}, nil)
			if !errors.Is(err, os.ErrNotExist) || !strings.Contains(filepath.ToSlash(err.Error()), missing) {
				t.Fatal("startup did not reject missing compiled module", missing, err)
			}
		})
	}
}
