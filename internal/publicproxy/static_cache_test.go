package publicproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionedPublicAssetCacheBoundary(t *testing.T) {
	for _, tc := range []struct {
		path, mime   string
		status       int
		cookie, want bool
	}{
		{"/static/js/compiled/media-crypto.js?v=0123456789abcdef", "text/javascript; charset=utf-8", 200, false, true},
		{"/static/css/player.css?v=0123456789abcdef", "text/css", 200, false, true},
		{"/static/js/player.js", "text/javascript", 200, false, false},
		{"/static/js/player.js?v=0123456789abcdef&v=0123456789abcdef", "text/javascript", 200, false, false},
		{"/static/js/player.js?v=0123456789abcdeg", "text/javascript", 200, false, false},
		{"/static/js/admin.js?v=0123456789abcdef", "text/javascript", 200, false, false},
		{"/api/v1/media/crypto/key?v=0123456789abcdef", "application/json", 200, false, false},
		{"/media-crypto-sw.js?v=0123456789abcdef", "text/javascript", 200, false, false},
		{"/static/js/player.js?v=0123456789abcdef", "text/html", 200, false, false},
		{"/static/js/player.js?v=0123456789abcdef", "text/javascript", 503, false, false},
		{"/static/js/player.js?v=0123456789abcdef", "text/javascript", 200, true, false},
	} {
		t.Run(tc.path+tc.mime, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			resp := &http.Response{StatusCode: tc.status, Header: make(http.Header)}
			resp.Header.Set("Content-Type", tc.mime)
			if tc.cookie {
				resp.Header.Set("Set-Cookie", "session=private")
			}
			if got := versionedPublicAsset(req, resp); got != tc.want {
				t.Fatalf("cache=%v want %v", got, tc.want)
			}
		})
	}
}
