package httpapi

import (
	"strings"
	"testing"
)

func TestPublicBusinessNavigationUsesRenderedParent(t *testing.T) {
	router, _, _, public := publicFixture(t, true)
	asset := public.assets["js/business-navigation.js"]
	if asset == "" || !strings.Contains(asset, "?v=") {
		t.Fatalf("business navigation needs a content-versioned asset: %q", asset)
	}
	for _, tc := range []struct{ page, parent string }{
		{"/api/v1/media/music", "/api/v1/media"},
		{"/api/v1/media/video", "/api/v1/media"},
		{"/api/v1/media/music/category?path=music/nested", "/api/v1/media/music"},
		{"/api/v1/media/music/category?path=music/nested/album", "/api/v1/media/music/category?path=music%2Fnested"},
		{"/api/v1/media/video/category?path=vido/director", "/api/v1/media/video"},
	} {
		response := request(router, "GET", tc.page, "")
		body := response.Body.String()
		if response.Code != 200 || !strings.Contains(body, `href="`+tc.parent+`" class="back-btn"`) {
			t.Fatalf("%s did not render its business parent %q: %d", tc.page, tc.parent, response.Code)
		}
		if !strings.Contains(body, `src="`+asset+`"`) {
			t.Fatalf("%s omitted the navigation gesture asset", tc.page)
		}
	}
	if strings.Contains(request(router, "GET", "/api/v1/media", "").Body.String(), asset) {
		t.Fatal("the business root must not acquire a return gesture")
	}
}
