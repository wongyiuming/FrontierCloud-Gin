package httpapi

import (
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// Exercise the handlers with an in-memory tree configuration and a separate
// legacy business DB: a durable marker check alone cannot cover this partial
// installation. Authentication is supplied by the real protected routes in
// production; this fixture tests the handlers' response boundary.
func TestOpaquePartialInstallRejectsLegacyDeliveryAndAdminDownloads(t *testing.T) {
	router, _, _, public := publicFixture(t, false)
	admin := &Admin{settings: public.settings, public: public}
	group := router.Group("/partial-admin")
	group.GET("/bytes", admin.cryptoBytes)
	group.GET("/download", admin.download)
	group.GET("/plan", admin.downloadPlan)
	group.GET("/plan-bytes", admin.downloadPlanBytes)
	stream := "/api/v1/media/stream?file_path=music/artist/song.mp3"
	if response := request(router, "GET", stream, ""); response.Code != 200 {
		t.Fatal("legacy stream unavailable", response.Code, response.Body.String())
	}
	if response := request(router, "GET", "/partial-admin/bytes?file_path=music/artist/song.mp3", ""); response.Code != 200 {
		t.Fatal("legacy Admin bytes unavailable", response.Code, response.Body.String())
	}
	public.opaqueTree = &sealedtree.SQLStore{}
	for _, target := range []string{stream, "/partial-admin/bytes?file_path=music/artist/song.mp3", "/partial-admin/download", "/partial-admin/plan", "/partial-admin/plan-bytes"} {
		response := request(router, "GET", target, "")
		if response.Code != 503 || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("legacy path %s returned %d", target, response.Code)
		}
	}
}
