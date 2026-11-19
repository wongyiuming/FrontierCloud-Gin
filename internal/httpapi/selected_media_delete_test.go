package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSelectedMediaDeleteRequiresExactManagedTargets(t *testing.T) {
	resource := strings.Repeat("a", 64)
	operation := strings.Repeat("b", 32)
	valid := `{"path":"music/作者/曲目.mp3","resource_id":"` + resource + `","operation_id":"` + operation + `"}`
	folder := strings.TrimSuffix(strings.Replace(valid, "music/作者/曲目.mp3", "music/作者", 1), "}") + `,"directory":true}`
	for _, tc := range []struct {
		name, body, query string
		ok, directory     bool
	}{
		{name: "resume", body: `{"targets":[` + valid + `]}`, ok: true},
		{name: "legacy paths", body: `{"paths":["music/作者/曲目.mp3"]}`},
		{name: "mixed shape", body: `{"targets":[` + valid + `],"paths":[]}`},
		{name: "unknown locator", body: `{"targets":[` + strings.TrimSuffix(valid, "}") + `,"object_id":"secret"}]}`},
		{name: "root", body: `{"targets":[` + strings.Replace(valid, "music/作者/曲目.mp3", "music", 1) + `]}`},
		{name: "folder", body: `{"targets":[` + strings.Replace(valid, "music/作者/曲目.mp3", "music/作者", 1) + `]}`},
		{name: "exact folder", body: `{"targets":[` + folder + `]}`, ok: true, directory: true},
		{name: "protected folder", body: `{"targets":[` + strings.Replace(folder, "music/作者", "music", 1) + `]}`},
		{name: "internal default", body: `{"targets":[` + strings.Replace(valid, "music/作者/曲目.mp3", "lyrics/default.lrc", 1) + `]}`},
		{name: "path alias", body: `{"targets":[` + strings.Replace(valid, "music/作者/曲目.mp3", "music//作者/曲目.mp3", 1) + `]}`},
		{name: "invalid resource", body: `{"targets":[` + strings.Replace(valid, resource, strings.ToUpper(resource), 1) + `]}`},
		{name: "invalid operation", body: `{"targets":[` + strings.Replace(valid, operation, "1234", 1) + `]}`},
		{name: "duplicate resource", body: `{"targets":[` + valid + `,` + strings.Replace(valid, "曲目.mp3", "另一个.mp3", 1) + `]}`},
		{name: "query", body: `{"targets":[` + valid + `]}`, query: "?retry=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/media/admin/delete"+tc.query, strings.NewReader(tc.body))
			c.Request.Header.Set("Content-Type", "application/json")
			got, ok := selectedMediaDeleteTargets(c, 2)
			if ok != tc.ok || ok && (len(got) != 1 || got[0].ResourceID != resource || got[0].OperationID != operation || got[0].Directory != tc.directory) {
				t.Fatalf("targets = %+v, accepted = %v", got, ok)
			}
		})
	}
}

func TestSelectedMediaDeleteStateMustMatchExactOperation(t *testing.T) {
	target := store.SelectedMediaDeleteTarget{Path: "music/a/song.mp3", ResourceID: strings.Repeat("a", 64), OperationID: strings.Repeat("b", 32)}
	for _, tc := range []struct {
		name   string
		item   store.SelectedMediaDeleteItem
		status int
	}{
		{"pending", store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: target, State: store.SelectedMediaDeletePending}, http.StatusAccepted},
		{"deleted", store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: target, State: store.SelectedMediaDeleteDeleted}, http.StatusOK},
		{"missing state", store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: target}, 0},
		{"replacement resource", store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: store.SelectedMediaDeleteTarget{Path: target.Path, ResourceID: strings.Repeat("c", 64), OperationID: target.OperationID}, State: store.SelectedMediaDeleteDeleted}, 0},
		{"replacement operation", store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: store.SelectedMediaDeleteTarget{Path: target.Path, ResourceID: target.ResourceID, OperationID: strings.Repeat("d", 32)}, State: store.SelectedMediaDeleteDeleted}, 0},
		{"replacement kind", store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: store.SelectedMediaDeleteTarget{Path: target.Path, ResourceID: target.ResourceID, OperationID: target.OperationID, Directory: true}, State: store.SelectedMediaDeleteDeleted}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := store.SelectedMediaDeleteResult{Items: []store.SelectedMediaDeleteItem{tc.item}}
			if got, ok := selectedMediaDeleteStatus([]store.SelectedMediaDeleteTarget{target}, result); got != tc.status || ok != (tc.status != 0) {
				t.Fatalf("status = %d, accepted = %v", got, ok)
			}
		})
	}
}

func TestSelectedMediaDeleteDoesNotFallBackWithoutCoordinator(t *testing.T) {
	admin := &Admin{public: &Public{opaqueTree: &sealedtree.SQLStore{}}}
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/media/admin/delete", strings.NewReader(`{"paths":["music/a/song.mp3"]}`))
	c.Request.Header.Set("Content-Type", "application/json")
	admin.delete(c)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("sealed route did not fail closed: %d %s", response.Code, response.Body)
	}
}
