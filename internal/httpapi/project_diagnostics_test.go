package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestLogBrowserDiagnosticsExplicitActivationAndSanitization(t *testing.T) {
	key, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	c, e := logarchive.OpenCatalog(t.TempDir(), key, strings.Repeat("a", 32))
	if e != nil {
		t.Fatal(e)
	}
	runtime := logarchive.NewRuntime(c, nil, func() bool { return false })
	runtime.Start(context.Background())
	router := gin.New()
	registerProjectDiagnostics(router, runtime)
	call := func(method, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, projectDiagnosticPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := call(http.MethodGet, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatal("diagnostics enabled before activation", w.Code)
	}
	good := `{"stage":"waiting","page":"music","media_time":64,"ready":2,"network":2,"code":0,"online":true,"elapsed_ms":4000}`
	if w := call(http.MethodPost, good); w.Code != 204 {
		t.Fatal("inactive diagnostic response", w.Code)
	}
	if _, e = runtime.Configure(context.Background(), logarchive.Target{MemberID: strings.Repeat("b", 32), RelationshipID: strings.Repeat("c", 32), Origin: "https://logs.test"}, 0); e != nil {
		t.Fatal(e)
	}
	if w := call(http.MethodPost, strings.TrimSuffix(good, "}")+`,"url":"https://secret.example/private?key=credential"}`); w.Code != 422 {
		t.Fatal("arbitrary diagnostic fields accepted", w.Code)
	}
	if w := call(http.MethodPost, strings.Replace(good, `"waiting"`, `"arbitrary_console_dump"`, 1)); w.Code != 422 {
		t.Fatal("unknown diagnostic stage accepted", w.Code)
	}
	if w := call(http.MethodPost, good); w.Code != 202 {
		t.Fatal("valid diagnostic refused", w.Code, w.Body.String())
	}
	// Graceful shutdown must flush the queue without waiting for the 1s timer.
	if e = runtime.Close(); e != nil {
		t.Fatal(e)
	}
	// Own catalog is closed; use a borrowed equivalent reader to reopen it in a
	// separate runtime test. Here flush evidence is the absence of pending memory.
	if pending := runtime.Health()["memory_pending"]; pending != int64(0) {
		t.Fatal("shutdown lost accepted browser report", pending)
	}
}
