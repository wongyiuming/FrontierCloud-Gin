package httpapi

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

func TestRequestAndErrorLogsDoNotPersistClientPaths(t *testing.T) {
	var log bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&log, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(requests(resolver))
	router.GET("/media/*path", func(c *gin.Context) {
		internalError(c, &os.PathError{Op: "open", Path: "SECRET_FILE_NAME", Err: os.ErrNotExist})
	})
	for _, path := range []string{"/media/SECRET_FILE_NAME?token=SECRET_TOKEN", "/SECRET_FILE_NAME?token=SECRET_TOKEN"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	}
	server := NewWithResolver(func(context.Context) error { return nil }, nil, resolver)
	server.GET("/panic/*path", func(*gin.Context) { panic("SECRET_FILE_NAME SECRET_TOKEN") })
	panicResult := httptest.NewRecorder()
	server.ServeHTTP(panicResult, httptest.NewRequest(http.MethodGet, "/panic/SECRET_FILE_NAME?token=SECRET_TOKEN", nil))
	if panicResult.Code != http.StatusInternalServerError {
		t.Fatal("panic did not produce an error response", panicResult.Code)
	}
	output := log.String()
	if strings.Contains(output, "SECRET_FILE_NAME") || strings.Contains(output, "SECRET_TOKEN") {
		t.Fatal("sensitive request or error appeared in log")
	}
	for _, expected := range []string{`"path":"/media/*path"`, `"path":"/unmatched"`, `"path":"/panic/*path"`, `"msg":"request panic"`, `"error_type":"not_found"`, `"status":500`, `"status":404`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing safe diagnostic %s", expected)
		}
	}
}
