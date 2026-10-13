package httpapi

import (
	"bytes"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
	"io"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBusinessTrafficCountsStreamingBytesBeforeRequestCompletion(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	now := time.Unix(1800000000, 0)
	m := businesstraffic.New(func() time.Time { return now })
	now = now.Add(businesstraffic.LowInterval)
	router := gin.New()
	router.Use(BusinessTrafficMiddleware(m))
	router.POST("/business", func(c *gin.Context) {
		// The declared length is deliberately unrelated to bytes consumed.
		data := make([]byte, 21)
		if _, e := io.ReadFull(c.Request.Body, data); e != nil {
			t.Fatal(e)
		}
		c.Writer.Write(bytes.Repeat([]byte("x"), int(businesstraffic.HighBytesPerSecond)))
		v := m.Snapshot()
		if v.CanRun || v.Ingress != 4 || v.Recent != businesstraffic.HighBytesPerSecond+21 {
			t.Fatal("in-flight bytes not counted", v)
		}
		c.Writer.WriteString("tail")
	})
	req := httptest.NewRequest("POST", "/business", bytes.NewReader(make([]byte, 100)))
	req.ContentLength = 999999999
	router.ServeHTTP(httptest.NewRecorder(), req)
	if m.Snapshot().Recent != businesstraffic.HighBytesPerSecond+25 {
		t.Fatal(m.Snapshot())
	}
}

func TestMigrationAndObservationTrafficCannotBlockTheirOwnResume(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	now := time.Unix(1800000000, 0)
	m := businesstraffic.New(func() time.Time { return now })
	now = now.Add(businesstraffic.LowInterval)
	router := gin.New()
	router.Use(BusinessTrafficMiddleware(m))
	for _, route := range []string{"/internal/v1/resource-migration/peer-read", "/internal/v1/resource-migration/data/pull", "/api/v1/media/admin/nodes/migrations/task", "/api/v1/media/admin/nodes"} {
		router.Any(route, func(c *gin.Context) {
			io.Copy(io.Discard, c.Request.Body)
			c.Writer.Write(bytes.Repeat([]byte("x"), 1<<20))
		})
		method := "POST"
		if route[0:4] == "/api" {
			method = "GET"
		}
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, route, bytes.NewReader(make([]byte, 1<<20))))
	}
	if v := m.Snapshot(); !v.CanRun || v.Recent != 0 {
		t.Fatal(v)
	}
	for _, route := range []string{"/internal/v1/media/id", "/internal/v1/recordings/id"} {
		router.GET(route, func(c *gin.Context) {
			c.Writer.Write(bytes.Repeat([]byte("x"), int(businesstraffic.HighBytesPerSecond)))
		})
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", route, nil))
	}
	if m.Snapshot().CanRun {
		t.Fatal("Relay business reads did not yield migration")
	}
}
