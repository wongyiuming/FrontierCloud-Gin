package httpapi

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
)

func TestBusinessTrafficPreservesRealConnectionDeadlines(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	monitor := businesstraffic.New(nil)
	router := gin.New()
	router.Use(BusinessTrafficMiddleware(monitor))
	result := make(chan error, 1)
	router.PUT("/api/v1/node/selected-upload", func(c *gin.Context) {
		ctl := http.NewResponseController(c.Writer)
		if err := ctl.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			result <- err
			return
		}
		if err := ctl.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
			result <- err
			return
		}
		_, err := io.ReadAll(c.Request.Body)
		result <- err
	})
	server := httptest.NewServer(router)
	defer server.Close()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = fmt.Fprint(conn, "PUT /api/v1/node/selected-upload HTTP/1.1\r\nHost: fixture\r\nContent-Length: 4\r\n\r\nx"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("stalled request did not hit socket deadline: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("wrapped socket deadline failed to interrupt stalled request")
	}
	if monitor.Snapshot().Recent != 1 {
		t.Fatal("traffic accounting lost received byte")
	}
}
