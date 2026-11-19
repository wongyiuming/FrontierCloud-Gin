package httpapi

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

func TestNodeEndpointReadinessErrors(t *testing.T) {
	for _, item := range []struct {
		err  error
		code string
	}{
		{node.ErrIngressEndpointUnprepared, "ingress_endpoint_unprepared"},
		{node.ErrResourceEndpointUnprepared, "direct_endpoint_unprepared"},
	} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		nodeAdminError(c, fmt.Errorf("preflight: %w", item.err))
		if w.Code != 409 || !strings.Contains(w.Body.String(), `"code":"`+item.code+`"`) || strings.Contains(w.Body.String(), "node state conflict") {
			t.Fatal("missing actionable readiness reason", w.Code, w.Body.String())
		}
	}
}
