package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

// RegisterNodeIngressCandidateProbe exposes a fixed authenticated diagnostic;
// the Master address and candidate origin come only from paired configuration.
func RegisterNodeIngressCandidateProbe(router *gin.Engine, settings config.Config, resolver *network.Resolver, service *node.Service) {
	router.POST("/internal/v1/public-ingress-probe", func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			detail(c, http.StatusBadRequest, "Invalid control message")
			return
		}
		body, ok := nodeBody(c)
		if !ok || len(body) > 256 {
			if ok {
				detail(c, http.StatusBadRequest, "Invalid control message")
			}
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
		defer cancel()
		relation, err := service.Authenticate(ctx, c.Request.Header, c.Request.Method, c.Request.URL.EscapedPath(), body, false, false)
		if err != nil {
			detail(c, http.StatusUnauthorized, "Invalid relationship authentication")
			return
		}
		var request struct {
			Challenge string `json:"challenge"`
		}
		if controlJSON(body, &request) != nil || !node.ValidIdentifier(request.Challenge) {
			detail(c, http.StatusBadRequest, "Invalid control message")
			return
		}
		result, err := service.ProbeMasterIngressEdge(ctx, relation, request.Challenge)
		if err != nil {
			detail(c, http.StatusServiceUnavailable, "Ingress probe unavailable")
			return
		}
		c.JSON(http.StatusOK, result)
	})
}
