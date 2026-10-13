package httpapi

import (
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

func registerMigrationTraffic(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service) {
	router.POST("/internal/v1/resource-migration/traffic", func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		rel, e := control.Authenticate(c.Request.Context(), c.Request.Header, c.Request.Method, c.Request.URL.RequestURI(), body, false, false)
		if e != nil {
			detail(c, 401, "Invalid traffic observation authentication")
			return
		}
		if control.RequireFollower(c.Request.Context(), rel) != nil {
			detail(c, 403, "Traffic observation requires the active Master")
			return
		}
		if string(body) != "{}" || c.Request.URL.RawQuery != "" {
			detail(c, 400, "Invalid traffic observation request")
			return
		}
		identity, e := control.IdentityState(c.Request.Context())
		if e != nil {
			detail(c, 409, "Traffic identity unavailable")
			return
		}
		c.JSON(200, gin.H{"node_id": identity.ID, "traffic": control.BusinessTraffic()})
	})
}
