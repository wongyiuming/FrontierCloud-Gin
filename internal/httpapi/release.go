package httpapi

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

// Only the Master's local updater is exposed. Storage nodes have no release
// routes, updater socket, Docker socket or version convergence requirements.
func RegisterReleaseAdmin(router *gin.Engine, a *Admin, service *release.Coordinator) {
	group := router.Group("/api/v1/media/admin/nodes/release", a.transport, a.authenticate)
	group.GET("", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		value, err := service.Status(ctx, c.Query("refresh_ci") == "true" || c.Query("refresh_ci") == "1")
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(200, value)
	})
	group.GET("/history", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
		defer cancel()
		versions, err := service.History(ctx)
		if err != nil {
			detail(c, 503, "发布历史暂不可用；历史回退保持禁用")
			return
		}
		c.JSON(200, gin.H{"versions": versions, "discovery_is_not_authorization": true})
	})
	for _, mode := range []string{"upgrade", "rollback"} {
		group.POST("/"+mode, func(c *gin.Context) {
			if !nodeHTTPS(c, a.settings, a.network) {
				return
			}
			body, ok := nodeBody(c)
			if !ok {
				return
			}
			target := ""
			if len(body) != 0 {
				var value map[string]any
				if controlJSON(body, &value) != nil || value == nil {
					detail(c, 400, "Invalid release request")
					return
				}
				if len(value) != 0 {
					var valid bool
					target, valid = value["target_sha"].(string)
					if mode != "rollback" || len(value) != 1 || !valid || !release.ValidSHA(target) {
						detail(c, 400, "Only rollback accepts a listed historical target_sha")
						return
					}
				}
			}
			ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
			defer cancel()
			action, source := "release_"+mode, "release_branch="+service.Policy.Branch+";target="+target
			if err := a.auth.Audit(ctx, session(c).Hash, action, source, "pending", "", 1, a.info(c)); err != nil {
				internalError(c, err)
				return
			}
			value, err := service.StartVersion(ctx, mode, target)
			result, message := "success", ""
			if err != nil {
				result, message = "failed", "release request rejected"
			}
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer stop()
			if auditErr := a.auth.Audit(cleanup, session(c).Hash, action, source, result, message, 1, a.info(c)); auditErr != nil {
				internalError(c, auditErr)
				return
			}
			if err != nil {
				detail(c, 409, err.Error())
				return
			}
			c.JSON(200, value)
		})
	}
}
