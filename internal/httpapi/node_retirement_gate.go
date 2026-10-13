package httpapi

import (
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"strings"
)

// Install before registering internal routes. This lease is independent of the
// native media/recording mutation locks: an upload may take their exclusive locks
// while holding this shared request lease without recursive locking.
func RegisterNodeRetirementBarrier(router *gin.Engine, settings config.Config, control *node.Service) (func() error, error) {
	closeGate, e := control.OpenRetirementRequestGate(settings.DataRoot)
	if e != nil {
		return nil, e
	}
	router.Use(func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/internal/v1/") || c.Request.URL.Path == "/internal/v1/retirement" {
			c.Next()
			return
		}
		ctx, release, e := control.RetirementRequestLease(c.Request.Context(), false)
		if e != nil {
			detail(c, 409, "Native request admission is unavailable")
			c.Abort()
			return
		}
		defer release()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	return closeGate, nil
}
