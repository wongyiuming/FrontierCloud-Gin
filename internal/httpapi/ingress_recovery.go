package httpapi

import (
	"context"
	"html"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// IngressRecovery is installed only by the authenticated Master runtime.
// Its implementation must keep normal serving closed until revalidation.
type IngressRecovery interface {
	Active() bool
	Status(context.Context) (string, store.PublicIngress, error)
	Restore(context.Context, string, int64, store.NodeAudit) (store.PublicIngress, error)
}

func RegisterIngressRecovery(router *gin.Engine, a *Admin, recovery IngressRecovery) {
	group := router.Group("/api/v1/media/admin/ingress-recovery", a.transport)
	group.GET("", func(c *gin.Context) {
		if !recovery.Active() || !a.directManagementOrigin(c) {
			c.Status(http.StatusNotFound)
			return
		}
		serveTrustedHTML(c, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>入口恢复</title></head><body><main data-csrf="`+html.EscapeString(a.settings.CSRFCookieName())+`"><h1>入口恢复</h1><p>当前入口暂不可用。登录后可将入口切回主站。</p><form id="login"><label>管理密钥 <input name="token" type="password" required autocomplete="current-password"></label><button>登录</button></form><section id="restore" hidden><p id="status"></p><button id="restore-button">切回主站</button></section><p id="message" role="status"></p></main><script src="/api/v1/media/admin/ingress-recovery.js" defer></script></body></html>`, false)
	})
	router.GET("/api/v1/media/admin/ingress-recovery.js", a.transport, func(c *gin.Context) {
		if !recovery.Active() || !a.directManagementOrigin(c) {
			c.Status(http.StatusNotFound)
			return
		}
		content, err := a.public.static.ReadFile("js/ingress-recovery.js")
		if err != nil {
			c.Status(http.StatusServiceUnavailable)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.Data(http.StatusOK, "text/javascript; charset=utf-8", content)
	})
	protected := group.Group("", a.authenticate)
	protected.GET("/state", func(c *gin.Context) {
		if !recovery.Active() || !a.directManagementOrigin(c) {
			c.Status(http.StatusNotFound)
			return
		}
		master, current, err := recovery.Status(c.Request.Context())
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{"master_id": master, "master_public_origin": a.settings.PublicOrigin, "ingress": current})
	})
	protected.POST("/restore", func(c *gin.Context) {
		if !recovery.Active() || !a.directManagementOrigin(c) || !sameOriginPost(c, a.settings.AdminOrigin) {
			c.Status(http.StatusForbidden)
			return
		}
		var body struct {
			MemberID   string `json:"member_id"`
			Generation *int64 `json:"generation"`
		}
		if !decodeNodeAdmin(c, &body) {
			return
		}
		if !node.ValidIdentifier(body.MemberID) || body.Generation == nil || *body.Generation < 1 {
			invalid(c, "body", "member_id")
			return
		}
		info := a.info(c)
		result, err := recovery.Restore(c.Request.Context(), body.MemberID, *body.Generation, store.NodeAudit{Actor: session(c).Hash, RequestID: info.RequestID, TraceID: info.TraceID})
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, result)
	})
}
