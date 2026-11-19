package httpapi

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"unicode/utf8"
)

// The established Admin session/CSRF contract applies to every node operation;
// mutations additionally require the TLS-enabled node control-plane boundary.
func RegisterAdminNodes(router *gin.Engine, a *Admin, service *node.Service) {
	group := router.Group("/api/v1/media/admin/nodes", a.transport, a.authenticate)
	audit := func(c *gin.Context) store.NodeAudit {
		info := a.info(c)
		return store.NodeAudit{Actor: session(c).Hash, RequestID: info.RequestID, TraceID: info.TraceID}
	}
	mutate := func(c *gin.Context) {
		if !nodeHTTPS(c, a.settings, a.network) {
			c.Abort()
		}
	}
	group.GET("", func(c *gin.Context) {
		result, err := service.Status(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		result["storage_pool"] = nil
		result["reinitialize_available"] = a.public.opaqueTree == nil && result["role"] != "Standalone"
		result["retirement_inventory_available"] = a.public.opaqueTree == nil
		if result["role"] == "Master" {
			pool, err := a.public.media.StoragePool(c.Request.Context())
			if err != nil {
				internalError(c, err)
				return
			}
			result["storage_pool"] = pool
			result["migration_planning_available"] = a.migrationPlanningAvailable()
		}
		c.JSON(200, result)
	})
	group.GET("/observability", func(c *gin.Context) {
		result, err := service.Observability(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(200, result)
	})
	group.GET("/public-routing", func(c *gin.Context) {
		ingress, policies, err := service.PublicRouting(c.Request.Context())
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(200, gin.H{"ingress": ingress, "master_public_origin": a.settings.PublicOrigin, "native_transport_policies": policies, "selection_enabled": service.IngressSelectionAvailable(c.Request.Context())})
	})
	writes := group.Group("", mutate)
	writes.POST("/public-routing/select", func(c *gin.Context) {
		var body struct {
			MemberID     string `json:"member_id"`
			Generation   *int64 `json:"generation"`
			PublicOrigin string `json:"public_origin"`
		}
		if !decodeNodeAdmin(c, &body) {
			return
		}
		if !node.ValidIdentifier(body.MemberID) || body.Generation == nil || *body.Generation < 1 {
			invalid(c, "body", "member_id")
			return
		}
		selected, err := service.SelectPublicIngressAtOrigin(c.Request.Context(), body.MemberID, *body.Generation, body.PublicOrigin, audit(c))
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(200, selected)
	})
	writes.POST("/public-routing/candidates/:member/check", func(c *gin.Context) {
		origin, err := service.CheckPublicIngressCandidate(c.Request.Context(), c.Param("member"))
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(200, gin.H{"origin": origin, "proxy_check": "passed", "selection_enabled": service.IngressSelectionAvailable(c.Request.Context())})
	})
	writes.POST("/public-routing/transport/:member", func(c *gin.Context) {
		var body struct {
			Transport string `json:"configured_transport"`
			Revision  *int64 `json:"revision"`
		}
		if !decodeNodeAdmin(c, &body) {
			return
		}
		if body.Revision == nil || *body.Revision < 0 || (body.Transport != "Direct" && body.Transport != "Relay") {
			invalid(c, "body", "configured_transport")
			return
		}
		policy, err := service.ConfirmNativeTransport(c.Request.Context(), c.Param("member"), body.Transport, *body.Revision, audit(c))
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(200, policy)
	})
	group.GET("/:identifier/certificate", func(c *gin.Context) {
		v, err := service.Certificate(c.Request.Context(), c.Param("identifier"), certificate.Request{Action: "status"}, audit(c))
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(200, v)
	})
	writes.POST("/:identifier/certificate", func(c *gin.Context) {
		var request certificate.Request
		if !decodeNodeAdmin(c, &request) {
			return
		}
		if request.Action != "download" {
			invalid(c, "body", "action")
			return
		}
		v, err := service.Certificate(c.Request.Context(), c.Param("identifier"), request, audit(c))
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(200, v)
	})
	writes.POST("/promote", func(c *gin.Context) {
		var body struct {
			Role     string `json:"role"`
			Endpoint string `json:"endpoint"`
			Capacity *int64 `json:"local_capacity_gib"`
		}
		if !decodeNodeAdmin(c, &body) {
			return
		}
		if body.Role != "Master" || body.Endpoint == "" || utf8.RuneCountInString(body.Endpoint) > 512 || body.Capacity != nil && (*body.Capacity < 1 || *body.Capacity > 10240) {
			invalid(c, "body", "promotion")
			return
		}
		allocation := int64(0)
		if body.Capacity != nil {
			allocation = *body.Capacity * store.GiB
		}
		row, err := service.Promote(c.Request.Context(), body.Role, body.Endpoint, allocation, audit(c))
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		service.Wake()
		c.JSON(200, gin.H{"role": row.Role})
	})
	writes.POST("/reinitialize", func(c *gin.Context) {
		var body struct {
			Confirmation string `json:"confirmation"`
		}
		if !decodeNodeAdmin(c, &body) {
			return
		}
		if body.Confirmation == "" || utf8.RuneCountInString(body.Confirmation) > 32 {
			invalid(c, "body", "confirmation")
			return
		}
		row, err := service.Reinitialize(c.Request.Context(), body.Confirmation, audit(c))
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		c.JSON(200, gin.H{"role": row.Role, "node_id": row.ID})
	})
	writes.POST("/pair", func(c *gin.Context) {
		var body struct {
			Package node.Envelope `json:"package"`
		}
		if !decodeNodeAdmin(c, &body) {
			return
		}
		id, err := service.ImportPair(c.Request.Context(), body.Package, audit(c))
		service.Wake() // A lost confirmation reply leaves a recoverable pending pair.
		if err != nil {
			nodeAdminError(c, err)
			return
		}
		c.JSON(200, gin.H{"relationship_id": id})
	})
	writes.POST("/:identifier/mode", func(c *gin.Context) {
		var body struct {
			Mode string `json:"mode"`
		}
		if !decodeNodeAdmin(c, &body) {
			return
		}
		if body.Mode != "Direct" && body.Mode != "Relay" {
			invalid(c, "body", "mode")
			return
		}
		if err := service.SetMode(c.Request.Context(), c.Param("identifier"), body.Mode, audit(c)); err != nil {
			nodeAdminError(c, err)
			return
		}
		c.JSON(200, gin.H{"mode": body.Mode})
	})
	writes.POST("/:identifier/resources", func(c *gin.Context) {
		var body struct {
			Storage  bool   `json:"storage_enabled"`
			Capacity *int64 `json:"storage_capacity_gib"`
			Backup   bool   `json:"backup_enabled"`
		}
		if !decodeNodeAdmin(c, &body) {
			return
		}
		if body.Capacity == nil || *body.Capacity < 0 || *body.Capacity > 10240 {
			invalid(c, "body", "storage_capacity_gib")
			return
		}
		var config store.ResourceConfiguration
		config.Storage.Enabled, config.Backup.Enabled = body.Storage, body.Backup
		if body.Storage {
			config.Storage.Allocation = *body.Capacity * store.GiB
		}
		if err := service.Configure(c.Request.Context(), c.Param("identifier"), config, audit(c)); err != nil {
			nodeAdminError(c, err)
			return
		}
		c.JSON(200, gin.H{"status": "ok"})
	})
	writes.POST("/:identifier/revoke", func(c *gin.Context) {
		if err := service.RevokeFromAdmin(c.Request.Context(), c.Param("identifier"), audit(c)); err != nil {
			nodeAdminError(c, err)
			return
		}
		service.Wake()
		c.JSON(200, gin.H{"state": "revoked"})
	})
}

func decodeNodeAdmin(c *gin.Context, target any) bool {
	body, ok := nodeBody(c)
	if !ok {
		return false
	}
	if err := controlJSON(body, target); err != nil {
		invalid(c, "body", "payload")
		return false
	}
	return true
}
func nodeAdminError(c *gin.Context, err error) {
	if errors.Is(err,node.ErrLogArchiveNodePinned){c.JSON(409,gin.H{"code":"log_archive_node_in_use","detail":"该节点仍承载日志或日志迁移任务；请先在日志管理中完成节点移动，期间不能改为中继"});return}
	if errors.Is(err, node.ErrIngressEndpointUnprepared) {
		c.JSON(409, gin.H{"code": "ingress_endpoint_unprepared", "detail": "该节点尚未准备并上报可验证的公共入口端点；请完成节点入口部署并等待心跳确认，当前入口未改变"})
		return
	}
	if errors.Is(err, node.ErrResourceEndpointUnprepared) {
		c.JSON(409, gin.H{"code": "direct_endpoint_unprepared", "detail": "该节点尚未准备并上报可验证的 Direct 资源端点；已保存的配置不等于已生效，请完成节点直连端点部署"})
		return
	}
	message := "节点 HTTPS 验证或通信失败；请检查证书、网络及节点身份"
	if errors.Is(err, store.ErrNodeState) || errors.Is(err, store.ErrStorageCapacity) {
		message = err.Error()
	}
	detail(c, 409, message)
}
