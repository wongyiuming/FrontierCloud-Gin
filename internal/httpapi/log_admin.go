package httpapi

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

func NewProjectLogRuntime(catalog *logarchive.Catalog, service *node.Service, audience string) *logarchive.Runtime {
	return logarchive.NewRuntime(catalog, &logRemote{node: service, audience: audience}, func() bool { return service.BusinessTraffic().CanRun })
}

func RegisterAdminLogs(router *gin.Engine, a *Admin, service *node.Service, logs *logarchive.Runtime) {
	if logs != nil {
		registerProjectDiagnostics(router, logs)
	}
	group := router.Group("/api/v1/media/admin/logs", a.transport, a.authenticate)
	group.Use(func(c *gin.Context) {
		noStore(c)
		id, e := service.IdentityState(c.Request.Context())
		if e != nil || id.Role != "Master" {
			detail(c, 409, "日志节点由唯一主站管理")
			c.Abort()
			return
		}
		if logs == nil {
			detail(c, 503, "日志服务尚未准备，请检查主站日志存储")
			c.Abort()
			return
		}
		c.Next()
	})
	group.GET("/worker.js", func(c *gin.Context) {
		c.Header("Content-Security-Policy", mediaCryptoWorkerCSP)
		a.public.staticFile(c, "js/log-query-worker.js", false)
	})
	group.GET("/status", func(c *gin.Context) {
		cfg, e := logs.Catalog.Configuration(c.Request.Context())
		if e != nil {
			detail(c, 503, "日志配置不可读")
			return
		}
		queue, e := logs.Catalog.QueueStatus(c.Request.Context(), cfg.Generation)
		if e != nil {
			detail(c, 503, "日志任务状态不可读")
			return
		}
		c.JSON(200, gin.H{"configuration": cfg, "queue": queue, "capture": logs.Health(), "types": logarchive.Kinds(), "now_ms": time.Now().UnixMilli(), "local_hours": 12, "retention_days": 35, "idle": service.BusinessTraffic(), "query_required": true, "manual_delete_available": false})
	})
	group.POST("/configure", func(c *gin.Context) {
		unlock := service.LockLogDestination()
		defer unlock()
		if a.settings.NginxMedia && !logarchive.CollectorReady() {
			detail(c, 409, "主站日志采集通道尚未准备；配置未改变")
			return
		}
		if a.public.opaqueTree == nil {
			detail(c, 409, "日志归档需要当前加密文件树运行时")
			return
		}
		var request struct {
			MemberID   string `json:"member_id"`
			Generation int64  `json:"generation"`
			Confirm    bool   `json:"confirm"`
		}
		if !smallStrictJSON(c, &request) || !request.Confirm {
			detail(c, 422, "请选择直连日志节点并确认启用或移动")
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
		defer cancel()
		target, e := service.LogArchiveTarget(ctx, request.MemberID)
		if e != nil {
			nodeAdminError(c, e)
			return
		}
		probe, probeError := service.LogArchiveCall(ctx, target, map[string]any{"action": "probe"})
		if probeError != nil || probe["capture_ready"] != true {
			detail(c, 409, "日志节点尚未准备密文归档服务；配置未改变")
			return
		}
		cfg, e := logs.Configure(ctx, target, request.Generation)
		if e != nil {
			detail(c, 409, "日志配置已变化或不可写，请刷新后重试")
			return
		}
		logs.Capture(logarchive.Audit, map[string]any{"action": "log_destination_selected", "node_id": target.MemberID, "generation": cfg.Generation})
		service.Wake()
		c.JSON(200, gin.H{"configuration": cfg, "state": "queued", "detail": "已保存日志节点；已有日志仅在闲时复制、验证并提交新位置，完成前保留来源"})
	})
	group.POST("/query", func(c *gin.Context) {
		var request struct {
			Start   int64           `json:"start_ms"`
			End     int64           `json:"end_ms"`
			Kind    logarchive.Kind `json:"type"`
			Keyword bool            `json:"keyword_filter"`
			After   string          `json:"after"`
		}
		if !smallStrictJSON(c, &request) {
			detail(c, 422, "日志查询参数无效")
			return
		}
		cfg, e := logs.Catalog.Configuration(c.Request.Context())
		if e != nil || !cfg.Enabled {
			detail(c, 409, "请先启用直连日志节点")
			return
		}
		if e = logarchive.ValidateQuery(time.UnixMilli(request.Start), time.UnixMilli(request.End), time.Now(), request.Kind, request.Keyword); e != nil {
			detail(c, 422, "请选择35天内的日期与日志类型；关键字查询窗口必须小于12小时")
			return
		}
		if request.After == "" {
			if e = logs.Catalog.PublishCapture(c.Request.Context(), time.Now(), request.Kind, true); e != nil {
				detail(c, 503, "近期日志正在等待持久化，请稍后重试")
				return
			}
		}
		items, more, e := logs.Catalog.Query(c.Request.Context(), time.UnixMilli(request.Start), time.UnixMilli(request.End), time.Now(), request.Kind, request.Keyword, request.After)
		if e != nil {
			detail(c, 422, "请选择35天内的日期与日志类型；关键字查询窗口必须小于12小时")
			return
		}
		result := make([]gin.H, 0, len(items))
		after := ""
		for _, entry := range items {
			key, e := logs.Catalog.ReadKey(entry.Record)
			if e != nil {
				detail(c, 409, "日志密钥或清单校验失败")
				return
			}
			ref := entry.Record.Reference()
			source := gin.H{"url": "/api/v1/media/admin/logs/local/" + ref.ID, "local": true}
			if entry.Remote.MemberID != "" {
				grant, e := service.LogReadGrant(c.Request.Context(), entry.Remote, ref, a.settings.AdminOrigin)
				if e != nil {
					clear(key[:])
					detail(c, 409, "日志节点的读取授权暂不可用")
					return
				}
				source = gin.H{"url": entry.Remote.Origin + logBlobPath, "local": false, "grant": grant}
			}
			result = append(result, gin.H{"header": entry.Record.Header, "reference": ref, "key": base64.RawURLEncoding.EncodeToString(key[:]), "expires": time.Now().Add(logarchive.GrantLifetime).Unix(), "source": source})
			clear(key[:])
			after = ref.ID
		}
		c.JSON(200, gin.H{"blocks": result, "more": more, "after": after, "complete": !more})
	})
	group.GET("/local/:id", func(c *gin.Context) {
		entry, e := logs.Catalog.Entry(c.Request.Context(), c.Param("id"))
		if e != nil || len(entry.Ciphertext) == 0 {
			detail(c, 404, "主站未保留此日志块，请重新查询归档位置")
			return
		}
		c.Data(200, "application/octet-stream", entry.Ciphertext)
	})
}
