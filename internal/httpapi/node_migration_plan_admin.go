package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type migrationPlanner interface {
	Create(string, string, string) (resourcemigration.PlanView, error)
	Status(string, string) (resourcemigration.PlanView, error)
	Start(string, string, string, string, store.NodeAudit) (resourcemigration.PlanView, error)
}

// Plans are asynchronous observations. Clients select IDs and confirm the
// reviewed digest; no endpoint accepts a physical proof, path or capacity.
func RegisterAdminMigrationPlanning(router *gin.Engine, a *Admin, planner migrationPlanner) {
	if planner == nil {
		return
	}
	group := router.Group("/api/v1/media/admin/nodes/migration-plans", a.transport, a.authenticate)
	group.Use(func(c *gin.Context) {
		if !nodeHTTPS(c, a.settings, a.network) {
			c.Abort()
			return
		}
		n, e := a.public.media.IdentityState(c.Request.Context())
		if e != nil || n.Role != "Master" {
			detail(c, 409, "资源迁移计划仅由当前业务 Master 管理")
			c.Abort()
			return
		}
		c.Set("migration_master_id", n.ID)
		c.Next()
	})
	reply := func(c *gin.Context, v resourcemigration.PlanView, e error) {
		if errors.Is(e, resourcemigration.ErrPlanBusy) {
			detail(c, 429, "已有迁移计划或执行前复核正在运行")
			return
		}
		if e != nil {
			detail(c, 409, "迁移计划已变化、过期或不可用，请重新生成并确认")
			return
		}
		c.JSON(200, v)
	}
	read := func(c *gin.Context, v any) bool {
		raw, ok := nodeBody(c)
		if !ok {
			return false
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF || c.Request.URL.RawQuery != "" {
			invalid(c, "body", "migration_plan")
			return false
		}
		return true
	}
	group.POST("", func(c *gin.Context) {
		var req struct {
			RequestID string `json:"request_id"`
			Source    string `json:"source_id"`
			Target    string `json:"target_id"`
		}
		if !read(c, &req) {
			return
		}
		if !retirementID(req.RequestID) || !retirementID(req.Source) || !retirementID(req.Target) || req.Source == req.Target || req.Source == c.GetString("migration_master_id") || req.Target == c.GetString("migration_master_id") {
			invalid(c, "body", "source_or_target")
			return
		}
		v, e := planner.Create(req.RequestID, req.Source, req.Target)
		reply(c, v, e)
	})
	group.GET("/:plan", func(c *gin.Context) {
		if !retirementID(c.Param("plan")) || len(c.Request.URL.Query()) > 1 || len(c.Request.URL.Query()["after"]) > 1 || len(c.Request.URL.Query()) == 1 && c.Query("after") == "" {
			invalid(c, "query", "plan_page")
			return
		}
		v, e := planner.Status(c.Param("plan"), c.Query("after"))
		reply(c, v, e)
	})
	group.POST("/:plan/start", func(c *gin.Context) {
		if !retirementID(c.Param("plan")) {
			invalid(c, "path", "plan")
			return
		}
		var req struct {
			Review string `json:"review_sha256"`
			Source string `json:"confirm_source_id"`
			Target string `json:"confirm_target_id"`
		}
		if !read(c, &req) {
			return
		}
		info := a.info(c)
		v, e := planner.Start(c.Param("plan"), req.Review, req.Source, req.Target, store.NodeAudit{Actor: session(c).Hash, RequestID: info.RequestID, TraceID: info.TraceID})
		reply(c, v, e)
	})
}
