package httpapi

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"strconv"
	"strings"
)

// Only existing durable tasks are exposed here. Planning/start must obtain
// fresh authenticated physical proofs through the separate migration service.
func RegisterAdminMigrations(router *gin.Engine, a *Admin, repository store.MigrationAdminRepository) {
	group := router.Group("/api/v1/media/admin/nodes/migrations", a.transport, a.authenticate)
	failed := func(c *gin.Context) {
		c.JSON(409, gin.H{"code": "migration_state_conflict", "detail": "迁移任务状态或身份已变化，请刷新后重试"})
	}
	group.GET("", func(c *gin.Context) {
		after := c.Query("after_id")
		stamp := int64(0)
		if raw := c.Query("after_time"); raw != "" {
			var e error
			stamp, e = strconv.ParseInt(raw, 10, 64)
			if e != nil {
				invalid(c, "query", "after_time")
				return
			}
		}
		value, e := repository.MigrationTasksPage(c.Request.Context(), stamp, after)
		if e != nil {
			failed(c)
			return
		}
		c.JSON(200, value)
	})
	group.GET("/:task", func(c *gin.Context) {
		if !retirementID(c.Param("task")) {
			invalid(c, "path", "task")
			return
		}
		value, e := repository.MigrationStatus(c.Request.Context(), c.Param("task"), c.Query("after"))
		if e != nil {
			failed(c)
			return
		}
		c.JSON(200, value)
	})
	group.POST("/:task/control", func(c *gin.Context) {
		if !nodeHTTPS(c, a.settings, a.network) {
			return
		}
		if !retirementID(c.Param("task")) {
			invalid(c, "path", "task")
			return
		}
		raw, ok := nodeBody(c)
		if !ok {
			return
		}
		var request struct {
			Action   string `json:"action"`
			Revision int64  `json:"revision"`
			Source   string `json:"confirm_source_id"`
			Target   string `json:"confirm_target_id"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Revision < 1 || !retirementID(request.Source) || !retirementID(request.Target) {
			invalid(c, "body", "confirmation")
			return
		}
		switch request.Action {
		case "pause", "resume", "cancel", "retry":
		default:
			invalid(c, "body", "action")
			return
		}
		current, e := repository.MigrationStatus(c.Request.Context(), c.Param("task"), "")
		if e != nil || current.Task.SourceID != request.Source || current.Task.TargetID != request.Target {
			failed(c)
			return
		}
		info := a.info(c)
		audit := store.NodeAudit{Actor: session(c).Hash, RequestID: info.RequestID, TraceID: info.TraceID}
		value, e := repository.ControlMigrationRevision(c.Request.Context(), c.Param("task"), request.Action, request.Revision, audit)
		if e != nil {
			failed(c)
			return
		}
		c.JSON(200, value)
	})
}
