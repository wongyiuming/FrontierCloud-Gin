package httpapi

import (
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"strconv"
	"strings"
	"time"
)

// Only existing durable tasks are exposed here. Planning/start must obtain
// fresh authenticated physical proofs through the separate migration service.
type migrationDrainReleaser interface {
	ReleaseDrain(context.Context, string, string, store.NodeAudit) error
}

func RegisterAdminMigrations(router *gin.Engine, a *Admin, repository store.MigrationAdminRepository, releasers ...migrationDrainReleaser) {
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
		var value store.MigrationTaskPage
		var e error
		switch c.Query("view") {
		case "queue":
			queue, ok := repository.(interface {
				MigrationQueuePage(context.Context, int64, string) (store.MigrationTaskPage, error)
			})
			if !ok {
				failed(c)
				return
			}
			value, e = queue.MigrationQueuePage(c.Request.Context(), stamp, after)
		case "", "history":
			value, e = repository.MigrationTasksPage(c.Request.Context(), stamp, after)
		default:
			invalid(c, "query", "view")
			return
		}
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
		if value.Task.State != "paused" && value.Task.State != "failed" && value.Task.State != "completed" && value.Task.State != "cancelled" && len(releasers) == 1 {
			if runtime, ok := releasers[0].(interface {
				ExecutionStatus(string) *store.MigrationExecution
			}); ok {
				value.Execution = runtime.ExecutionStatus(value.Task.ID)
			}
		}
		c.JSON(200, value)
	})
	drainSlot := make(chan struct{}, 1)
	group.POST("/:task/release-drain", func(c *gin.Context) {
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
		select {
		case drainSlot <- struct{}{}:
			defer func() { <-drainSlot }()
		default:
			c.JSON(429, gin.H{"detail": "已有排空解除检查正在执行，请稍后重试"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		current, e := repository.MigrationStatus(ctx, c.Param("task"), "")
		if e != nil || current.Task.Revision != request.Revision || current.Task.SourceID != request.Source || current.Task.TargetID != request.Target || (current.Task.State != "completed" && current.Task.State != "cancelled") || len(releasers) != 1 || releasers[0] == nil {
			failed(c)
			return
		}
		info := a.info(c)
		audit := store.NodeAudit{Actor: session(c).Hash, RequestID: info.RequestID, TraceID: info.TraceID}
		if e = releasers[0].ReleaseDrain(ctx, current.Task.ID, request.Source, audit); e != nil {
			failed(c)
			return
		}
		c.JSON(200, current.Task)
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
