package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"strings"
	"time"
)

type retirementChecker interface {
	Check(context.Context, string, string) (noderetirement.Report, error)
}
type retirementApplier interface {
	Apply(context.Context, string, string, store.NodeAudit) (store.RetirementFence, error)
}

// POST requires the established session and CSRF contract even though this
// bounded observation changes no business facts. It never invokes revocation.
func RegisterAdminRetirement(router *gin.Engine, a *Admin, service retirementChecker) {
	group := router.Group("/api/v1/media/admin/nodes", a.transport, a.authenticate)
	slot := make(chan struct{}, 1)
	group.POST("/:identifier/retire/check", func(c *gin.Context) {
		if !nodeHTTPS(c, a.settings, a.network) {
			return
		}
		raw, ok := nodeBody(c)
		if !ok {
			return
		}
		var request struct {
			MemberID string `json:"member_id"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !retirementID(request.MemberID) || !retirementID(c.Param("identifier")) {
			invalid(c, "body", "member_id")
			return
		}
		select {
		case slot <- struct{}{}:
			defer func() { <-slot }()
		default:
			c.JSON(429, gin.H{"detail": "已有退役检查正在执行，请稍后重试", "code": "retirement_check_busy"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Minute)
		defer cancel()
		report, err := service.Check(ctx, request.MemberID, c.Param("identifier"))
		if err != nil {
			report.ObservationComplete = false
			c.JSON(409, gin.H{"detail": "退役检查未完成；请检查节点连接与盘点阻断项后重新检查", "code": "retirement_observation_incomplete", "report": report})
			return
		}
		c.JSON(200, report)
	})
	group.POST("/:identifier/retire/apply", func(c *gin.Context) {
		if !nodeHTTPS(c, a.settings, a.network) {
			return
		}
		raw, ok := nodeBody(c)
		if !ok {
			return
		}
		var req struct {
			MemberID string `json:"member_id"`
			Confirm  string `json:"confirm_member_id"`
		}
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF || !retirementID(req.MemberID) || req.Confirm != req.MemberID || !retirementID(c.Param("identifier")) {
			invalid(c, "body", "confirm_member_id")
			return
		}
		service, ok := service.(retirementApplier)
		if !ok {
			detail(c, 409, "安全退役服务不可用")
			return
		}
		select {
		case slot <- struct{}{}:
			defer func() { <-slot }()
		default:
			detail(c, 429, "退役检查或执行正在进行")
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Minute)
		defer cancel()
		info := a.info(c)
		result, e := service.Apply(ctx, req.MemberID, c.Param("identifier"), store.NodeAudit{Actor: session(c).Hash, RequestID: info.RequestID, TraceID: info.TraceID})
		if e != nil {
			c.JSON(409, gin.H{"code": "retirement_incomplete", "detail": "退役尚未完成；已建立的写入隔离会保留，请处理盘点阻断项后重试", "fence": result})
			return
		}
		c.JSON(200, result)
	})
}
func retirementID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && value == strings.ToLower(value)
}
