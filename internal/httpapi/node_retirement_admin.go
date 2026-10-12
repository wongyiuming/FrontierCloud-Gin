package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"io"
	"strings"
	"time"
)

type retirementChecker interface {
	Check(context.Context, string, string) (noderetirement.Report, error)
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
}
func retirementID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && value == strings.ToLower(value)
}
