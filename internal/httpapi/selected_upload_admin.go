package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

// ConfigureSelectedUploadRuntime is startup-only. The supplied coordinator
// itself requires the trusted recovery/readiness lease; no request can install
// a gate or select another tree, crypto manager, or management origin.
func (a *Admin) ConfigureSelectedUploadRuntime(runtime *business.SelectedUploadRuntime) error {
	if a == nil || a.public == nil || a.public.opaqueTree == nil || runtime == nil || !runtime.Matches(a.public.opaqueTree, a.public.crypto, a.settings.AdminOrigin) || a.selectedUpload != nil {
		return errors.New("selected upload runtime unavailable")
	}
	a.selectedUpload = runtime
	return nil
}

func (a *Admin) selectedAdminAllowed(c *gin.Context, mutating bool) bool {
	noStore(c)
	if a == nil || a.public == nil || a.public.opaqueTree == nil || a.selectedUpload == nil || !a.selectedUpload.Matches(a.public.opaqueTree, a.public.crypto, a.settings.AdminOrigin) {
		detail(c, http.StatusServiceUnavailable, "资源暂不可用")
		return false
	}
	if !a.directManagementOrigin(c) {
		detail(c, http.StatusForbidden, "请求来源无效")
		return false
	}
	if mutating && !sameOriginPost(c, a.settings.AdminOrigin) {
		detail(c, http.StatusForbidden, "请求来源无效")
		return false
	}
	if !mutating {
		origins := c.Request.Header.Values("Origin")
		if len(origins) > 1 || len(origins) == 1 && origins[0] != a.settings.AdminOrigin {
			detail(c, http.StatusForbidden, "请求来源无效")
			return false
		}
	}
	return true
}
func selectedRuntimeError(c *gin.Context, err error) {
	_ = err
	detail(c, http.StatusConflict, "上传状态不可用，请重试或查询状态")
}

func logSelectedPrepareFailure(err error) {
	stage, cause := business.SelectedPrepareFailureClass(err)
	slog.Warn("selected upload preparation rejected", "stage", stage, "cause", cause)
}

func selectedRuntimeContext(c *gin.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Request.Context(), 30*time.Second)
}

func (a *Admin) selectedPrepareUpload(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	var body business.SelectedPrepareRequest
	if !cryptoSameOrigin(c) {
		return
	}
	// The selected S3 request may contain up to 1280 SHA-256 part commitments.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 128<<10)
	if err := c.ShouldBindJSON(&body); err != nil {
		invalid(c, "body", "crypto")
		return
	}
	if body.Encryption.PlaintextSize <= 0 || body.Encryption.PlaintextSize > a.settings.AdminMaxUploadBytes || body.Encryption.CiphertextSize > encryptedUploadLimit(a.settings.AdminMaxUploadBytes) {
		detail(c, http.StatusRequestEntityTooLarge, "文件超过单文件上传限制")
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	ticket, err := a.selectedUpload.PrepareAndIssue(ctx, session(c).Hash, body)
	if err != nil {
		logSelectedPrepareFailure(err)
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, ticket)
}
func (a *Admin) selectedResumeUpload(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	ticket, err := a.selectedUpload.Resume(ctx, session(c).Hash, c.Param("upload"))
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, ticket)
}
func (a *Admin) selectedUploadStatus(c *gin.Context) {
	if !a.selectedAdminAllowed(c, false) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	status, err := a.selectedUpload.Status(ctx, session(c).Hash, c.Param("upload"))
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, status)
}

type selectedSignedReceipt struct {
	Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
	Signature string                         `json:"signature"`
}

func (a *Admin) selectedCompleteUpload(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	var body selectedSignedReceipt
	if !cryptoDecode(c, &body) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	already, err := a.selectedUpload.Complete(ctx, session(c).Hash, c.Param("upload"), body.Receipt, body.Signature)
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"state": "completed", "already": already})
}
func (a *Admin) selectedCancelUpload(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	ticket, err := a.selectedUpload.BeginCancel(ctx, session(c).Hash, c.Param("upload"))
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, ticket)
}
func (a *Admin) selectedFinishCancel(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	var body selectedSignedReceipt
	if !cryptoDecode(c, &body) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	already, err := a.selectedUpload.FinishCancel(ctx, session(c).Hash, c.Param("upload"), body.Receipt, body.Signature)
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"state": "cancelled", "already": already})
}

// Relay uses the authenticated Admin's same-origin connection to the Master.
// The short Owner capability remains server-side, and the body is streamed.
func (a *Admin) selectedRelayBytes(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	if c.Request.ContentLength <= 0 || c.Request.ContentLength > encryptedUploadLimit(a.settings.AdminMaxUploadBytes) {
		detail(c, http.StatusRequestEntityTooLarge, "文件超过单文件上传限制")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 24*time.Hour)
	defer cancel()
	transport, err := a.selectedUpload.Transport(ctx, session(c).Hash, c.Param("upload"))
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	var result map[string]any
	if transport == "Local" {
		result, err = a.selectedUpload.LocalOperation(ctx, session(c).Hash, c.Param("upload"), http.NewResponseController(c.Writer), c.Request.Body, "upload", c.Request.ContentLength)
	} else if transport == "Relay" {
		result, err = a.selectedUpload.RelayBytes(ctx, session(c).Hash, c.Param("upload"), c.Request.Body, c.Request.ContentLength)
	} else {
		err = store.ErrNodeState
	}
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}
func (a *Admin) selectedRelayRecover(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	transport, err := a.selectedUpload.Transport(ctx, session(c).Hash, c.Param("upload"))
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	var result map[string]any
	if transport == "Local" {
		result, err = a.selectedUpload.LocalOperation(ctx, session(c).Hash, c.Param("upload"), http.NewResponseController(c.Writer), c.Request.Body, "recover", 0)
	} else if transport == "Relay" {
		relayCtx, relayCancel := context.WithTimeout(c.Request.Context(), protocol.SelectedRelayVerificationTimeout)
		defer relayCancel()
		result, err = a.selectedUpload.RelayRecover(relayCtx, session(c).Hash, c.Param("upload"))
	} else {
		err = store.ErrNodeState
	}
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}
func (a *Admin) selectedRelayCleanup(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	transport, err := a.selectedUpload.Transport(ctx, session(c).Hash, c.Param("upload"))
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	var result map[string]any
	if transport == "Local" {
		result, err = a.selectedUpload.LocalOperation(ctx, session(c).Hash, c.Param("upload"), http.NewResponseController(c.Writer), c.Request.Body, "cleanup", 0)
	} else if transport == "Relay" {
		relayCtx, relayCancel := context.WithTimeout(c.Request.Context(), protocol.SelectedRelayVerificationTimeout)
		defer relayCancel()
		result, err = a.selectedUpload.RelayCleanup(relayCtx, session(c).Hash, c.Param("upload"))
	} else {
		err = store.ErrNodeState
	}
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}
