package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const s3HTTPBodyLimit = 32 * 1024

var s3HTTPID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// This surface has no byte-upload or redirect endpoint. The authenticated
// Master issues bounded controls; provider bearer URLs stay in no-store JSON.
func (a *Admin) registerS3(protected *gin.RouterGroup) {
	nodes := protected.Group("/nodes/s3", a.s3Master)
	nodes.GET("", a.s3Members)
	nodes.POST("", a.s3AddMember)
	nodes.PATCH("/:member", a.s3ConfigureMember)
	nodes.DELETE("/:member", a.s3RemoveMember)
	nodes.POST("/:member/test", a.s3ProbeMember)
	nodes.POST("/:member/recovery-credentials", a.s3RecoveryCredentials)
	uploads := protected.Group("/upload/s3/:upload", a.s3Master)
	uploads.GET("", a.s3UploadStatus)
	uploads.POST("/begin", a.s3BeginUpload)
	uploads.POST("/touch", a.s3TouchUpload)
	uploads.POST("/parts/:number/grant", a.s3PartGrant)
	uploads.POST("/parts/:number/confirm", a.s3ConfirmPart)
	uploads.POST("/finalize", a.s3CompleteUpload)
	uploads.DELETE("", a.s3CancelUpload)
}

func (a *Admin) s3Master(c *gin.Context) {
	noStore(c)
	if !nodeHTTPS(c, a.settings, a.network) {
		c.Abort()
		return
	}
	role, err := a.public.media.BusinessRole(c.Request.Context())
	if err != nil || role != "Master" {
		s3HTTPError(c, store.ErrNodeState)
		c.Abort()
		return
	}
	for _, name := range []string{"member", "upload"} {
		if id := c.Param(name); id != "" && !s3HTTPID.MatchString(id) {
			invalid(c, "path", name)
			c.Abort()
			return
		}
	}
	if c.Request.URL.RawQuery != "" {
		invalid(c, "query", "payload")
		c.Abort()
		return
	}
	c.Next()
}

func (a *Admin) s3NodeAudit(c *gin.Context) store.NodeAudit {
	info := a.info(c)
	return store.NodeAudit{Actor: session(c).Hash, RequestID: info.RequestID, TraceID: info.TraceID}
}

// Reject duplicate (including case-folded) names, deep JSON, unknown fields,
// trailing values and invalid UTF-8 before a credential or mutation is used.
func s3JSONValue(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("JSON depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("JSON key")
			}
			name = strings.ToLower(name)
			if seen[name] || len(seen) >= 64 {
				return errors.New("JSON duplicate key")
			}
			seen[name] = true
			if err = s3JSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for count := 0; decoder.More(); count++ {
			if count >= 128 {
				return errors.New("JSON array")
			}
			if err = s3JSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func decodeS3(c *gin.Context, target any) bool {
	if c.ContentType() != "application/json" {
		detail(c, 415, "S3 控制请求必须使用 JSON")
		return false
	}
	controller := http.NewResponseController(c.Writer)
	_ = controller.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer controller.SetReadDeadline(time.Time{})
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, s3HTTPBodyLimit)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			detail(c, 413, "S3 控制请求过大")
		} else {
			detail(c, 400, "S3 控制请求无效")
		}
		return false
	}
	if !utf8.Valid(body) || len(bytes.TrimSpace(body)) == 0 || bytes.TrimSpace(body)[0] != '{' {
		invalid(c, "body", "payload")
		return false
	}
	check := json.NewDecoder(bytes.NewReader(body))
	check.UseNumber()
	if err = s3JSONValue(check, 0); err != nil {
		invalid(c, "body", "payload")
		return false
	}
	var tail any
	if err = check.Decode(&tail); err != io.EOF {
		invalid(c, "body", "payload")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		invalid(c, "body", "payload")
		return false
	}
	return true
}

func s3HTTPError(c *gin.Context, err error) {
	noStore(c)
	status := http.StatusBadGateway
	switch {
	case errors.Is(err, store.ErrNodeState), errors.Is(err, s3store.ErrConflict), errors.Is(err, s3media.ErrPending):
		status = 409
	case errors.Is(err, store.ErrStorageCapacity):
		status = 507
	case errors.Is(err, media.ErrPath), errors.Is(err, s3store.ErrConfig), errors.Is(err, s3store.ErrCredentials), errors.Is(err, s3store.ErrEndpoint):
		status = 422
	case errors.Is(err, os.ErrNotExist), errors.Is(err, s3store.ErrNotFound):
		status = 404
	case errors.Is(err, s3media.ErrUnavailable), errors.Is(err, media.ErrUnavailable):
		status = 503
	}
	// Never log, format or serialize the original provider/SDK error.
	c.JSON(status, gin.H{"detail": "S3 操作未完成，请查看节点状态后重试", "code": s3media.ErrorCode(err), "uncertain": s3store.IsUncertain(err)})
}

func (a *Admin) s3Members(c *gin.Context) {
	value, err := a.public.media.S3Members(c.Request.Context())
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, gin.H{"members": value})
}

func (a *Admin) s3AddMember(c *gin.Context) {
	var body s3media.Configuration
	if !decodeS3(c, &body) {
		return
	}
	value, err := a.public.media.S3AddMember(c.Request.Context(), body, a.s3NodeAudit(c))
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, value)
}

func (a *Admin) s3ConfigureMember(c *gin.Context) {
	var body struct {
		Revision int64 `json:"revision"`
		s3media.Configuration
	}
	if !decodeS3(c, &body) {
		return
	}
	if body.Revision < 1 {
		invalid(c, "body", "revision")
		return
	}
	value, err := a.public.media.S3ConfigureMember(c.Request.Context(), c.Param("member"), body.Revision, body.Configuration, a.s3NodeAudit(c))
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, value)
}

type s3RevisionBody struct {
	Revision int64 `json:"revision"`
}

func s3Revision(c *gin.Context) (int64, bool) {
	var body s3RevisionBody
	if !decodeS3(c, &body) {
		return 0, false
	}
	if body.Revision < 1 {
		invalid(c, "body", "revision")
		return 0, false
	}
	return body.Revision, true
}

func (a *Admin) s3RemoveMember(c *gin.Context) {
	revision, ok := s3Revision(c)
	if !ok {
		return
	}
	if err := a.public.media.S3RemoveMember(c.Request.Context(), c.Param("member"), revision, a.s3NodeAudit(c)); err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, gin.H{"status": "removed"})
}

func (a *Admin) s3ProbeMember(c *gin.Context) {
	revision, ok := s3Revision(c)
	if !ok {
		return
	}
	// The trusted configured origin, never a client-supplied Host/Origin, is the
	// browser CORS target. Fixed node roles already require public HTTPS.
	value, err := a.public.media.S3ProbeMember(c.Request.Context(), c.Param("member"), revision, a.settings.PublicOrigin, a.s3NodeAudit(c))
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, value)
}

func (a *Admin) s3RecoveryCredentials(c *gin.Context) {
	var body struct {
		Revision    int64               `json:"revision"`
		Credentials s3store.Credentials `json:"credentials"`
	}
	if !decodeS3(c, &body) {
		return
	}
	if body.Revision < 1 {
		invalid(c, "body", "revision")
		return
	}
	value, err := a.public.media.S3RecoveryCredentials(c.Request.Context(), c.Param("member"), body.Revision, body.Credentials, a.s3NodeAudit(c))
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, value)
}

func s3Empty(c *gin.Context) bool { var body struct{}; return decodeS3(c, &body) }

func (a *Admin) s3UploadStatus(c *gin.Context) {
	value, err := a.public.media.S3UploadStatus(c.Request.Context(), c.Param("upload"), false)
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, value)
}
func (a *Admin) s3TouchUpload(c *gin.Context) {
	if !s3Empty(c) {
		return
	}
	value, err := a.public.media.S3UploadStatus(c.Request.Context(), c.Param("upload"), true)
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, value)
}
func (a *Admin) s3BeginUpload(c *gin.Context) {
	if !s3Empty(c) {
		return
	}
	value, err := a.public.media.S3BeginUpload(c.Request.Context(), c.Param("upload"))
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, value)
}
func s3PartNumber(c *gin.Context) (int, bool) {
	value, err := strconv.Atoi(c.Param("number"))
	if err != nil || value < 1 || value > 1280 || strconv.Itoa(value) != c.Param("number") {
		invalid(c, "path", "number")
		return 0, false
	}
	return value, true
}
func (a *Admin) s3PartGrant(c *gin.Context) {
	number, ok := s3PartNumber(c)
	if !ok {
		return
	}
	var body struct {
		Size     int64  `json:"size_bytes"`
		Checksum string `json:"checksum_sha256"`
	}
	if !decodeS3(c, &body) {
		return
	}
	digest, err := base64.StdEncoding.DecodeString(body.Checksum)
	if body.Size < 1 || body.Size > store.S3PartBytes || err != nil || len(digest) != 32 || base64.StdEncoding.EncodeToString(digest) != body.Checksum {
		invalid(c, "body", "part")
		return
	}
	value, err := a.public.media.S3PartGrant(c.Request.Context(), c.Param("upload"), number, body.Size, body.Checksum)
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, value)
}
func (a *Admin) s3ConfirmPart(c *gin.Context) {
	number, ok := s3PartNumber(c)
	if !ok || !s3Empty(c) {
		return
	}
	value, err := a.public.media.S3ConfirmPart(c.Request.Context(), c.Param("upload"), number)
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, value)
}
func (a *Admin) s3CompleteUpload(c *gin.Context) {
	if !s3Empty(c) {
		return
	}
	value, err := a.public.media.S3CompleteUpload(c.Request.Context(), c.Param("upload"), a.mutationAudit(c, "s3-upload-finalized", []string{c.Param("upload")}))
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(200, value)
}
func (a *Admin) s3CancelUpload(c *gin.Context) {
	// DELETE carries no authority-bearing fields; reject bodies rather than
	// accepting a client provider upload id, key, ETag or refund assertion.
	if c.Request.ContentLength != 0 {
		invalid(c, "body", "payload")
		return
	}
	value, err := a.public.media.S3CancelUpload(c.Request.Context(), c.Param("upload"), a.mutationAudit(c, "s3-upload-cancel-requested", []string{c.Param("upload")}))
	if err != nil && !errors.Is(err, s3media.ErrPending) {
		s3HTTPError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, value)
}
