package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

func (a *Admin) selectedS3(c *gin.Context, mutating bool) *business.SelectedS3Coordinator {
	if !a.selectedAdminAllowed(c, mutating) {
		return nil
	}
	coordinator := a.selectedUpload.SelectedS3()
	if coordinator == nil {
		detail(c, http.StatusServiceUnavailable, "S3 资源暂不可用")
		return nil
	}
	return coordinator
}

func (a *Admin) selectedS3Status(c *gin.Context, touch bool) {
	s := a.selectedS3(c, touch)
	if s == nil {
		return
	}
	if touch && !s3Empty(c) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	value, err := s.Status(ctx, session(c).Hash, c.Param("upload"))
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(http.StatusOK, value)
}

func (a *Admin) selectedS3Begin(c *gin.Context) {
	s := a.selectedS3(c, true)
	if s == nil || !s3Empty(c) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	value, err := s.BeginOrRecover(ctx, session(c).Hash, c.Param("upload"))
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(http.StatusOK, value)
}

func (a *Admin) selectedS3PartGrant(c *gin.Context) {
	s := a.selectedS3(c, true)
	if s == nil {
		return
	}
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
	digest, err := base64.StdEncoding.Strict().DecodeString(body.Checksum)
	if body.Size < 1 || body.Size > store.S3PartBytes || err != nil || len(digest) != 32 || base64.StdEncoding.EncodeToString(digest) != body.Checksum {
		invalid(c, "body", "part")
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	grant, err := s.PartGrant(ctx, session(c).Hash, c.Param("upload"), number, body.Size, body.Checksum)
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(http.StatusOK, grant)
}

func (a *Admin) selectedS3Confirm(c *gin.Context) {
	s := a.selectedS3(c, true)
	if s == nil {
		return
	}
	number, ok := s3PartNumber(c)
	if !ok || !s3Empty(c) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	if _, err := s.ConfirmPart(ctx, session(c).Hash, c.Param("upload"), number); err != nil {
		s3HTTPError(c, err)
		return
	}
	value, err := s.Status(ctx, session(c).Hash, c.Param("upload"))
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(http.StatusOK, value)
}

func (a *Admin) selectedS3Complete(c *gin.Context) {
	s := a.selectedS3(c, true)
	if s == nil || !s3Empty(c) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	value, err := s.Complete(ctx, session(c).Hash, c.Param("upload"))
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(http.StatusOK, value)
}

func (a *Admin) selectedS3Cancel(c *gin.Context) {
	s := a.selectedS3(c, true)
	if s == nil {
		return
	}
	if c.Request.ContentLength != 0 {
		invalid(c, "body", "payload")
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	value, err := s.Cancel(ctx, session(c).Hash, c.Param("upload"))
	if errors.Is(err, s3media.ErrPending) {
		value, err = s.Status(ctx, session(c).Hash, c.Param("upload"))
		if err == nil {
			c.JSON(http.StatusAccepted, value)
			return
		}
	}
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	c.JSON(http.StatusOK, value)
}
