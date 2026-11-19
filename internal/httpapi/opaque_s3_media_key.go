package httpapi

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

// The public admission already owns the composite lease. An S3 source is
// returned only when the matching tree and real S3 read gate are installed.
func (p *Public) opaqueEncryptedS3MediaKey(c *gin.Context, binding string, body cryptoKeyBody) {
	ctx := c.Request.Context()
	object, placement, err := p.media.OpaquePublicS3Media(ctx, p.opaqueTree, body.FilePath, body.ResourceID, body.ObjectID)
	if err != nil {
		detail(c, http.StatusServiceUnavailable, "资源路径不可用")
		return
	}
	sessionCtx, err := p.crypto.WithDirectSession(ctx, binding, body.SessionID)
	if err != nil {
		cryptoError(c, err)
		return
	}
	envelope, err := p.crypto.Wrap(binding, body.SessionID, *object.Encryption)
	if err != nil {
		cryptoError(c, err)
		return
	}
	deadline := min(envelope.ExpiresAt, time.Now().Unix()+protocol.TokenSeconds-1)
	source, err := p.media.OpaqueS3ReadSource(sessionCtx, p.opaqueTree, placement, deadline)
	if err != nil {
		detail(c, http.StatusServiceUnavailable, "资源路径不可用")
		return
	}
	response, ok := s3SourceJSON(c, object.Path, source)
	if !ok {
		return
	}
	response["resource_id"], response["encryption"], response["key_envelope"] = object.ID, object.Encryption, envelope
	response["source_expires_in"], response["source_expires_at"] = response["expires_in"], response["expires_at"]
	c.JSON(http.StatusOK, response)
}
