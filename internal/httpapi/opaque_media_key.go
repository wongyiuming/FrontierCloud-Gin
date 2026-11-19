package httpapi

import (
	"context"
	"mime"
	"net/http"
	"path"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (p *Public) opaqueEncryptedMediaKey(c *gin.Context, binding string, body cryptoKeyBody) {
	ctx := c.Request.Context()
	object, placement, err := p.media.OpaquePublicMedia(ctx, p.opaqueTree, body.FilePath, body.ResourceID, body.ObjectID)
	if err != nil {
		p.opaqueEncryptedS3MediaKey(c, binding, body)
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
	expiry := min(envelope.ExpiresAt, time.Now().Unix()+protocol.TokenSeconds-1)
	plan, headers, sourceExpiry, err := p.issueOpaqueMediaSource(sessionCtx, object, placement.OwnerID, body.ObjectID, binding, body.SessionID, expiry)
	expiry = min(expiry, sourceExpiry)
	remaining := expiry - time.Now().Unix()
	if err != nil || remaining < 1 || plan.Source == "" || plan.OwnerID != placement.OwnerID || plan.SourceObjectID != placement.ReadAlias || plan.Size != placement.Bytes ||
		!node.ValidIdentifier(plan.OwnerID) || !masterDirectObject.MatchString(plan.SourceObjectID) || !masterDirectObject.MatchString(plan.Revision) || !network.HasActivePublicAdmission(sessionCtx) {
		detail(c, http.StatusServiceUnavailable, "资源路径不可用")
		return
	}
	contentType := mime.TypeByExtension(path.Ext(object.Path))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	response := gin.H{"transport": "Native", "source_identity_version": 1, "resource_id": object.ID, "object_id": body.ObjectID,
		"source_owner_id": plan.OwnerID, "source_object_id": plan.SourceObjectID, "source_revision": plan.Revision,
		"source_transport": plan.Transport, "encryption": object.Encryption, "key_envelope": envelope,
		"content_type": contentType, "filename": path.Base(object.Path), "source_url": plan.Source,
		"source_headers": headers, "source_expires_at": expiry, "source_expires_in": remaining}
	if plan.Transport == "Direct" {
		response["source_origin"] = plan.Origin
	}
	noStore(c)
	c.JSON(http.StatusOK, response)
}

func (p *Public) issueOpaqueMediaSource(ctx context.Context, object store.MediaObject, owner, objectID, binding, sessionID string, expiry int64) (media.OpaqueSourceDetails, map[string]string, int64, error) {
	var empty media.OpaqueSourceDetails
	_, local := network.LocalPublicIngressFromContext(ctx)
	if !local {
		identity, err := p.media.IdentityState(ctx)
		if err != nil || identity.Role != "Master" {
			return empty, nil, 0, media.ErrUnavailable
		}
		if owner == identity.ID {
			policy, err := p.media.MasterIngressPolicy(ctx)
			if err != nil || policy.State != "applied" || policy.ConfiguredTransport != policy.AppliedTransport {
				return empty, nil, 0, media.ErrUnavailable
			}
			if policy.AppliedTransport == "Direct" && p.masterDirect != nil && p.masterDirect.opaqueTree == p.opaqueTree {
				return p.masterDirect.IssueOpaqueMedia(ctx, object, objectID, binding, sessionID)
			}
			if policy.AppliedTransport == "Relay" && p.masterRelay != nil && p.masterRelay.opaqueTree == p.opaqueTree {
				return p.masterRelay.IssueOpaqueMedia(ctx, object, objectID, binding, sessionID)
			}
			return empty, nil, 0, media.ErrUnavailable
		}
	}
	plan, err := p.media.OpaqueIngressResource(ctx, p.opaqueTree, object, objectID, expiry)
	if err != nil || local && plan.Transport == "Local" && !p.masterLocalMediaReady(ctx) {
		return empty, nil, 0, media.ErrUnavailable
	}
	if plan.Transport == "Relay" {
		if local && !p.localFollowerRelayReady(ctx) || !local && p.opaqueFollowerRelay == nil {
			return empty, nil, 0, media.ErrUnavailable
		}
		return plan, map[string]string{"X-Media-Relay": plan.Token}, expiry, nil
	}
	return plan, map[string]string{"X-Media-Capability": plan.Token}, expiry, nil
}
