package httpapi

import (
	"errors"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// nativePlainSource is a distinct source plan; S3 keeps its existing contract.
// It handles only explicitly plaintext Master-owned media.
func (p *Public) nativePlainSource(c *gin.Context) {
	if !p.cryptoTransport(c) {
		return
	}
	_, peer := network.AuthenticatedIngressFromContext(c.Request.Context())
	_, local := network.LocalPublicIngressFromContext(c.Request.Context())
	if !peer && !(local && p.opaqueTree != nil) || !network.HasActivePublicAdmission(c.Request.Context()) {
		detail(c, http.StatusServiceUnavailable, "资源路径不可用")
		return
	}
	var body struct {
		SessionID       string `json:"session_id"`
		FilePath        string `json:"file_path"`
		ResourceID      string `json:"resource_id"`
		ObjectID        string `json:"object_id"`
		TrackResourceID string `json:"track_resource_id"`
	}
	if !cryptoDecode(c, &body) {
		return
	}
	if len(body.SessionID) != 32 || len(body.ResourceID) != 64 || len(body.ObjectID) != 64 || body.FilePath == "" || len(body.FilePath) > 4096 {
		invalid(c, "body", "identity")
		return
	}
	binding, err := p.browserBinding(c, false)
	if err != nil {
		cryptoError(c, err)
		return
	}
	lyric := strings.HasPrefix(body.FilePath, "lyrics/")
	if p.opaqueTree != nil && lyric {
		p.opaquePlainLyricSource(c, binding, body.SessionID, body.TrackResourceID, body.ResourceID, body.ObjectID, body.FilePath)
		return
	}
	resourceID := body.ResourceID
	if lyric {
		resourceID = ""
	}
	object, err := p.media.CryptoObject(c.Request.Context(), body.FilePath, resourceID, false)
	if err != nil {
		cryptoError(c, err)
		return
	}
	if object.Encryption != nil || object.ID != body.ResourceID || lyric != (object.Kind == "lyric") {
		detail(c, http.StatusConflict, "资源不是明文媒体")
		return
	}
	if p.opaqueTree != nil {
		// Once enabled there is no fallback to a legacy path.
		leaseCtx, sessionErr := p.crypto.WithDirectSession(c.Request.Context(), binding, body.SessionID)
		if sessionErr != nil {
			cryptoError(c, sessionErr)
			return
		}
		_, _, sessionExpiry, valid := mediacrypto.DirectSessionFromContext(leaseCtx).Values()
		if !valid {
			cryptoError(c, mediacrypto.ErrSession)
			return
		}
		expiry := min(sessionExpiry, time.Now().Unix()+protocol.TokenSeconds)
		plan, sourceErr := p.media.OpaqueIngressResource(leaseCtx, p.opaqueTree, object, body.ObjectID, expiry)
		if sourceErr == nil && local && plan.Transport == "Local" && !p.masterLocalMediaReady(c.Request.Context()) {
			sourceErr = media.ErrUnavailable
		}
		if sourceErr == nil && local && plan.Transport == "Relay" && !p.localFollowerRelayReady(c.Request.Context()) {
			sourceErr = media.ErrUnavailable
		}
		if sourceErr != nil || expiry-time.Now().Unix() <= 1 || !node.ValidIdentifier(plan.OwnerID) || !masterDirectObject.MatchString(plan.SourceObjectID) || !masterDirectObject.MatchString(plan.Revision) {
			detail(c, http.StatusServiceUnavailable, "资源路径不可用")
			return
		}
		contentType := mime.TypeByExtension(path.Ext(object.Path))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		header := "X-Media-Capability"
		if plan.Transport == "Relay" {
			header = "X-Media-Relay"
		}
		response := gin.H{"transport": "Native", "resource_id": object.ID, "object_id": body.ObjectID, "size_bytes": plan.Size, "source_revision": plan.Revision, "source_url": plan.Source, "source_headers": map[string]string{header: plan.Token}, "source_transport": plan.Transport, "source_expires_at": expiry - 1, "source_expires_in": expiry - time.Now().Unix() - 1, "content_type": contentType, "filename": path.Base(object.Path)}
		response["source_object_id"] = plan.SourceObjectID
		response["source_owner_id"] = plan.OwnerID
		response["source_identity_version"] = 1
		if plan.Transport == "Direct" {
			response["source_origin"] = plan.Origin
		}
		noStore(c)
		c.JSON(http.StatusOK, response)
		return
	}
	if !lyric {
		local, followerPolicy, localErr := p.media.FollowerIngressPolicy(c.Request.Context(), object)
		if localErr == nil && (local || followerPolicy.State == "applied" && followerPolicy.ConfiguredTransport == followerPolicy.AppliedTransport && (followerPolicy.AppliedTransport == "Direct" || followerPolicy.AppliedTransport == "Relay")) {
			leaseCtx, sessionErr := p.crypto.WithDirectSession(c.Request.Context(), binding, body.SessionID)
			if sessionErr != nil {
				cryptoError(c, sessionErr)
				return
			}
			_, _, sessionExpiry, valid := mediacrypto.DirectSessionFromContext(leaseCtx).Values()
			if !valid {
				cryptoError(c, mediacrypto.ErrSession)
				return
			}
			expiry := min(sessionExpiry, time.Now().Unix()+protocol.TokenSeconds)
			var source, origin, token, revision, mode string
			header := "X-Media-Capability"
			var size int64
			var sourceErr error
			if local {
				mode = "Local"
				source, token, revision, size, sourceErr = p.media.IngressLocalPlainSource(leaseCtx, object, body.ObjectID, expiry)
			} else if followerPolicy.AppliedTransport == "Direct" {
				mode = "Direct"
				source, origin, token, revision, size, sourceErr = p.media.FollowerDirectPlainSource(leaseCtx, object, body.ObjectID, expiry)
			} else if p.followerRelay != nil {
				mode, header = "Relay", "X-Media-Relay"
				var headers map[string]string
				var relayExpiry int64
				source, headers, relayExpiry, sourceErr = p.followerRelay.Issue(c.Request.Context(), object, binding, body.SessionID)
				if sourceErr == nil {
					token = headers[header]
					var row store.GlobalMedia
					var claim node.FollowerRelayClaim
					row, claim, sourceErr = p.media.FollowerRelayObject(c.Request.Context(), token, object.ID)
					if sourceErr == nil && (row.ObjectID != body.ObjectID || claim.ObjectID != body.ObjectID) {
						sourceErr = media.ErrUnavailable
					}
					revision, size, expiry = claim.Revision, row.Bytes, min(expiry, relayExpiry)
				}
			} else {
				sourceErr = media.ErrUnavailable
			}
			if sourceErr != nil || expiry-time.Now().Unix() <= 1 {
				detail(c, http.StatusServiceUnavailable, "资源路径不可用")
				return
			}
			contentType := mime.TypeByExtension(path.Ext(object.Path))
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			noStore(c)
			response := gin.H{"transport": "Native", "resource_id": object.ID, "object_id": body.ObjectID, "size_bytes": size, "source_revision": revision, "source_url": source, "source_headers": map[string]string{header: token}, "source_transport": mode, "source_expires_at": expiry - 1, "source_expires_in": expiry - time.Now().Unix() - 1, "content_type": contentType, "filename": path.Base(object.Path)}
			if origin != "" {
				response["source_origin"] = origin
			}
			c.JSON(http.StatusOK, response)
			return
		}
	}
	var size int64
	var revision, descriptor string
	if lyric {
		if body.ObjectID != object.ID {
			detail(c, http.StatusForbidden, "资源身份不符")
			return
		}
		size, revision, descriptor, err = p.media.MasterPlainLyricIdentity(c.Request.Context(), object)
	} else {
		owner, ownerErr := p.media.MasterOwnsIngressObject(c.Request.Context(), object)
		if ownerErr != nil || !owner {
			detail(c, http.StatusServiceUnavailable, "资源路径不可用")
			return
		}
		size, revision, descriptor, err = p.media.MasterPlainIdentity(c.Request.Context(), object, body.ObjectID)
	}
	if err != nil {
		cryptoError(c, err)
		return
	}
	policy, err := p.media.MasterIngressPolicy(c.Request.Context())
	if err != nil || policy.State != "applied" || policy.ConfiguredTransport != policy.AppliedTransport {
		detail(c, http.StatusServiceUnavailable, "资源路径不可用")
		return
	}
	var source, origin string
	var headers map[string]string
	var expiry int64
	switch policy.AppliedTransport {
	case "Direct":
		if p.masterDirect == nil {
			detail(c, http.StatusServiceUnavailable, "资源路径不可用")
			return
		}
		source, headers, err = p.masterDirect.Issue(c.Request.Context(), object, binding, body.SessionID)
		if err == nil {
			origin = p.masterDirect.origin
			var claim node.MasterDirectClaim
			claim, err = p.masterDirect.control.VerifyMasterDirectCapability(c.Request.Context(), headers["X-Media-Capability"], origin, object.ID)
			if err == nil && (claim.ObjectID != body.ObjectID || claim.Revision != revision || claim.Descriptor != descriptor) {
				err = media.ErrUnavailable
			}
			expiry = claim.ExpiresAt
		}
	case "Relay":
		if p.masterRelay == nil {
			detail(c, http.StatusServiceUnavailable, "资源路径不可用")
			return
		}
		source, headers, expiry, err = p.masterRelay.Issue(c.Request.Context(), object, binding, body.SessionID)
		if err == nil {
			var claim node.MasterRelayClaim
			claim, err = p.masterRelay.control.VerifyMasterRelayCapability(c.Request.Context(), headers["X-Media-Relay"], object.ID)
			if err == nil && (claim.ObjectID != body.ObjectID || claim.Revision != revision || claim.Descriptor != descriptor) {
				err = media.ErrUnavailable
			}
		}
	default:
		err = media.ErrUnavailable
	}
	if err != nil {
		if errors.Is(err, node.ErrCapability) {
			err = media.ErrUnavailable
		}
		cryptoError(c, err)
		return
	}
	ttl := expiry - time.Now().Unix() - 1
	if ttl < 1 || ttl > protocol.TokenSeconds {
		detail(c, http.StatusServiceUnavailable, "资源授权已失效")
		return
	}
	contentType := mime.TypeByExtension(path.Ext(object.Path))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	response := gin.H{"transport": "Native", "resource_id": object.ID, "object_id": body.ObjectID, "size_bytes": size, "source_revision": revision, "source_url": source, "source_headers": headers, "source_transport": policy.AppliedTransport, "source_expires_at": expiry - 1, "source_expires_in": ttl, "content_type": contentType, "filename": path.Base(object.Path)}
	if origin != "" {
		response["source_origin"] = origin
	}
	noStore(c)
	c.JSON(http.StatusOK, response)
}
