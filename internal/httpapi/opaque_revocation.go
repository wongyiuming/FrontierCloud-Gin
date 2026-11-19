package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

// RegisterOpaqueRevocationControl is explicit; production startup keeps it
// unregistered until the complete Master intent and owner lifecycle is wired.
func RegisterOpaqueRevocationControl(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service) {
	router.POST(protocol.OpaqueRevokePath, func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			detail(c, http.StatusBadRequest, "Invalid opaque control request")
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		fence, err := control.AcquireOpaqueOwnerRequestFence(c.Request.Context())
		if err != nil {
			detail(c, http.StatusServiceUnavailable, "Opaque control unavailable")
			return
		}
		defer fence.Release()
		relation, err := control.Authenticate(c.Request.Context(), c.Request.Header, c.Request.Method, protocol.OpaqueRevokePath, body, false, false)
		if err != nil {
			detail(c, http.StatusUnauthorized, "Invalid relationship authentication")
			return
		}
		if err = control.RequireFollower(c.Request.Context(), relation); err != nil {
			detail(c, http.StatusForbidden, "Opaque control unavailable")
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var receipt protocol.OpaqueRevocationReceipt
		if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF {
			detail(c, http.StatusBadRequest, "Invalid opaque control request")
			return
		}
		_, err = receipt.Payload()
		identity, identityErr := control.IdentityState(c.Request.Context())
		if err != nil || identityErr != nil || identity.Role != "Follower" || receipt.OwnerID != identity.ID || receipt.MasterID != relation.PeerID || receipt.RelationshipID != relation.ID {
			detail(c, http.StatusForbidden, "Opaque control unavailable")
			return
		}
		if fence.Check(c.Request.Context()) != nil {
			detail(c, http.StatusServiceUnavailable, "Opaque control unavailable")
			return
		}
		if err = volume.RevokeOpaqueOwnerReceipt(c.Request.Context(), receipt); err != nil {
			detail(c, http.StatusConflict, "Opaque revocation unavailable")
			return
		}
		signed, err := control.SignOpaqueRevocationReceipt(c.Request.Context(), relation, receipt)
		if err != nil || fence.Check(c.Request.Context()) != nil {
			detail(c, http.StatusServiceUnavailable, "Opaque revocation unavailable")
			return
		}
		noStore(c)
		c.JSON(http.StatusOK, signed)
	})
	router.POST(protocol.OpaqueDeletePath, func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			detail(c, http.StatusBadRequest, "Invalid opaque control request")
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		fence, err := control.AcquireOpaqueOwnerRequestFence(c.Request.Context())
		if err != nil {
			detail(c, http.StatusServiceUnavailable, "Opaque control unavailable")
			return
		}
		defer fence.Release()
		relation, err := control.Authenticate(c.Request.Context(), c.Request.Header, c.Request.Method, protocol.OpaqueDeletePath, body, false, false)
		if err != nil {
			detail(c, http.StatusUnauthorized, "Invalid relationship authentication")
			return
		}
		if err = control.RequireFollower(c.Request.Context(), relation); err != nil {
			detail(c, http.StatusForbidden, "Opaque control unavailable")
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var receipt protocol.OpaqueDeletionReceipt
		if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF {
			detail(c, http.StatusBadRequest, "Invalid opaque control request")
			return
		}
		_, err = receipt.Payload()
		identity, identityErr := control.IdentityState(c.Request.Context())
		if err != nil || identityErr != nil || identity.Role != "Follower" || receipt.OwnerID != identity.ID || receipt.MasterID != relation.PeerID || receipt.RelationshipID != relation.ID {
			detail(c, http.StatusForbidden, "Opaque control unavailable")
			return
		}
		if fence.Check(c.Request.Context()) != nil {
			detail(c, http.StatusServiceUnavailable, "Opaque control unavailable")
			return
		}
		if err = volume.DeleteOpaqueOwnerBlob(c.Request.Context(), receipt); err != nil {
			detail(c, http.StatusConflict, "Opaque deletion unavailable")
			return
		}
		signed, err := control.SignOpaqueDeletionReceipt(c.Request.Context(), relation, receipt)
		if err != nil || fence.Check(c.Request.Context()) != nil {
			detail(c, http.StatusServiceUnavailable, "Opaque deletion unavailable")
			return
		}
		noStore(c)
		c.JSON(http.StatusOK, signed)
	})
}
