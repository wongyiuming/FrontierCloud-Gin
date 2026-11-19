//go:build linux

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RegisterNodeMediaGuarded only accepts the real ownerfence-backed adapter.
// Product startup deliberately does not call it while activation is gated.
func RegisterNodeMediaGuarded(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service, guard *node.LegacyReadGuard) error {
	if guard == nil || !guard.ReadyFor(control, volume) {
		return node.ErrCapability
	}
	return registerNodeMediaGuarded(router, settings, resolver, control, volume, guard)
}

// RegisterLegacyReadDrainControl is an explicit isolated-only endpoint. A
// pure-Go configuration does not prove that earlier X-Accel transfers or old
// processes have drained; startup intentionally does not register this route.
func RegisterLegacyReadDrainControl(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service, guard *node.LegacyReadGuard) error {
	if router == nil || resolver == nil || control == nil || volume == nil || guard == nil || !guard.ReadyFor(control, volume) || settings.NginxMedia {
		return node.ErrCapability
	}
	router.POST(protocol.LegacyReadEnrollmentPath, func(c *gin.Context) {
		noStore(c)
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			detail(c, http.StatusBadRequest, "Invalid control request")
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var request protocol.LegacyReadEnrollmentRequest
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !request.Valid() {
			detail(c, http.StatusBadRequest, "Invalid control request")
			return
		}
		bounded, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		signed, err := guard.AttestEnrollment(bounded, request, func(held context.Context) (store.Relationship, error) {
			relation, err := control.Authenticate(held, c.Request.Header, c.Request.Method, protocol.LegacyReadEnrollmentPath, body, false, false)
			if err != nil {
				return store.Relationship{}, err
			}
			if err = control.RequireFollower(held, relation); err != nil {
				return store.Relationship{}, err
			}
			return relation, nil
		})
		if err != nil {
			detail(c, http.StatusServiceUnavailable, "Legacy media enrollment unavailable")
			return
		}
		c.JSON(http.StatusOK, signed)
	})
	router.POST(protocol.LegacyReadStatusPath, func(c *gin.Context) {
		noStore(c)
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			detail(c, http.StatusBadRequest, "Invalid control request")
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var request protocol.LegacyReadStatusRequest
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
			detail(c, http.StatusBadRequest, "Invalid control request")
			return
		}
		if _, err := request.Receipt("revoked"); err != nil {
			detail(c, http.StatusBadRequest, "Invalid control request")
			return
		}
		bounded, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		signed, err := guard.ObserveStatus(bounded, request, func(held context.Context) (store.Relationship, error) {
			relation, err := control.Authenticate(held, c.Request.Header, c.Request.Method, protocol.LegacyReadStatusPath, body, false, false)
			if err != nil {
				return store.Relationship{}, err
			}
			if err = control.RequireFollower(held, relation); err != nil {
				return store.Relationship{}, err
			}
			return relation, nil
		})
		if err != nil {
			detail(c, http.StatusServiceUnavailable, "Legacy media status unavailable")
			return
		}
		c.JSON(http.StatusOK, signed)
	})
	router.POST(protocol.LegacyReadDrainPath, func(c *gin.Context) {
		noStore(c)
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			detail(c, http.StatusBadRequest, "Invalid control request")
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var receipt protocol.LegacyReadDrainReceipt
		if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF {
			detail(c, http.StatusBadRequest, "Invalid control request")
			return
		}
		if _, err := receipt.Payload(); err != nil {
			detail(c, http.StatusBadRequest, "Invalid control request")
			return
		}
		bounded, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		signed, err := guard.Drain(bounded, receipt, func(held context.Context) (store.Relationship, error) {
			relation, err := control.Authenticate(held, c.Request.Header, c.Request.Method, protocol.LegacyReadDrainPath, body, false, false)
			if err != nil {
				return store.Relationship{}, err
			}
			if err = control.RequireFollower(held, relation); err != nil {
				return store.Relationship{}, err
			}
			return relation, nil
		})
		if err != nil {
			detail(c, http.StatusServiceUnavailable, "Legacy media drain unavailable")
			return
		}
		c.JSON(http.StatusOK, signed)
	})
	return nil
}
