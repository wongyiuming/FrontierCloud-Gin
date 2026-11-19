package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Browser ciphertext reads request exactly one bounded GCM chunk. All other
// requests retain the existing full-content verification path.
func opaqueBrowserCipherRange(r *http.Request, size int64) bool {
	_, end, ok := parseOpaqueBrowserCipherRange(r)
	return ok && end < size
}

func parseOpaqueBrowserCipherRange(r *http.Request) (int64, int64, bool) {
	if r.Method != http.MethodGet || len(r.Header.Values("Range")) != 1 || r.Header.Get("If-Range") != "" {
		return 0, 0, false
	}
	value := r.Header.Get("Range")
	if len(value) > 96 || !strings.HasPrefix(value, "bytes=") {
		return 0, 0, false
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes="), "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, false
	}
	for _, part := range parts {
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return 0, 0, false
			}
		}
	}
	start, firstErr := strconv.ParseInt(parts[0], 10, 64)
	end, lastErr := strconv.ParseInt(parts[1], 10, 64)
	return start, end, firstErr == nil && lastErr == nil && start >= 0 && end >= start && end-start < mediacrypto.ChunkSize+16
}

// RegisterOpaqueNodeMedia is explicit and is not installed by production
// startup until opaque storage, migration and readiness are fully wired.
func RegisterOpaqueNodeMedia(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service) {
	adminOriginGate := newSelectedOriginGate(8, 8, 2)
	serve := func(c *gin.Context) {
		noStore(c)
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		if c.Request.Method == http.MethodOptions {
			nodeMediaOriginPreflight(c, func(ctx context.Context, requested string) bool {
				ingress, _, err := control.ObservedPublicIngress(ctx)
				if err == nil && ingress.PublicOrigin == requested {
					return true
				}
				if !adminOriginGate.acquire() {
					return false
				}
				defer adminOriginGate.release()
				origin, err := control.FreshSelectedAdminOrigin(ctx, "")
				return err == nil && requested == origin
			})
			return
		}
		if challenges := c.Request.Header.Values("X-Fc-Opaque-Probe"); len(challenges) != 0 {
			tokens := c.Request.Header.Values("X-Media-Capability")
			if c.Request.Method != http.MethodGet || c.Request.URL.Path != node.NativeOpaqueMediaProbePath || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || c.Request.ContentLength > 0 || len(c.Request.TransferEncoding) != 0 || len(challenges) != 1 || !node.ValidIdentifier(challenges[0]) || len(tokens) != 1 || tokens[0] == "" || len(tokens[0]) > 4096 {
				detail(c, http.StatusBadRequest, "Invalid opaque media probe")
				return
			}
			relation, err := control.Authenticate(c.Request.Context(), c.Request.Header, c.Request.Method, c.Request.URL.EscapedPath(), nil, false, false)
			if err != nil {
				detail(c, http.StatusUnauthorized, "Invalid relationship authentication")
				return
			}
			signed, err := control.VerifyOwnedOpaqueMediaProbe(c.Request.Context(), relation, challenges[0], tokens[0])
			if err != nil {
				detail(c, http.StatusServiceUnavailable, "Opaque media probe unavailable")
				return
			}
			c.JSON(http.StatusOK, signed)
			return
		}
		values := c.Request.Header.Values("X-Media-Capability")
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || len(values) != 1 || values[0] == "" || len(values[0]) > 4096 {
			detail(c, http.StatusUnauthorized, "Media capability invalid or expired")
			return
		}
		relation, claims, err := control.VerifyOwnedOpaqueMedia(c.Request.Context(), values[0], c.Param("object"))
		adminDownload := false
		if err != nil {
			relation, claims, err = control.VerifyOwnedOpaqueAdminDownload(c.Request.Context(), values[0], c.Param("object"))
			adminDownload = err == nil
		}
		if err != nil {
			detail(c, http.StatusUnauthorized, "Media capability invalid or expired")
			return
		}
		origin, _ := claims["origin"].(string)
		origins := c.Request.Header.Values("Origin")
		if len(origins) > 1 || len(origins) == 1 && origins[0] != origin {
			detail(c, http.StatusForbidden, "Unpaired media origin")
			return
		}
		if adminDownload {
			mode, _ := claims["transport"].(string)
			target, _ := claims["target_origin"].(string)
			direct, parseErr := url.Parse(target)
			if mode == "Direct" && (len(origins) != 1 || parseErr != nil || !strings.EqualFold(c.Request.Host, direct.Host)) ||
				mode == "Relay" && len(origins) != 0 {
				detail(c, http.StatusForbidden, "Admin download origin rejected")
				return
			}
		}
		c.Header("Vary", "Origin")
		if len(origins) == 1 {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, ETag")
		}
		blob, _ := claims["blob"].(string)
		digest, _ := claims["content_sha256"].(string)
		descriptor, _ := claims["descriptor"].(string)
		revision, _ := claims["revision"].(string)
		masterID, _ := claims["m"].(string)
		ownerID, _ := claims["o"].(string)
		encodedSize, ok := claims["size"].(json.Number)
		if !ok {
			detail(c, http.StatusUnauthorized, "Media capability invalid or expired")
			return
		}
		size, err := encodedSize.Int64()
		if err != nil {
			detail(c, http.StatusUnauthorized, "Media capability invalid or expired")
			return
		}
		if adminDownload {
			start, end, ok := parseOpaqueBrowserCipherRange(c.Request)
			plainDescriptor, e := protocol.IngressMediaDescriptor(size, nil)
			if !ok || start >= size || start%(mediacrypto.ChunkSize+16) != 0 || end != min(start+mediacrypto.ChunkSize+16, size)-1 ||
				e != nil || descriptor == plainDescriptor {
				detail(c, http.StatusRequestedRangeNotSatisfiable, "Admin download requires one encrypted range")
				return
			}
		}
		encodedExpiry, ok := claims["e"].(json.Number)
		if !ok {
			detail(c, http.StatusUnauthorized, "Media capability invalid or expired")
			return
		}
		expiry, err := encodedExpiry.Int64()
		if err != nil || expiry <= time.Now().Unix() {
			detail(c, http.StatusUnauthorized, "Media capability invalid or expired")
			return
		}
		deadline := time.Unix(expiry, 0)
		controller := http.NewResponseController(c.Writer)
		if err := controller.SetWriteDeadline(deadline); err != nil {
			detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
			return
		}
		defer controller.SetWriteDeadline(time.Time{})
		bounded, cancel := context.WithDeadline(c.Request.Context(), deadline)
		defer cancel()
		if adminDownload {
			lease, err := control.AcquireOpaqueAdminDownloadOwnerPolicy(bounded, relation, claims)
			if err != nil {
				detail(c, http.StatusConflict, "Admin download policy changed")
				return
			}
			defer lease.Release()
		}
		logical, _ := claims["g"].(string)
		// Both identities are the opaque wire alias. Before this route can be
		// activated, lifecycle/recovery/deletion fences must use the same alias;
		// legacy ID keyed migration fences alone do not prove that property.
		readCtx, release, err := control.ProtectOwnedRead(bounded, relation.ID, logical, c.Param("object"), "media", func() {})
		if err != nil {
			detail(c, http.StatusConflict, "Resource read is fenced by migration or node state")
			return
		}
		defer release()
		c.Request = c.Request.WithContext(readCtx)
		binding := media.OpaqueOwnerBinding{MasterID: masterID, OwnerID: ownerID, RelationshipID: relation.ID, Alias: c.Param("object"), Blob: blob, Revision: revision, Digest: digest, Descriptor: descriptor, Size: size}
		plainDescriptor, descriptorErr := protocol.IngressMediaDescriptor(size, nil)
		var reader io.ReadSeeker
		var info os.FileInfo
		var closeStream func()
		if descriptorErr == nil && descriptor != plainDescriptor && opaqueBrowserCipherRange(c.Request, size) {
			var stream *media.OpaqueBrowserCipher
			stream, err = volume.OpenAuthorizedOpaqueBrowserCipher(readCtx, binding)
			if err == nil {
				reader, info, closeStream = stream.Reader, stream.Info, stream.Close
			}
		} else {
			var stream *media.VerifiedOpaqueBlob
			stream, err = volume.OpenAuthorizedOpaqueBlob(readCtx, binding)
			if err == nil {
				reader, info, closeStream = stream.Reader, stream.Info, stream.Close
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				detail(c, http.StatusNotFound, "Resource not found")
			} else if errors.Is(err, store.ErrNodeState) {
				detail(c, http.StatusConflict, "Resource changed since authorization")
			} else {
				internalError(c, err)
			}
			return
		}
		defer closeStream()
		c.Header("Content-Type", "application/octet-stream")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("ETag", `"`+digest+`"`)
		http.ServeContent(c.Writer, opaqueEmptyRangeRequest(c.Request, info.Size(), settings.NginxMedia), "blob", time.Time{}, reader)
		if verified, ok := reader.(interface{ Err() error }); ok && verified.Err() != nil {
			panic(http.ErrAbortHandler)
		}
	}
	router.GET("/internal/v1/opaque-media/:object", serve)
	router.HEAD("/internal/v1/opaque-media/:object", serve)
	router.OPTIONS("/internal/v1/opaque-media/:object", serve)
	control.ConfigureOpaqueReadProbe(volume.ProbeVerifiedOpaqueBlob)
}
