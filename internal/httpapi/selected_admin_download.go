package httpapi

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const selectedDownloadBytesPath = "/api/v1/media/admin/download/bytes"

func selectedDownloadError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, media.ErrUploadSize):
		detail(c, http.StatusRequestEntityTooLarge, "下载范围最多包含 5000 项，请分批下载")
	case errors.Is(err, media.ErrOpaqueAdminDownloadOwner):
		detail(c, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, sealedtree.ErrConflict):
		detail(c, http.StatusConflict, "下载资源已变化，请刷新目录后重新选择")
	case errors.Is(err, mediacrypto.ErrSession):
		cryptoError(c, err)
	case errors.Is(err, media.ErrPath), errors.Is(err, media.ErrCategory):
		mediaAdminError(c, err)
	default:
		detail(c, http.StatusServiceUnavailable, "加密下载暂不可用")
	}
}

func (a *Admin) selectedDownloadPlan(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	var request struct {
		Targets []media.OpaqueAdminDownloadTarget `json:"targets"`
	}
	if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || !strictJSON(c, &request, 512*1024) ||
		len(request.Targets) == 0 || len(request.Targets) > a.settings.AdminMaxDownloadItems {
		invalid(c, "body", "targets")
		return
	}
	seen := make(map[string]bool, len(request.Targets))
	for _, target := range request.Targets {
		if target.Path == "" || !utf8.ValidString(target.Path) || utf8.RuneCountInString(target.Path) > 1024 ||
			!masterDirectObject.MatchString(target.ResourceID) || seen[target.ResourceID] ||
			(target.Kind != "file" && target.Kind != "directory") {
			invalid(c, "body", "targets")
			return
		}
		seen[target.ResourceID] = true
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	var items []media.OpaqueAdminDownloadEntry
	var zip bool
	err := a.selectedUpload.WithAdminDownload(ctx, session(c).Hash, func(tree *sealedtree.SQLStore, lease *sealedtree.TreeLease) error {
		var err error
		items, zip, err = a.public.media.OpaqueAdminDownloadPlan(ctx, tree, lease, request.Targets)
		return err
	})
	if err != nil {
		selectedDownloadError(c, err)
		return
	}
	if err = a.auth.Audit(ctx, session(c).Hash, "download", "[]", "success", "sealed_encrypted_download_plan", len(items), a.info(c)); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "force_zip": zip})
}

func (a *Admin) selectedDownloadKey(c *gin.Context, body cryptoKeyBody) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	if !masterDirectObject.MatchString(body.ResourceID) || !masterDirectObject.MatchString(body.DownloadSnapshot) ||
		!node.ValidIdentifier(body.SessionID) || body.ObjectID != "" || body.TrackResourceID != "" || body.FilePath == "" ||
		c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
		invalid(c, "body", "download_snapshot")
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	binding := "admin:" + session(c).Hash
	ctx, err := a.public.crypto.WithDirectSession(ctx, binding, body.SessionID)
	if err != nil {
		cryptoError(c, err)
		return
	}
	var item media.OpaqueAdminDownloadEntry
	var envelope mediacrypto.KeyEnvelope
	var source s3media.SourceGrant
	var native media.OpaqueSourceDetails
	var nativeExpiry int64
	err = a.selectedUpload.WithAdminDownload(ctx, session(c).Hash, func(tree *sealedtree.SQLStore, lease *sealedtree.TreeLease) error {
		var err error
		item, err = a.public.media.OpaqueAdminDownloadEntry(ctx, tree, lease, body.ResourceID)
		if err != nil {
			return err
		}
		if item.Path != body.FilePath || item.Snapshot != body.DownloadSnapshot {
			return sealedtree.ErrConflict
		}
		envelope, err = a.public.crypto.Wrap(binding, body.SessionID, item.Encryption)
		if err == nil && item.Transport == "S3" {
			deadline := min(envelope.ExpiresAt, time.Now().Unix()+store.S3GrantSeconds)
			source, err = a.public.media.OpaqueAdminS3ReadSource(ctx, tree, lease, item, a.settings.AdminOrigin, deadline)
		}
		if err == nil && (item.Transport == "Direct" || item.Transport == "Relay") {
			native, nativeExpiry, err = a.public.media.OpaqueAdminFollowerDownloadGrant(ctx, item)
		}
		return err
	})
	if err != nil {
		selectedDownloadError(c, err)
		return
	}
	if item.Transport == "S3" {
		response, ok := s3SourceJSON(c, item.Path, source)
		if !ok {
			return
		}
		response["resource_id"], response["download_snapshot"] = item.ResourceID, item.Snapshot
		response["encryption"], response["key_envelope"] = item.Encryption, envelope
		c.JSON(http.StatusOK, response)
		return
	}
	if item.Transport == "Direct" {
		ttl := nativeExpiry - time.Now().Unix()
		if ttl < 1 || ttl > 300 {
			selectedDownloadError(c, media.ErrUnavailable)
			return
		}
		c.JSON(http.StatusOK, gin.H{"transport": "Native", "source_identity_version": 1, "resource_id": item.ResourceID,
			"object_id": item.ObjectID, "download_snapshot": item.Snapshot, "encryption": item.Encryption, "key_envelope": envelope,
			"source_url": native.Source, "source_origin": native.Origin, "source_transport": "Direct",
			"source_headers": gin.H{"X-Media-Capability": native.Token}, "source_object_id": native.SourceObjectID,
			"source_owner_id": native.OwnerID, "source_revision": native.Revision, "size_bytes": native.Size,
			"source_expires_in": ttl, "source_expires_at": nativeExpiry, "filename": item.Filename, "content_type": "application/octet-stream"})
		return
	}
	query := url.Values{"resource_id": {item.ResourceID}, "snapshot": {item.Snapshot}}
	c.JSON(http.StatusOK, gin.H{"resource_id": item.ResourceID, "download_snapshot": item.Snapshot, "filename": item.Filename,
		"encryption": item.Encryption, "key_envelope": envelope, "source_url": selectedDownloadBytesPath + "?" + query.Encode(),
		"content_type": "application/octet-stream"})
}

func (a *Admin) selectedDownloadBytes(c *gin.Context) {
	if !a.selectedAdminAllowed(c, false) {
		return
	}
	query, err := url.ParseQuery(c.Request.URL.RawQuery)
	resourceID, snapshot := query.Get("resource_id"), query.Get("snapshot")
	sessions := c.Request.Header.Values("X-Fc-Download-Session")
	if err != nil || len(query) != 2 || len(query["resource_id"]) != 1 || len(query["snapshot"]) != 1 || len(sessions) != 1 ||
		!masterDirectObject.MatchString(resourceID) || !masterDirectObject.MatchString(snapshot) || !node.ValidIdentifier(sessions[0]) {
		invalid(c, "query", "snapshot")
		return
	}
	start, end, ok := parseOpaqueBrowserCipherRange(c.Request)
	if !ok || start%(mediacrypto.ChunkSize+16) != 0 {
		detail(c, http.StatusRequestedRangeNotSatisfiable, "下载需要一个加密分块范围")
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	ctx, err = a.public.crypto.WithDirectSession(ctx, "admin:"+session(c).Hash, sessions[0])
	if err != nil {
		cryptoError(c, err)
		return
	}
	var reader *media.OpaqueBlob
	var relay io.ReadCloser
	var size int64
	err = a.selectedUpload.WithAdminDownload(ctx, session(c).Hash, func(tree *sealedtree.SQLStore, lease *sealedtree.TreeLease) error {
		item, err := a.public.media.OpaqueAdminDownloadEntry(ctx, tree, lease, resourceID)
		if err != nil {
			return err
		}
		if item.Snapshot != snapshot || item.Transport != "" && item.Transport != "Relay" {
			return sealedtree.ErrConflict
		}
		size = item.Encryption.CiphertextSize
		if start >= size || end != min(start+mediacrypto.ChunkSize+16, size)-1 {
			return errSelectedDownloadRange
		}
		if item.Transport == "Relay" {
			response, err := a.public.media.OpenOpaqueAdminRelayDownload(ctx, item, c.Request.Header.Get("Range"))
			if response.Body != nil {
				relay = response.Body
			}
			if err != nil || response.Status != http.StatusPartialContent || response.Length != end-start+1 || response.ContentRange != fmt.Sprintf("bytes %d-%d/%d", start, end, size) {
				return media.ErrUnavailable
			}
			return nil
		}
		reader, err = a.public.media.OpenOpaqueAdminDownload(ctx, item)
		return err
	})
	if reader != nil {
		defer reader.Close()
	}
	if relay != nil {
		defer relay.Close()
	}
	if errors.Is(err, errSelectedDownloadRange) {
		c.Header("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
		detail(c, http.StatusRequestedRangeNotSatisfiable, "下载需要一个加密分块范围")
		return
	}
	if err != nil {
		selectedDownloadError(c, err)
		return
	}
	if _, _, _, active := mediacrypto.DirectSessionFromContext(ctx).Values(); !active {
		cryptoError(c, mediacrypto.ErrSession)
		return
	}
	var body io.Reader = relay
	if reader != nil {
		if _, err = reader.Reader.Seek(start, io.SeekStart); err != nil {
			selectedDownloadError(c, err)
			return
		}
		body = reader.Reader
	}
	length := end - start + 1
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", strconv.FormatInt(length, 10))
	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	c.Header("Accept-Ranges", "bytes")
	c.Header("ETag", `"`+snapshot+`"`)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Status(http.StatusPartialContent)
	if _, err = io.CopyN(c.Writer, body, length); err != nil {
		panic(http.ErrAbortHandler)
	}
}

var errSelectedDownloadRange = errors.New("invalid encrypted download range")
