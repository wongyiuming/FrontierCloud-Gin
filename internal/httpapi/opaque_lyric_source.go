package httpapi

import (
	"context"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func opaqueLyricAdmissionAlive(ctx context.Context) bool {
	if ctx == nil || !network.HasActivePublicAdmission(ctx) {
		return false
	}
	_, _, _, active := mediacrypto.DirectSessionFromContext(ctx).Values()
	prerequisite, ok := store.IngressPrerequisiteFromContext(ctx)
	if !active || !ok {
		return false
	}
	if lease, valid := prerequisite.(*sealedtree.TreeLease); valid {
		return lease != nil && lease.Check(ctx) == nil
	}
	reader, valid := prerequisite.(interface {
		ReadLinkedVisibleLyric(context.Context, *sealedtree.SQLStore, string) (sealedtree.VisibleObject, sealedtree.VisibleObject, error)
	})
	return valid && reader != nil && prerequisite.Check(ctx) == nil
}

type opaqueLyricSourcePlan struct {
	source, alias, revision, origin, transport string
	headers                                    map[string]string
	expires                                    int64
}

func (p *Public) issueOpaqueLyricSource(ctx context.Context, binding, sessionID, trackID, lyricID string) (opaqueLyricSourcePlan, error) {
	var plan opaqueLyricSourcePlan
	if _, local := network.LocalPublicIngressFromContext(ctx); local {
		if p.masterLocalLyric == nil || p.masterLocalLyric.tree != p.opaqueTree {
			return plan, media.ErrUnavailable
		}
		var err error
		plan.transport = "Local"
		plan.source, plan.headers, plan.alias, plan.expires, err = p.masterLocalLyric.Issue(ctx, trackID, lyricID, binding, sessionID)
		if err == nil {
			var claim node.MasterLocalLyricClaim
			claim, err = p.masterLocalLyric.control.VerifyMasterLocalLyricCapability(ctx, plan.headers["X-Media-Capability"], plan.alias)
			plan.revision = claim.Revision
		}
		if err != nil || plan.source == "" || plan.expires-time.Now().Unix() <= 1 {
			return opaqueLyricSourcePlan{}, media.ErrUnavailable
		}
		return plan, nil
	}
	policy, err := p.media.MasterIngressPolicy(ctx)
	if err != nil || policy.State != "applied" || policy.ConfiguredTransport != policy.AppliedTransport {
		return plan, media.ErrUnavailable
	}
	plan.transport = policy.AppliedTransport
	switch plan.transport {
	case "Direct":
		if p.masterDirect == nil || p.masterDirect.opaqueTree != p.opaqueTree {
			return opaqueLyricSourcePlan{}, media.ErrUnavailable
		}
		plan.source, plan.headers, plan.alias, err = p.masterDirect.IssueOpaqueLyric(ctx, trackID, lyricID, binding, sessionID)
		if err == nil {
			var claim node.MasterDirectClaim
			claim, err = p.masterDirect.control.VerifyMasterDirectCapability(ctx, plan.headers["X-Media-Capability"], p.masterDirect.origin, plan.alias)
			plan.revision, plan.expires, plan.origin = claim.Revision, claim.ExpiresAt, p.masterDirect.origin
		}
	case "Relay":
		if p.masterRelay == nil || p.masterRelay.opaqueTree != p.opaqueTree {
			return opaqueLyricSourcePlan{}, media.ErrUnavailable
		}
		plan.source, plan.headers, plan.alias, plan.expires, err = p.masterRelay.IssueOpaqueLyric(ctx, trackID, lyricID, binding, sessionID)
		if err == nil {
			var claim node.MasterRelayClaim
			claim, err = p.masterRelay.control.VerifyMasterRelayCapability(ctx, plan.headers["X-Media-Relay"], plan.alias)
			plan.revision = claim.Revision
		}
	default:
		err = media.ErrUnavailable
	}
	if err != nil || plan.source == "" || plan.expires-time.Now().Unix() <= 1 {
		return opaqueLyricSourcePlan{}, media.ErrUnavailable
	}
	return plan, nil
}

// opaqueLyricMetadata returns only the already-public association. The
// subsequent source request separately requires the live browser session.
func (p *Public) opaqueLyricMetadata(c *gin.Context, page bool) {
	trackID, requestedPath := c.Query("resource_id"), c.Query("track")
	if !masterDirectObject.MatchString(trackID) || requestedPath == "" {
		detail(c, http.StatusServiceUnavailable, "歌词资源路径不可用")
		return
	}
	trackPath, lyric, err := p.media.DescribeOpaqueLinkedLyric(c.Request.Context(), p.opaqueTree, trackID)
	if err != nil || trackPath != requestedPath {
		entries, fallback, e := p.media.OpaqueTrackBuiltinFallback(c.Request.Context(), p.opaqueTree, trackID, requestedPath)
		if e == nil && fallback {
			noStore(c)
			if page {
				lines := make([]string, 0, len(entries))
				for _, entry := range entries {
					lines = append(lines, entry.Text)
				}
				p.page(c, "lyrics.html", map[string]string{"LYRICS_JSON": jsonString(lines), "LINE_COUNT": strconv.Itoa(len(lines))})
			} else {
				c.JSON(http.StatusOK, gin.H{"entries": entries})
			}
			return
		}
		detail(c, http.StatusServiceUnavailable, "歌词资源路径不可用")
		return
	}
	data := gin.H{"file_path": lyric.Path, "resource_id": lyric.Entry.ObjectID, "object_id": lyric.Entry.ObjectID, "track_resource_id": trackID, "size_bytes": lyric.Placement.Bytes, "source_identity_version": 1}
	if lyric.Placement.Encryption != nil {
		data["encrypted"], data["native_source"], data["encryption"] = true, true, lyric.Placement.Encryption
	}
	noStore(c)
	if page {
		data["native_source"] = true
		p.page(c, "lyrics.html", map[string]string{"LYRICS_JSON": "[]", "LINE_COUNT": "0", "ENCRYPTED_LYRICS_JSON": jsonString(data)})
		return
	}
	if lyric.Placement.Encryption == nil {
		data["native_lyric"] = true
	} else {
		data["lyric_path"] = lyric.Path
	}
	c.JSON(http.StatusOK, data)
}

// opaquePlainLyricSource selects only the administrator's applied Master
// transport. A missing or failed reader never causes an automatic fallback.
func (p *Public) opaquePlainLyricSource(c *gin.Context, binding, sessionID, trackID, lyricID, objectID, name string) {
	if !masterDirectObject.MatchString(trackID) || !masterDirectObject.MatchString(lyricID) || objectID != lyricID {
		detail(c, http.StatusServiceUnavailable, "歌词资源路径不可用")
		return
	}
	ctx, err := p.crypto.WithDirectSession(c.Request.Context(), binding, sessionID)
	if err != nil {
		cryptoError(c, err)
		return
	}
	lyric, err := p.media.ResolveOpaqueLinkedLyric(ctx, p.opaqueTree, trackID, lyricID)
	if err != nil || lyric.Path != name || lyric.Placement.Encryption != nil {
		detail(c, http.StatusServiceUnavailable, "歌词资源路径不可用")
		return
	}
	plan, err := p.issueOpaqueLyricSource(ctx, binding, sessionID, trackID, lyricID)
	now := time.Now().Unix()
	if err != nil || plan.expires-now <= 1 || !node.ValidIdentifier(lyric.Placement.OwnerID) || !opaqueLyricAdmissionAlive(ctx) {
		detail(c, http.StatusServiceUnavailable, "歌词资源路径不可用")
		return
	}
	noStore(c)
	response := gin.H{
		"transport": "Native", "source_identity_version": 1, "resource_id": lyricID, "object_id": objectID,
		"source_object_id": plan.alias, "source_owner_id": lyric.Placement.OwnerID, "size_bytes": lyric.Placement.Bytes,
		"source_revision": plan.revision, "source_url": plan.source,
		"source_headers": plan.headers, "source_transport": plan.transport,
		"source_expires_at": plan.expires - 1, "source_expires_in": plan.expires - now - 1,
		"content_type": "text/plain; charset=utf-8", "filename": path.Base(name),
	}
	if plan.origin != "" {
		response["source_origin"] = plan.origin
	}
	c.JSON(http.StatusOK, response)
}

func (p *Public) opaqueEncryptedLyricKey(c *gin.Context, binding string, body cryptoKeyBody) {
	if !masterDirectObject.MatchString(body.TrackResourceID) || !masterDirectObject.MatchString(body.ResourceID) || body.ObjectID != body.ResourceID {
		detail(c, http.StatusServiceUnavailable, "歌词资源路径不可用")
		return
	}
	ctx, err := p.crypto.WithDirectSession(c.Request.Context(), binding, body.SessionID)
	if err != nil {
		cryptoError(c, err)
		return
	}
	lyric, err := p.media.ResolveOpaqueLinkedLyric(ctx, p.opaqueTree, body.TrackResourceID, body.ResourceID)
	if err != nil || lyric.Path != body.FilePath || lyric.Placement.Encryption == nil {
		detail(c, http.StatusServiceUnavailable, "歌词资源路径不可用")
		return
	}
	envelope, err := p.crypto.Wrap(binding, body.SessionID, *lyric.Placement.Encryption)
	if err != nil {
		cryptoError(c, err)
		return
	}
	plan, err := p.issueOpaqueLyricSource(ctx, binding, body.SessionID, body.TrackResourceID, body.ResourceID)
	now := time.Now().Unix()
	expires := min(plan.expires, envelope.ExpiresAt) - 1
	if err != nil || expires-now < 1 || !node.ValidIdentifier(lyric.Placement.OwnerID) || !opaqueLyricAdmissionAlive(ctx) {
		detail(c, http.StatusServiceUnavailable, "歌词资源路径不可用")
		return
	}
	response := gin.H{
		"transport": "Native", "source_identity_version": 1, "resource_id": body.ResourceID, "object_id": body.ObjectID,
		"source_object_id": plan.alias, "source_owner_id": lyric.Placement.OwnerID, "source_revision": plan.revision,
		"encryption": lyric.Placement.Encryption, "key_envelope": envelope,
		"source_url": plan.source, "source_headers": plan.headers, "source_transport": plan.transport,
		"source_expires_at": expires, "source_expires_in": expires - now,
		"content_type": "text/plain; charset=utf-8", "filename": path.Base(body.FilePath),
	}
	if plan.origin != "" {
		response["source_origin"] = plan.origin
	}
	noStore(c)
	c.JSON(http.StatusOK, response)
}
