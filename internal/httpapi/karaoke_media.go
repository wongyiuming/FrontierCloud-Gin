package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

// The peer verifier attests HTTPS before forwarding. Read-only media routes
// also require its active admission below; account routes may run after commit.
func secureKaraokeTransport(request *http.Request, resolver *network.Resolver) bool {
	return request != nil && resolver != nil && securePublicCryptoTransport(request, resolver)
}

func RegisterKaraokeMedia(router *gin.Engine, public *Public, resolver *network.Resolver) {
	opaqueAdmission := func(c *gin.Context) {
		ctx := c.Request.Context()
		_, peer := network.AuthenticatedIngressFromContext(ctx)
		if public.opaqueTree == nil {
			if peer {
				detail(c, 503, "Karaoke media unavailable")
				c.Abort()
				return
			}
			c.Next()
			return
		}
		if !public.settings.TLSEnabled || !secureKaraokeTransport(c.Request, resolver) || peer && !network.HasActivePublicAdmission(ctx) {
			detail(c, 403, "Karaoke global media requires HTTPS")
			c.Abort()
			return
		}
		public.catalogIngressAdmission()(c)
	}
	opaqueTrack := func(c *gin.Context) (string, bool) {
		tokens := c.Request.URL.Query()["media"]
		if len(tokens) != 1 {
			invalid(c, "query", "media")
			return "", false
		}
		return tokens[0], true
	}
	resolve := func(c *gin.Context) (media.KaraokeMedia, bool) {
		noStore(c)
		tokens := c.Request.URL.Query()["media"]
		if len(tokens) != 1 {
			invalid(c, "query", "media")
			return media.KaraokeMedia{}, false
		}
		v, e := public.media.ResolveKaraoke(c.Request.Context(), tokens[0])
		if e != nil {
			if errors.Is(e, media.ErrUnavailable) {
				detail(c, 503, e.Error())
			} else if errors.Is(e, os.ErrNotExist) {
				detail(c, 404, "Karaoke media not found")
			} else {
				internalError(c, e)
			}
			return v, false
		}
		if v.Kind == "global" && (!public.settings.TLSEnabled || !resolver.SecureAdmin(c.Request)) {
			detail(c, 403, "Karaoke global media requires HTTPS")
			return v, false
		}
		return v, true
	}
	router.GET("/api/v1/karaoke/context", opaqueAdmission, func(c *gin.Context) {
		if public.opaqueTree != nil {
			token, ok := opaqueTrack(c)
			if !ok {
				return
			}
			track, hasLyrics, err := public.media.DescribeOpaqueKaraoke(c.Request.Context(), public.opaqueTree, token)
			if err != nil {
				detail(c, 503, "Karaoke media unavailable")
				return
			}
			var lyrics any
			if hasLyrics {
				lyrics = "/api/v1/karaoke/lyrics?" + url.Values{"media": {token}}.Encode()
			}
			noStore(c)
			data := gin.H{"id": token, "file_path": track.Path, "resource_id": track.ID, "object_id": track.ObjectID, "size_bytes": track.Bytes, "encryption": track.Encryption, "title": strings.TrimSuffix(path.Base(track.Path), path.Ext(track.Path)), "type": track.Kind, "has_lyrics": hasLyrics, "lyrics_url": lyrics, "cover_url": "/favicon.ico"}
			if track.S3 {
				data["transport"] = "S3"
			} else {
				data["transport"], data["native_source"], data["source_identity_version"] = "Native", true, 1
			}
			c.JSON(200, data)
			return
		}
		v, ok := resolve(c)
		if !ok {
			return
		}
		query := url.Values{"media": {c.Query("media")}}.Encode()
		var lyrics any
		if v.HasLyrics {
			lyrics = "/api/v1/karaoke/lyrics?" + query
		}
		object, err := public.media.CryptoObject(c.Request.Context(), v.Path, func() string {
			if v.Kind == "global" {
				return v.ID
			}
			return ""
		}(), false)
		if err != nil {
			cryptoError(c, err)
			return
		}
		c.JSON(200, gin.H{"id": c.Query("media"), "file_path": v.Path, "encryption": object.Encryption, "title": strings.TrimSuffix(path.Base(v.Path), path.Ext(v.Path)), "type": v.Type, "stream_url": "/api/v1/karaoke/stream?" + query, "has_lyrics": v.HasLyrics, "lyrics_url": lyrics, "cover_url": "/favicon.ico"})
	})
	serve := func(c *gin.Context) {
		if public.opaqueTree != nil {
			detail(c, 503, "Karaoke media unavailable")
			return
		}
		v, ok := resolve(c)
		if !ok {
			return
		}
		id := ""
		if v.Kind == "global" {
			id = v.ID
		}
		c.Set("karaoke_no_store", true)
		public.deliver(c, v.Path, id)
	}
	router.GET("/api/v1/karaoke/stream", serve)
	router.HEAD("/api/v1/karaoke/stream", serve)
	router.GET("/api/v1/karaoke/lyrics", opaqueAdmission, func(c *gin.Context) {
		if public.opaqueTree != nil {
			token, ok := opaqueTrack(c)
			if !ok {
				return
			}
			track, hasLyrics, err := public.media.DescribeOpaqueKaraoke(c.Request.Context(), public.opaqueTree, token)
			if err != nil || !hasLyrics {
				detail(c, 503, "Karaoke lyrics unavailable")
				return
			}
			if !track.ExplicitLyric {
				entries, fallback, e := public.media.OpaqueKaraokeBuiltinFallback(c.Request.Context(), public.opaqueTree, token)
				if e == nil && fallback {
					noStore(c)
					c.JSON(200, gin.H{"entries": entries})
					return
				}
				detail(c, 503, "Karaoke lyrics unavailable")
				return
			}
			_, lyric, err := public.media.DescribeOpaqueLinkedLyric(c.Request.Context(), public.opaqueTree, track.ID)
			if err != nil {
				detail(c, 503, "Karaoke lyrics unavailable")
				return
			}
			data := gin.H{"file_path": lyric.Path, "resource_id": lyric.Entry.ObjectID, "object_id": lyric.Entry.ObjectID, "track_resource_id": track.ID, "size_bytes": lyric.Placement.Bytes, "native_source": true, "source_identity_version": 1}
			if lyric.Placement.Encryption != nil {
				data["encrypted"], data["encryption"] = true, lyric.Placement.Encryption
			} else {
				data["native_lyric"] = true
			}
			noStore(c)
			c.JSON(200, data)
			return
		}
		v, ok := resolve(c)
		if !ok {
			return
		}
		if !v.HasLyrics {
			detail(c, 404, "Lyrics not found")
			return
		}
		id := ""
		if v.Kind == "global" {
			id = v.ID
		}
		object, err := public.media.EncryptedLyric(c.Request.Context(), v.Path, id)
		if err != nil {
			cryptoError(c, err)
			return
		}
		if object.Encryption != nil {
			c.JSON(200, cryptoEncryptedLyrics(object.Path, object.Encryption))
			return
		}
		entries, e := public.media.KaraokeLyrics(c.Request.Context(), v)
		if e != nil {
			internalError(c, e)
			return
		}
		c.JSON(200, gin.H{"entries": entries})
	})
}
