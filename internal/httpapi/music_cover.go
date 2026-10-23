package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
)

// Retry within the browser's fixed metadata deadline; media streaming's
// 30-second backoff would outlive that small optional-work budget.
func temporaryMusicMetadataError(err error) bool {
	return errors.Is(err, media.ErrMetadataBusy) || errors.Is(err, media.ErrUnavailable) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func (p *Public) musicMetadata(c *gin.Context) {
	name, ok := queryText(c, "file_path", 4096)
	if !ok {
		return
	}
	id := c.Query("resource_id")
	if !utf8.ValidString(id) || len(id) > 64 {
		invalid(c, "query", "resource_id")
		return
	}
	tags, err := p.media.MusicMetadata(c.Request.Context(), name, id)
	c.Header("Cache-Control", "private, no-store")
	if temporaryMusicMetadataError(err) {
		c.Header("Retry-After", "2")
		detail(c, 503, "Music metadata temporarily unavailable")
		return
	}
	if err != nil {
		detail(c, 404, "Music metadata not found")
		return
	}
	value := gin.H{}
	for key, text := range map[string]string{"title": tags.Title, "artist": tags.Artist, "album": tags.Album} {
		if text != "" {
			value[key] = text
		}
	}
	if len(tags.Picture) != 0 {
		value["cover"] = "/api/v1/media/cover?" + url.Values{"file_path": {name}, "resource_id": {id}}.Encode()
	}
	c.JSON(200, value)
}

func (p *Public) musicCover(c *gin.Context) {
	tags, err := p.media.MusicMetadata(c.Request.Context(), c.Query("file_path"), c.Query("resource_id"))
	if temporaryMusicMetadataError(err) {
		c.Header("Retry-After", "2")
		c.Header("Cache-Control", "private, no-store")
		detail(c, 503, "Music metadata temporarily unavailable")
		return
	}
	if err != nil || len(tags.Picture) == 0 {
		detail(c, 404, "Album cover not found")
		return
	}
	c.Header("Content-Type", tags.MIME)
	c.Header("Cache-Control", "private, max-age=300")
	c.Header("ETag", fmt.Sprintf(`"cover-%x"`, sha256.Sum256(tags.Picture)))
	http.ServeContent(c.Writer, c.Request, "cover", time.Time{}, bytes.NewReader(tags.Picture))
}
