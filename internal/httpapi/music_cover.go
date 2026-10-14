package httpapi

import (
	"bytes"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func (p *Public) musicCover(c *gin.Context) {
	tags, err := p.media.MusicMetadata(c.Request.Context(), c.Query("file_path"), c.Query("resource_id"))
	if err != nil || len(tags.Picture) == 0 {
		detail(c, 404, "Album cover not found")
		return
	}
	c.Header("Content-Type", tags.MIME)
	c.Header("Cache-Control", "private, max-age=300")
	http.ServeContent(c.Writer, c.Request, "cover", time.Time{}, bytes.NewReader(tags.Picture))
}
