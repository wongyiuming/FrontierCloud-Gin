package httpapi

import (
	"net/http"
	"path"

	"github.com/gin-gonic/gin"
)

// An issued mixed archive plan is the audited action. Range reads retain the
// plan's immutable source identity without generating duplicate audit events.
func (a *Admin) downloadPlanBytes(c *gin.Context) {
	noStore(c)
	d, err := a.public.media.Download(c.Request.Context(), []string{c.Query("file_path")})
	if err != nil {
		mediaAdminError(c, err)
		return
	}
	defer d.Close()
	delivery, err := d.PlanDelivery(c.Query("media_id"), c.Query("snapshot"), c.GetString("request_id"), c.GetString("trace_id"), a.settings.NginxMedia)
	if err != nil {
		mediaAdminError(c, err)
		return
	}
	c.Header("X-Media-Resource-ID", delivery.ResourceID)
	c.Header("X-Media-Owner-ID", delivery.OwnerID)
	c.Header("X-Media-Object-ID", delivery.ObjectID)
	if delivery.Redirect != "" {
		c.Header("Referrer-Policy", "no-referrer")
		c.Redirect(http.StatusTemporaryRedirect, delivery.Redirect)
		return
	}
	if delivery.Relay != "" {
		c.Header("X-Accel-Redirect", delivery.Relay)
		c.Status(http.StatusOK)
		return
	}
	stream := delivery.Stream
	defer stream.File.Close()
	c.Header("Content-Type", "application/octet-stream")
	// Serve the pinned descriptor directly. Deferring a local path read to Nginx
	// would release this lease before Nginx opened it, allowing substitution.
	http.ServeContent(c.Writer, c.Request, path.Base(stream.Path), stream.Info.ModTime(), stream.File)
}
