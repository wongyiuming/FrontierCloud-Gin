package httpapi

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
)

const projectDiagnosticPath = "/api/v1/media/project-diagnostics"

// A fixed-size global admission budget avoids unbounded attacker-controlled IP
// maps and extra database/Redis work on the business Master. Reports are hints,
// never authority for security, playback or an automatic recovery action.
func registerProjectDiagnostics(router *gin.Engine, logs *logarchive.Runtime) {
	var mu sync.Mutex
	minute := int64(0)
	accepted := 0
	router.GET(projectDiagnosticPath, func(c *gin.Context) {
		noStore(c)
		c.JSON(200, gin.H{"enabled": logs.Enabled(), "max_reports_per_page": 12, "version": 1})
	})
	router.POST(projectDiagnosticPath, func(c *gin.Context) {
		noStore(c)
		if !logs.Enabled() {
			c.Status(204)
			return
		}
		mu.Lock()
		current := time.Now().Unix() / 60
		if current != minute {
			minute = current
			accepted = 0
		}
		allowed := accepted < 120
		if allowed {
			accepted++
		}
		mu.Unlock()
		if !allowed {
			c.Status(429)
			return
		}
		var v struct {
			Stage     string  `json:"stage"`
			Page      string  `json:"page"`
			MediaTime float64 `json:"media_time"`
			Ready     int     `json:"ready"`
			Network   int     `json:"network"`
			Code      int     `json:"code"`
			Online    bool    `json:"online"`
			Elapsed   int64   `json:"elapsed_ms"`
		}
		if !smallStrictJSON(c, &v) {
			detail(c, 422, "Invalid bounded project diagnostic")
			return
		}
		stages := map[string]bool{"page_error": true, "rejection": true, "media_error": true, "waiting": true, "stalled": true, "playing": true}
		pages := map[string]bool{"music": true, "video": true, "karaoke": true, "catalog": true, "home": true}
		if !stages[v.Stage] || !pages[v.Page] || v.MediaTime < 0 || v.MediaTime > 86400 || v.Ready < 0 || v.Ready > 4 || v.Network < 0 || v.Network > 3 || v.Code < 0 || v.Code > 4 || v.Elapsed < 0 || v.Elapsed > 7*86400000 {
			detail(c, 422, "Invalid bounded project diagnostic")
			return
		}
		logs.Capture(logarchive.Browser, map[string]any{"request_id": c.GetString("request_id"), "trace_id": c.GetString("trace_id"), "stage": v.Stage, "page": v.Page, "media_time": v.MediaTime, "ready": v.Ready, "network": v.Network, "code": v.Code, "online": v.Online, "elapsed_ms": v.Elapsed})
		c.Status(202)
	})
}
