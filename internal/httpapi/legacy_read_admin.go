package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

// legacyReadAdminCoordinator must create all operation IDs and challenges
// internally and use durable intents; browser inputs select a relationship
// only. No implementation or route is installed by production startup.
type legacyReadAdminCoordinator interface {
	EnrollLegacyReads(context.Context, string) (string, error)
	DrainLegacyReads(context.Context, string) (string, error)
	ObserveLegacyReads(context.Context, string) (string, error)
	ResumeLegacyReads(context.Context, string) (string, error)
}

// RegisterLegacyReadAdmin is explicit and unregistered by default. The route
// installs the same Admin transport, session and CSRF middleware as Admin.
func RegisterLegacyReadAdmin(router *gin.Engine, a *Admin, coordinator *node.LegacyReadCoordinator) error {
	if coordinator == nil {
		return node.ErrCapability
	}
	return registerLegacyReadAdmin(router, a, coordinator)
}

func registerLegacyReadAdmin(router *gin.Engine, a *Admin, coordinator legacyReadAdminCoordinator) error {
	if router == nil || a == nil || a.auth == nil || a.network == nil || coordinator == nil {
		return node.ErrCapability
	}
	group := router.Group("/api/v1/media/admin/legacy-read", a.transport, a.authenticate)
	register := func(name string, operation func(context.Context, string) (string, error)) {
		group.POST("/"+name, func(c *gin.Context) {
			noStore(c)
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
			decoder := json.NewDecoder(c.Request.Body)
			decoder.DisallowUnknownFields()
			var input struct {
				RelationshipID string `json:"relationship_id"`
			}
			if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || !node.ValidIdentifier(input.RelationshipID) {
				detail(c, http.StatusBadRequest, "Invalid request")
				return
			}
			if err := a.auth.Audit(c.Request.Context(), session(c).Hash, "legacy-read-"+name, input.RelationshipID, "attempt", "", 1, a.info(c)); err != nil {
				internalError(c, err)
				return
			}
			state, err := operation(c.Request.Context(), input.RelationshipID)
			valid := name == "enroll" && state == "active" || (name == "drain" || name == "resume") && state == "revoked" || name == "status" && (state == "draining" || state == "revoked")
			if err != nil || !valid {
				detail(c, http.StatusServiceUnavailable, "Legacy read control unavailable")
				return
			}
			// This is a point-in-time observation, not an activation grant;
			// callers must independently revalidate a durable fresh proof.
			c.JSON(http.StatusOK, gin.H{"status": state, "observation": true})
		})
	}
	register("enroll", coordinator.EnrollLegacyReads)
	register("drain", coordinator.DrainLegacyReads)
	register("status", coordinator.ObserveLegacyReads)
	register("resume", coordinator.ResumeLegacyReads)
	return nil
}
