package httpapi

import (
	"database/sql"
	"errors"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (a *Admin) selectedDirectoryVisibility(c *gin.Context, paths []string, hidden bool, audit store.AdminAudit) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	changed, err := a.selectedUpload.SetDirectoryVisibility(ctx, session(c).Hash, paths, hidden, audit)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			err = os.ErrNotExist
		case errors.Is(err, sealedtree.ErrInvalid):
			err = media.ErrPath
		case errors.Is(err, sealedtree.ErrConflict), errors.Is(err, sealedtree.ErrRevocationPending):
			err = store.ErrNodeState
		}
		mediaAdminError(c, err)
		return
	}
	result := gin.H{"status": "ok", "hidden": hidden, "changed": changed}
	if hidden {
		result["existing_grants"] = "expire_normally"
	}
	c.JSON(http.StatusOK, result)
}

// selectedHiddenDirectory only creates a directly hidden new-tree directory.
// It never turns an existing visible directory into a hidden one.
func (a *Admin) selectedHiddenDirectory(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if !decodeAdmin(c, &body) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	if err := a.selectedUpload.PrepareHiddenDirectory(ctx, session(c).Hash, body.Path); err != nil {
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
