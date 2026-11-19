package httpapi

import (
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// selectedPriorityCatalog returns authenticated Master-only display fields;
// no placement or capability crosses the Admin response.
func (a *Admin) selectedPriorityCatalog(c *gin.Context, scope, query, kind string, page, pageSize int) {
	if !a.selectedAdminAllowed(c, false) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	var result media.PriorityResult
	err := a.selectedUpload.WithAdminTreeCatalog(ctx, session(c).Hash, func(tree *sealedtree.SQLStore, lease *sealedtree.TreeLease) error {
		var err error
		result, err = a.public.media.OpaquePriorities(ctx, tree, lease, scope, query, kind, page, pageSize)
		return err
	})
	if err != nil {
		mediaAdminError(c, err)
		return
	}
	c.JSON(200, result)
}
