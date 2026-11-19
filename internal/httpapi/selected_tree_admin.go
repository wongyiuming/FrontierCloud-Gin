package httpapi

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/search"
)

func (a *Admin) selectedAdminTree(c *gin.Context) {
	if !a.selectedAdminAllowed(c, false) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	var result media.Tree
	err := a.selectedUpload.WithAdminTreeCatalog(ctx, session(c).Hash, func(tree *sealedtree.SQLStore, lease *sealedtree.TreeLease) error {
		var err error
		result, err = a.public.media.OpaqueAdminTree(ctx, tree, lease, c.Query("path"))
		return err
	})
	if err != nil {
		mediaAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func (a *Admin) selectedAdminTreeSearch(c *gin.Context, query string) {
	if !a.selectedAdminAllowed(c, false) {
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	var result media.SearchResult
	err := a.selectedUpload.WithAdminTreeCatalog(ctx, session(c).Hash, func(tree *sealedtree.SQLStore, lease *sealedtree.TreeLease) error {
		var err error
		result, err = a.public.media.OpaqueAdminTreeSearch(ctx, tree, lease, c.Query("path"), query)
		return err
	})
	if err != nil {
		if errors.Is(err, search.ErrQuery) {
			detail(c, http.StatusBadRequest, err.Error())
		} else if errors.Is(err, media.ErrCategory) || errors.Is(err, media.ErrPath) {
			detail(c, http.StatusBadRequest, "搜索目录不在受支持的媒体层级内或不存在")
		} else {
			mediaAdminError(c, err)
		}
		return
	}
	c.JSON(http.StatusOK, result)
}
