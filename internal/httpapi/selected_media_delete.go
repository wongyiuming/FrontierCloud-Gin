package httpapi

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type selectedMediaDeleteFunc func(context.Context, string, []store.SelectedMediaDeleteTarget, store.AdminAudit) (store.SelectedMediaDeleteResult, error)

var selectedMediaDeleteResourceID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var selectedMediaDeleteOperationID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ConfigureSelectedMediaDelete is startup-only. The coordinator must bind new
// work to the exact resource under the mutation fence and resume by operation.
func (a *Admin) ConfigureSelectedMediaDelete(run selectedMediaDeleteFunc) error {
	if a == nil || a.public == nil || a.public.opaqueTree == nil || a.selectedUpload == nil ||
		!a.selectedUpload.Matches(a.public.opaqueTree, a.public.crypto, a.settings.AdminOrigin) || run == nil || a.selectedMediaDelete != nil {
		return store.ErrNodeState
	}
	a.selectedMediaDelete = run
	return nil
}

func selectedMediaDeleteTargets(c *gin.Context, limit int) ([]store.SelectedMediaDeleteTarget, bool) {
	var body struct {
		Targets []store.SelectedMediaDeleteTarget `json:"targets"`
	}
	if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery ||
		!strictJSON(c, &body, 512*1024) || len(body.Targets) == 0 || len(body.Targets) > limit {
		return nil, false
	}
	paths, ids := map[string]bool{}, map[string]bool{}
	for _, target := range body.Targets {
		validPath := media.ValidAdminDeleteFilePath(target.Path)
		if target.Directory {
			validPath = media.ValidAdminDeleteDirectoryPath(target.Path)
		}
		if !utf8.ValidString(target.Path) || utf8.RuneCountInString(target.Path) > 1024 || !validPath ||
			!selectedMediaDeleteResourceID.MatchString(target.ResourceID) ||
			target.OperationID != "" && !selectedMediaDeleteOperationID.MatchString(target.OperationID) || paths[target.Path] || ids[target.ResourceID] {
			return nil, false
		}
		paths[target.Path], ids[target.ResourceID] = true, true
	}
	return body.Targets, true
}

func selectedMediaDeleteStatus(targets []store.SelectedMediaDeleteTarget, result store.SelectedMediaDeleteResult) (int, bool) {
	if len(result.Items) != len(targets) {
		return 0, false
	}
	byID := make(map[string]store.SelectedMediaDeleteTarget, len(targets))
	for _, target := range targets {
		byID[target.ResourceID] = target
	}
	status := http.StatusOK
	for _, item := range result.Items {
		target, exists := byID[item.ResourceID]
		if !exists || item.Path != target.Path || item.Directory != target.Directory || !selectedMediaDeleteOperationID.MatchString(item.OperationID) ||
			target.OperationID != "" && item.OperationID != target.OperationID {
			return 0, false
		}
		delete(byID, item.ResourceID)
		switch item.State {
		case store.SelectedMediaDeletePending:
			status = http.StatusAccepted
		case store.SelectedMediaDeleteDeleted:
		default:
			return 0, false
		}
	}
	return status, true
}

func (a *Admin) deleteSelectedMedia(c *gin.Context) {
	if !a.selectedAdminAllowed(c, true) {
		return
	}
	targets, ok := selectedMediaDeleteTargets(c, a.settings.AdminMaxBatchFiles)
	if !ok {
		detail(c, http.StatusBadRequest, "请选择受管文件或目录并提供资源标识")
		return
	}
	if a.selectedMediaDelete == nil {
		detail(c, http.StatusServiceUnavailable, "加密资源删除暂不可用")
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	result, err := a.selectedMediaDelete(ctx, session(c).Hash, targets, a.mutationAudit(c, "sealed-media-delete", nil))
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), errors.Is(err, media.ErrUnavailable):
			detail(c, http.StatusServiceUnavailable, "尚未确认删除结果，请重试同一操作")
		case errors.Is(err, sealedtree.ErrInvalid):
			detail(c, http.StatusBadRequest, "删除目标不是受管文件或目录")
		case errors.Is(err, sealedtree.ErrDirectoryDeleteLimit):
			detail(c, http.StatusUnprocessableEntity, "目录范围过大，每次最多删除 200 个文件，请分批处理")
		case errors.Is(err, sealedtree.ErrDirectoryDeleteUploadPending):
			detail(c, http.StatusConflict, "目录中有待完成的上传，请完成或取消上传后重试")
		case errors.Is(err, sealedtree.ErrMasterLocalLyricDeleteCatalogLimit):
			detail(c, http.StatusConflict, "媒体库超出歌词关联核查上限，删除未开始")
		case errors.Is(err, sealedtree.ErrMasterLocalLyricDeleteLimit):
			detail(c, http.StatusConflict, "歌词关联超出单次处理上限，请缩小选择范围或先解除部分关联")
		case errors.Is(err, store.ErrNodeState), errors.Is(err, sealedtree.ErrConflict), errors.Is(err, sealedtree.ErrRevocationPending), errors.Is(err, sealedtree.ErrFenceChanged):
			detail(c, http.StatusConflict, "资源或删除操作已变化，请刷新后核对")
		default:
			internalError(c, errors.New("selected media deletion failed"))
		}
		return
	}
	status, ok := selectedMediaDeleteStatus(targets, result)
	if !ok {
		internalError(c, errors.New("selected media deletion returned invalid state"))
		return
	}
	c.JSON(status, result)
}
