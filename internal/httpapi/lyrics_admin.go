package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (a *Admin) lyricCatalog(c *gin.Context) {
	c.Header("Cache-Control", "private, no-store")
	track, lyric := c.DefaultQuery("track_path", "music"), c.DefaultQuery("lyric_path", "lyrics")
	tq, lq := c.Query("track_q"), c.Query("lyric_q")
	for name, value := range map[string]string{"track_path": track, "lyric_path": lyric, "track_q": tq, "lyric_q": lq} {
		maximum := 1024
		if name == "track_q" || name == "lyric_q" {
			maximum = 100
		}
		if utf8.RuneCountInString(value) > maximum {
			invalid(c, "query", name)
			return
		}
	}
	if a.public.opaqueTree != nil {
		a.selectedLyricCatalog(c, track, lyric, tq, lq)
		return
	}
	result, err := a.public.media.LyricCatalog(c.Request.Context(), track, lyric, tq, lq)
	if err != nil {
		mediaAdminError(c, err)
		return
	}
	c.JSON(200, result)
}
func (a *Admin) lyricRelations(c *gin.Context) {
	var body struct {
		Kind     string   `json:"origin_kind"`
		Path     string   `json:"origin_path"`
		Linked   []string `json:"linked_paths"`
		Unlinked []string `json:"unlinked_paths"`
	}
	if !decodeAdmin(c, &body) {
		return
	}
	if body.Linked == nil || len(body.Linked) > a.settings.AdminMaxBatchFiles {
		detail(c, 400, "关联目标无效")
		return
	}
	if a.public.opaqueTree != nil {
		if !a.selectedAdminAllowed(c, true) {
			return
		}
		if body.Kind == "lyric" {
			a.patchSelectedLyricTracks(c, body.Path, body.Linked, body.Unlinked)
			return
		}
		if body.Kind != "track" || len(body.Linked) > 1 || len(body.Unlinked) != 0 {
			detail(c, 400, "请选择单个音轨及最多一首歌词")
			return
		}
		lyric := ""
		if len(body.Linked) == 1 {
			lyric = body.Linked[0]
		}
		ctx, cancel := selectedRuntimeContext(c)
		defer cancel()
		if err := a.selectedUpload.SetTrackLyric(ctx, session(c).Hash, body.Path, lyric, a.mutationAudit(c, "lyric_relations", body.Linked)); err != nil {
			selectedRuntimeError(c, err)
			return
		}
		c.JSON(200, gin.H{"status": "ok", "relations": len(body.Linked)})
		return
	}
	if body.Unlinked != nil {
		detail(c, http.StatusBadRequest, "当前模式不支持按选择增删歌词关联")
		return
	}
	count, err := a.public.media.ReplaceLyrics(c.Request.Context(), body.Kind, body.Path, body.Linked, a.mutationAudit(c, "lyric_relations", body.Linked))
	if err != nil {
		mediaAdminError(c, err)
		return
	}
	c.JSON(200, gin.H{"status": "ok", "relations": count})
}

func (a *Admin) patchSelectedLyricTracks(c *gin.Context, lyric string, linked, unlinked []string) {
	count := len(linked) + len(unlinked)
	if count == 0 || count > min(a.settings.AdminMaxBatchFiles, sealedtree.MaxNativeLyricPatchTracks) {
		detail(c, http.StatusBadRequest, "关联目标无效或超过批量上限")
		return
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	if err := a.selectedUpload.PatchLyricTracks(ctx, session(c).Hash, lyric, linked, unlinked, a.mutationAudit(c, "lyric_relations", nil)); err != nil {
		if errors.Is(err, sealedtree.ErrInvalid) {
			detail(c, http.StatusBadRequest, "歌词或曲目无效，请检查选择")
		} else {
			detail(c, http.StatusConflict, "歌词关联无法保存，请刷新后重试")
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "relations": len(linked), "unlinked": len(unlinked)})
}

func (a *Admin) lyricAuto(c *gin.Context) {
	var body struct {
		Manual     json.RawMessage `json:"manual"`
		TrackScope string          `json:"track_path"`
		LyricScope string          `json:"lyric_path"`
	}
	if !decodeAdmin(c, &body) {
		return
	}
	if string(body.Manual) != "true" {
		detail(c, 400, "一键歌词关联只能由管理员手动确认触发")
		return
	}
	audit := a.mutationAudit(c, "lyric_auto_relate", nil)
	var result store.AutoLyricResult
	if a.public.opaqueTree != nil {
		if !a.selectedAdminAllowed(c, true) {
			return
		}
		if body.TrackScope == "" {
			body.TrackScope = "music"
		}
		if body.LyricScope == "" {
			body.LyricScope = "lyrics"
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		var err error
		result, err = a.selectedUpload.AutoLyricTracks(ctx, session(c).Hash, body.TrackScope, body.LyricScope, audit)
		if err != nil {
			switch {
			case errors.Is(err, sealedtree.ErrNativeLyricAutoScopeLimit):
				detail(c, http.StatusUnprocessableEntity, "关联范围超过单次上限，请进入更小的曲目或歌词目录后重试")
			case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
				detail(c, http.StatusConflict, "关联处理超时，请刷新后选择更小的目录重试")
			case errors.Is(err, sealedtree.ErrInvalid):
				detail(c, http.StatusBadRequest, "请选择有效的曲目和歌词目录")
			default:
				detail(c, http.StatusConflict, "暂时无法完成歌词关联，请刷新后重试")
			}
			return
		}
	} else {
		if body.TrackScope != "" || body.LyricScope != "" {
			detail(c, http.StatusBadRequest, "当前模式不支持按目录自动关联")
			return
		}
		var err error
		result, err = a.public.media.AutoLyrics(c.Request.Context(), audit)
		if err != nil {
			mediaAdminError(c, err)
			return
		}
	}
	c.JSON(200, gin.H{"status": "ok", "linked": result.Linked, "preserved": result.Preserved, "ambiguous": result.Ambiguous, "unmatched": result.Unmatched})
}
