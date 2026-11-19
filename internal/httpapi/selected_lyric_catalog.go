package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/search"
	"golang.org/x/text/cases"
)

const selectedLyricPageSize = 200

type selectedLyricSide struct {
	scope, root, query, cursor string
	subtree                    []sealedtree.NativeLyricScopeItem
	complete                   bool
}

type selectedLyricPage struct {
	rows      []sealedtree.NativeLyricScopeItem
	dirs      []gin.H
	next      string
	truncated bool
}

// selectedLyricCatalog keeps directory browsing paginated and restores the
// existing name/path aliases in a bounded search of the selected subtree.
func (a *Admin) selectedLyricCatalog(c *gin.Context, track, lyric, tq, lq string) {
	if !a.selectedAdminAllowed(c, false) {
		return
	}
	if !lyricCatalogScope(track, "music") || !lyricCatalogScope(lyric, "lyrics") {
		detail(c, http.StatusBadRequest, "目录无效")
		return
	}
	usage := c.DefaultQuery("lyric_usage", "all")
	if usage != "all" && usage != "used" && usage != "unused" {
		detail(c, http.StatusBadRequest, "歌词使用状态无效")
		return
	}
	trackSide := selectedLyricSide{scope: track, root: "music", query: strings.TrimSpace(tq), cursor: c.Query("track_cursor")}
	lyricSide := selectedLyricSide{scope: lyric, root: "lyrics", query: strings.TrimSpace(lq), cursor: c.Query("lyric_cursor")}
	for _, side := range []*selectedLyricSide{&trackSide, &lyricSide} {
		if side.query == "" {
			continue
		}
		query, err := search.Query(side.query)
		if err != nil {
			detail(c, http.StatusBadRequest, err.Error())
			return
		}
		if side.cursor != "" {
			detail(c, http.StatusBadRequest, "搜索结果无需目录分页游标")
			return
		}
		side.query = query
	}
	ctx, cancel := selectedRuntimeContext(c)
	defer cancel()
	var response gin.H
	err := a.selectedUpload.WithAdminTreeCatalog(ctx, session(c).Hash, func(tree *sealedtree.SQLStore, lease *sealedtree.TreeLease) error {
		var err error
		response, err = readSelectedLyricCatalog(ctx, tree, lease, trackSide, lyricSide, usage)
		return err
	})
	if errors.Is(err, sealedtree.ErrLyricScopeLimit) {
		detail(c, http.StatusUnprocessableEntity, "搜索范围过大，请进入更小的目录后重试")
		return
	}
	if err != nil {
		selectedRuntimeError(c, err)
		return
	}
	c.JSON(http.StatusOK, response)
}

func lyricCatalogScope(name, root string) bool {
	return (name == root || strings.HasPrefix(name, root+"/")) && path.Clean(name) == name && strings.Count(name, "/") <= 2
}

func readSelectedLyricCatalog(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, track, lyric selectedLyricSide, usage string) (gin.H, error) {
	scanCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	budget := sealedtree.MaxLyricScopeEntries
	sides := []*selectedLyricSide{&track, &lyric}
	if track.query == "" && lyric.query != "" {
		sides[0], sides[1] = sides[1], sides[0]
	}
	for _, side := range sides {
		rows, visited, err := tree.ReadNativeLyricScopeWithLease(scanCtx, lease, side.scope, side.root, budget)
		budget -= visited
		if err == nil {
			side.subtree, side.complete = rows, true
			continue
		}
		if !errors.Is(err, sealedtree.ErrLyricScopeLimit) && scanCtx.Err() != context.DeadlineExceeded {
			return nil, err
		}
		if side.query != "" {
			return nil, sealedtree.ErrLyricScopeLimit
		}
	}
	linkedCounts := map[string]int{}
	for _, item := range track.subtree {
		if item.LinkedLyricID != "" {
			linkedCounts[item.LinkedLyricID]++
		}
	}
	canFilter := track.complete && lyric.complete
	t, err := selectedLyricCatalogPage(ctx, tree, lease, track, nil)
	if err != nil {
		return nil, err
	}
	var lyricFilter func(sealedtree.NativeLyricScopeItem) bool
	if canFilter && usage != "all" {
		lyricFilter = func(item sealedtree.NativeLyricScopeItem) bool {
			return (linkedCounts[item.ID] > 0) == (usage == "used")
		}
	}
	l, err := selectedLyricCatalogPage(ctx, tree, lease, lyric, lyricFilter)
	if err != nil {
		return nil, err
	}
	lyricPaths := map[string]string{}
	for _, row := range lyric.subtree {
		lyricPaths[row.ID] = row.Path
	}
	lyricRows := make([]gin.H, 0, len(l.rows))
	for _, row := range l.rows {
		lyricPaths[row.ID] = row.Path
		var count any
		if track.complete {
			count = linkedCounts[row.ID]
		}
		lyricRows = append(lyricRows, gin.H{"path": row.Path, "name": lyricLabel(row.Path), "lyric_id": row.ID, "linked_count": count})
	}
	trackRows, relations := make([]gin.H, 0, len(t.rows)), []gin.H{}
	relationCount := 0
	for _, row := range t.rows {
		item := gin.H{"path": row.Path, "name": lyricLabel(row.Path), "media_id": row.ID, "has_lyrics": false, "lyric_path": nil}
		if row.LinkedLyricID != "" {
			linked := lyricPaths[row.LinkedLyricID]
			if linked == "" {
				target, e := tree.ReadListingObjectWithLease(ctx, lease, row.LinkedLyricID, true)
				if e != nil || target.Entry.Kind != "lyric" || target.Entry.ObjectID != row.LinkedLyricID || !strings.HasPrefix(target.Path, "lyrics/") || target.Path == "lyrics/default.lrc" {
					return nil, sealedtree.ErrInvalid
				}
				linked = target.Path
				lyricPaths[row.LinkedLyricID] = linked
			}
			item["has_lyrics"], item["lyric_path"] = true, linked
			relations = append(relations, gin.H{"track": row.Path, "lyric": linked})
			if strings.HasPrefix(linked, lyric.scope+"/") {
				relationCount++
			}
		}
		trackRows = append(trackRows, item)
	}
	countsScope := "page"
	trackCount, lyricCount := len(trackRows), len(lyricRows)
	if track.complete && lyric.complete {
		countsScope = "subtree"
		trackCount, lyricCount, relationCount = len(track.subtree), len(lyric.subtree), 0
		for _, row := range lyric.subtree {
			relationCount += linkedCounts[row.ID]
		}
	}
	usageScope := ""
	if track.complete {
		usageScope = "track_subtree"
	}
	return gin.H{
		"scopes": gin.H{"track": track.scope, "lyric": lyric.scope},
		"counts": gin.H{"tracks": trackCount, "lyrics": lyricCount, "relations": relationCount}, "counts_scope": countsScope,
		"sealed_scope": "directory", "lyric_usage_scope": usageScope, "lyric_usage_filter": canFilter,
		"truncated": gin.H{"track": t.truncated, "lyric": l.truncated}, "next": gin.H{"track": t.next, "lyric": l.next},
		"track_directories": t.dirs, "lyric_directories": l.dirs, "tracks": trackRows, "lyrics": lyricRows, "relations": relations,
	}, nil
}

func selectedLyricCatalogPage(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, side selectedLyricSide, filter func(sealedtree.NativeLyricScopeItem) bool) (selectedLyricPage, error) {
	out := selectedLyricPage{dirs: []gin.H{}}
	if side.query != "" || filter != nil {
		rows, err := selectLyricSearchRows(ctx, side.subtree, side.query, filter)
		out.truncated = len(rows) > selectedLyricPageSize
		out.rows = rows[:min(len(rows), selectedLyricPageSize)]
		return out, err
	}
	id, err := tree.ResolveDirectoryWithLease(ctx, lease, side.scope, true)
	if errors.Is(err, sql.ErrNoRows) && side.scope == side.root && side.cursor == "" {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	items, next, err := tree.ListCatalogPageWithLease(ctx, lease, id, side.cursor, selectedLyricPageSize, true)
	if err != nil {
		return out, err
	}
	if err = tree.VerifyNativeCatalogLyricFactsWithLease(ctx, lease, items); err != nil {
		return out, err
	}
	directoryCounts := map[string]int{}
	for _, row := range side.subtree {
		relative := strings.TrimPrefix(row.Path, side.scope+"/")
		if child, _, descendant := strings.Cut(relative, "/"); descendant {
			directoryCounts[child]++
		}
	}
	kind := "audio"
	if side.root == "lyrics" {
		kind = "lyric"
	}
	for _, item := range items {
		name := item.Entry.Name
		full := side.scope + "/" + name
		if item.Entry.Kind == "directory" && strings.Count(full, "/") <= 2 {
			var count any
			if side.complete {
				count = directoryCounts[name]
			}
			out.dirs = append(out.dirs, gin.H{"name": name, "path": full, "count": count})
		} else if item.Entry.Kind == kind && side.scope != "music" && full != "lyrics/default.lrc" {
			row := sealedtree.NativeLyricScopeItem{Path: full, ID: item.Entry.ObjectID}
			if item.Facts.Lyric != nil {
				row.LinkedLyricID = item.Facts.Lyric.LyricID
			}
			out.rows = append(out.rows, row)
		}
	}
	out.next, out.truncated = next, next != ""
	return out, nil
}

func selectLyricSearchRows(ctx context.Context, items []sealedtree.NativeLyricScopeItem, query string, filter func(sealedtree.NativeLyricScopeItem) bool) ([]sealedtree.NativeLyricScopeItem, error) {
	var engine *search.Engine
	if query != "" {
		var err error
		if engine, err = search.New(); err != nil {
			return nil, err
		}
	}
	rows := []sealedtree.NativeLyricScopeItem{}
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if filter != nil && !filter(item) {
			continue
		}
		if engine != nil {
			aliases, err := engine.Text(lyricLabel(item.Path), item.Path)
			if err != nil {
				return nil, err
			}
			if !strings.Contains(aliases, query) {
				continue
			}
		}
		rows = append(rows, item)
	}
	fold := cases.Fold()
	sort.Slice(rows, func(i, j int) bool {
		left, right := fold.String(lyricLabel(rows[i].Path)), fold.String(lyricLabel(rows[j].Path))
		if left == right {
			return fold.String(rows[i].Path) < fold.String(rows[j].Path)
		}
		return left < right
	})
	return rows, nil
}

func lyricLabel(name string) string {
	return strings.TrimSuffix(path.Base(name), path.Ext(name))
}
