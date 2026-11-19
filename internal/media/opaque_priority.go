package media

import (
	"context"
	"database/sql"
	"errors"
	"path"
	"sort"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/search"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/text/cases"
)

// OpaquePriorities returns the existing Admin priority view under a single
// authenticated tree lease. It bounds traversal and fails instead of silently
// truncating counts or ordering. Placements never appear in the response.
func (s *Service) OpaquePriorities(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, scope, query, kind string, page, pageSize int) (PriorityResult, error) {
	if s == nil || ctx == nil || tree == nil || lease == nil || page < 1 || pageSize < 1 || pageSize > 100 || (kind != "" && kind != "audio" && kind != "video") {
		return PriorityResult{}, ErrPath
	}
	name, err := normalizeAdminPath(scope, true)
	if err != nil || name != "" && strings.Split(name, "/")[0] == "lyrics" {
		return PriorityResult{}, ErrPath
	}
	normalized := ""
	if query != "" {
		normalized, err = search.Query(query)
		if err != nil {
			return PriorityResult{}, err
		}
	}
	if normalized != "" && s.search == nil {
		return PriorityResult{}, ErrUnavailable
	}
	result := PriorityResult{Items: []PriorityItem{}, Directories: []PriorityDirectory{}, Scope: name, Parent: directoryParent(name), Searching: normalized != "", Minimum: store.PriorityMinimum, Maximum: store.PriorityMaximum}
	prefix := ""
	if name != "" {
		prefix = name + "/"
	}
	counts := map[string]int{}
	var used int64
	var walk func(string, string, bool, string) error
	walk = func(dir, id string, inheritedHidden bool, root string) error {
		var cursor string
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			rows, next, err := tree.ListCatalogPageWithLease(ctx, lease, id, cursor, 128, true)
			if err != nil {
				return err
			}
			for _, row := range rows {
				full := dir + "/" + row.Entry.Name
				cost := int64(1024 + 8*len(full))
				if cost > opaqueCatalogMemoryBudget-used {
					return errOpaqueCatalogBudget
				}
				used += cost
				hidden := inheritedHidden || row.Facts.Visibility != nil && row.Facts.Visibility.Hidden == 1
				if row.Entry.Kind == "directory" {
					if len(strings.Split(full, "/")) <= 3 {
						if err := walk(full, row.Entry.ObjectID, hidden, root); err != nil {
							return err
						}
					}
					continue
				}
				expected := "audio"
				if root == "vido" {
					expected = "video"
				}
				if row.Entry.Kind != expected || !validExt(root, full) || len(strings.Split(full, "/")) < 3 {
					continue
				}
				result.CatalogTotal++
				remainder := strings.TrimPrefix(full, prefix)
				direct := !strings.Contains(remainder, "/")
				if !direct {
					counts[prefix+strings.Split(remainder, "/")[0]]++
				}
				title := strings.TrimSuffix(row.Entry.Name, path.Ext(row.Entry.Name))
				if normalized != "" {
					text, e := s.search.Text(title, full)
					if e != nil {
						return e
					}
					if !strings.Contains(text, normalized) {
						continue
					}
				} else if !direct {
					continue
				}
				stats := store.PlaybackStats{}
				if row.Facts.Playback != nil {
					stats.PlayScore = row.Facts.Playback.PlayScore
					stats.Preference = int(row.Facts.Playback.Preference)
					if int64(stats.Preference) != row.Facts.Playback.Preference {
						return ErrUnavailable
					}
				}
				result.Items = append(result.Items, PriorityItem{MediaPath: full, Title: title, Type: expected, Hidden: hidden, MediaID: row.Entry.ObjectID, PlaybackStats: stats})
			}
			if next == "" {
				return nil
			}
			if next == cursor {
				return ErrUnavailable
			}
			cursor = next
		}
	}
	for _, root := range []string{"music", "vido"} {
		if kind == "audio" && root != "music" || kind == "video" && root != "vido" {
			continue
		}
		dir := root
		if name != "" {
			if strings.Split(name, "/")[0] != root {
				continue
			}
			dir = name
		}
		id, e := tree.ResolveDirectoryWithLease(ctx, lease, dir, true)
		if errors.Is(e, sql.ErrNoRows) {
			return PriorityResult{}, ErrCategory
		}
		if e != nil {
			return PriorityResult{}, e
		}
		_, e = tree.ResolveDirectoryWithLease(ctx, lease, dir, false)
		hidden := errors.Is(e, sealedtree.ErrHidden)
		if e != nil && !hidden {
			return PriorityResult{}, e
		}
		if err := walk(dir, id, hidden, root); err != nil {
			return PriorityResult{}, err
		}
	}
	for directory, count := range counts {
		result.Directories = append(result.Directories, PriorityDirectory{Name: path.Base(directory), Path: directory, Count: count})
	}
	fold := cases.Fold()
	sort.Slice(result.Directories, func(i, j int) bool {
		a, b := result.Directories[i], result.Directories[j]
		if fold.String(a.Name) != fold.String(b.Name) {
			return fold.String(a.Name) < fold.String(b.Name)
		}
		fa, fb := fold.String(a.Path), fold.String(b.Path)
		if fa == fb {
			return a.Path < b.Path
		}
		return fa < fb
	})
	sort.Slice(result.Items, func(i, j int) bool {
		a, b := result.Items[i], result.Items[j]
		if a.Preference != b.Preference {
			return a.Preference > b.Preference
		}
		if a.MediaPath != b.MediaPath {
			return a.MediaPath < b.MediaPath
		}
		return a.MediaID < b.MediaID
	})
	total := len(result.Items)
	pages := max(1, (total+pageSize-1)/pageSize)
	page = min(page, pages)
	start := (page - 1) * pageSize
	result.Items = result.Items[start:min(start+pageSize, total)]
	result.Pagination = Pagination{Page: page, Pages: pages, Total: total, PageSize: pageSize}
	return result, nil
}
