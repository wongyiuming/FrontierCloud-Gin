package media

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/search"
	"golang.org/x/text/cases"
)

// opaqueAdminWalker projects authenticated tree records to the existing Admin
// display shape. It never returns an Owner capability, locator or provider key.
// The caller holds one tree lease across the entire bounded traversal.
type opaqueAdminWalker struct {
	service *Service
	tree    *sealedtree.SQLStore
	lease   *sealedtree.TreeLease
	used    int64
}

func (w *opaqueAdminWalker) directory(ctx context.Context, name string) (string, bool, error) {
	id, err := w.tree.ResolveDirectoryWithLease(ctx, w.lease, name, true)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrCategory
	}
	if err != nil {
		return "", false, err
	}
	_, err = w.tree.ResolveDirectoryWithLease(ctx, w.lease, name, false)
	hidden := errors.Is(err, sealedtree.ErrHidden)
	if err != nil && !hidden {
		return "", false, err
	}
	return id, hidden, nil
}

func (w *opaqueAdminWalker) children(ctx context.Context, directory, id string, inherited bool) ([]TreeItem, error) {
	items := []TreeItem{}
	cursor := ""
	pending := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var rows []sealedtree.CatalogItem
		var next string
		var err error
		if pending {
			rows, next, err = w.tree.ListAdminPendingDeletionsWithLease(ctx, w.lease, id, cursor, 128)
		} else {
			rows, next, err = w.tree.ListCatalogPageWithLease(ctx, w.lease, id, cursor, 128, true)
		}
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			full := row.Entry.Name
			if directory != "" {
				full = directory + "/" + full
			}
			cost := int64(1024 + 8*len(full))
			if cost > opaqueCatalogMemoryBudget-w.used {
				return nil, errOpaqueCatalogBudget
			}
			w.used += cost
			parts := strings.Split(full, "/")
			if len(parts) > 4 || directory == "" && (row.Entry.Kind != "directory" || full != "music" && full != "vido" && full != "lyrics") {
				continue
			}
			directHidden := row.Facts.Visibility != nil && row.Facts.Visibility.Hidden == 1
			item := TreeItem{Name: row.Entry.Name, Path: full, Hidden: inherited || directHidden, HiddenDirect: directHidden}
			if row.Entry.Kind == "directory" {
				if len(parts) > 3 {
					continue
				}
				item.Kind = "directory"
				if directory != "" {
					item.MediaID = row.Entry.ObjectID
				}
				item.Hideable = !pending && (parts[0] == "music" || parts[0] == "vido")
				if pending {
					if row.Facts.DirectoryDeletion == nil {
						return nil, ErrUnavailable
					}
					item.MutationState = "pending_delete"
					item.MutationID = row.Facts.DirectoryDeletion.OperationID
				}
			} else {
				if row.Entry.Kind != "audio" && row.Entry.Kind != "video" && row.Entry.Kind != "lyric" || !validExt(parts[0], full) || full == defaultLyric {
					continue
				}
				item.Kind, item.Media, item.MediaID = "file", parts[0] != "lyrics", row.Entry.ObjectID
				var size int64
				switch {
				case row.Placement != nil && row.S3Placement == nil:
					p := row.Placement
					if p.State != "active" || p.ObjectID != row.Entry.ObjectID {
						return nil, ErrUnavailable
					}
					size, item.ObjectID, item.MemberID, item.Encryption = p.Bytes, p.NativeObjectID, p.OwnerID, p.Encryption
					if w.service.identity != nil && w.service.identity.Role == "Master" && p.OwnerID == w.service.identity.ID {
						item.Transport = "Local"
					}
				case row.S3Placement != nil && row.Placement == nil:
					p := row.S3Placement
					if p.ObjectID != row.Entry.ObjectID {
						return nil, ErrUnavailable
					}
					size, item.ObjectID, item.MemberID, item.Encryption, item.Transport = p.Proof.Bytes, p.Proof.ObjectID, p.MemberID, p.Encryption, "S3"
				default:
					return nil, ErrUnavailable
				}
				item.Size, item.SizeBytes = &size, &size
				if pending {
					item.MutationState = "pending_delete"
					if row.Facts.S3Deletion != nil {
						item.MutationID = row.Facts.S3Deletion.OperationID
					} else if row.Facts.Revocation != nil {
						item.MutationID = row.Facts.Revocation.OperationID
					} else {
						return nil, ErrUnavailable
					}
				}
			}
			items = append(items, item)
		}
		if next == "" {
			if pending {
				break
			}
			pending, cursor = true, ""
			continue
		}
		if next == cursor {
			return nil, ErrUnavailable
		}
		cursor = next
	}
	fold := cases.Fold()
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Kind != b.Kind {
			return a.Kind == "directory"
		}
		fa, fb := fold.String(a.Name), fold.String(b.Name)
		if fa == fb {
			return a.Name < b.Name
		}
		return fa < fb
	})
	return items, nil
}

// OpaqueAdminTree returns one complete bounded directory view. A directory
// that exceeds the memory budget fails closed instead of silently truncating.
func (s *Service) OpaqueAdminTree(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, scope string) (Tree, error) {
	if s == nil || ctx == nil || tree == nil || lease == nil {
		return Tree{}, ErrUnavailable
	}
	name, err := normalizeAdminPath(scope, true)
	if err != nil {
		return Tree{}, err
	}
	w := &opaqueAdminWalker{service: s, tree: tree, lease: lease}
	id, hidden, err := w.directory(ctx, name)
	if err != nil {
		return Tree{}, err
	}
	items, err := w.children(ctx, name, id, hidden)
	if err != nil {
		return Tree{}, err
	}
	return Tree{Path: name, Items: items}, nil
}

// OpaqueAdminTreeSearch preserves the existing 200-match limit while bounding
// traversal memory. Direct and inherited hidden state remain separate.
func (s *Service) OpaqueAdminTreeSearch(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, scope, query string) (SearchResult, error) {
	if s == nil || ctx == nil || tree == nil || lease == nil || s.search == nil {
		return SearchResult{}, ErrUnavailable
	}
	normalized, err := search.Query(query)
	if err != nil {
		return SearchResult{}, err
	}
	name, err := normalizeAdminPath(scope, false)
	if err != nil {
		return SearchResult{}, err
	}
	w := &opaqueAdminWalker{service: s, tree: tree, lease: lease}
	id, hidden, err := w.directory(ctx, name)
	if err != nil {
		return SearchResult{}, err
	}
	result := SearchResult{Path: name, Query: query, Items: []TreeItem{}}
	var walk func(string, string, bool) error
	walk = func(directory, id string, inherited bool) error {
		items, err := w.children(ctx, directory, id, inherited)
		if err != nil {
			return err
		}
		for _, item := range items {
			if item.Kind == "directory" {
				if item.MutationState == "" && len(strings.Split(item.Path, "/")) < 4 {
					child, err := w.tree.ResolveDirectoryWithLease(ctx, w.lease, item.Path, true)
					if err != nil {
						return err
					}
					if err = walk(item.Path, child, item.Hidden); err != nil || result.Truncated {
						return err
					}
				}
				continue
			}
			if item.Media && len(strings.Split(item.Path, "/")) < 3 {
				continue
			}
			text, err := s.search.Text(item.Name, item.Path)
			if err != nil {
				return err
			}
			if strings.Contains(text, normalized) {
				if len(result.Items) == 200 {
					result.Truncated = true
					return nil
				}
				result.Items = append(result.Items, item)
			}
		}
		return nil
	}
	if err := walk(name, id, hidden); err != nil {
		return SearchResult{}, err
	}
	return result, nil
}
