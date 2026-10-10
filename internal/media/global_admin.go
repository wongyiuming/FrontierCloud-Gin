package media

import (
	"context"
	"path"
	"sort"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/text/cases"
)

func (s *Service) globalTreeItem(ctx context.Context, row store.GlobalMedia, h map[string]bool) (TreeItem, error) {
	size := row.Bytes
	item := TreeItem{Name: path.Base(row.Path), Path: row.Path, Kind: "file", Size: &size, Hidden: hidden(row.Path, h), HiddenDirect: h[row.Path], Media: true, MediaID: row.ID, MemberID: row.MemberID, Transport: row.Transport, NodeHealth: row.Health}
	if _, ok := s.repository.(store.EncryptionRepository); ok {
		var err error
		item.Encryption, err = s.Encryption(ctx, row.ID)
		if err != nil {
			return TreeItem{}, err
		}
	}
	return item, nil
}
func (s *Service) globalScan(ctx context.Context, scope string, h map[string]bool) ([]TreeItem, error) {
	rows, err := s.pool.ManagementResources(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	items := make([]TreeItem, 0, len(rows))
	byID := map[string]int{}
	for _, row := range rows {
		item, err := s.globalTreeItem(ctx, row, h)
		if err != nil {
			return nil, err
		}
		if row.State == "renaming" {
			item.MutationState = "rename_pending"
		}
		byID[row.ID] = len(items)
		items = append(items, item)
	}
	// A distributed move may remain pending when an owner is unreachable. Keep
	// its durable manifest visible to administrators, never to public playback.
	pending, err := s.pool.PendingGlobalRenames(ctx, 100)
	if err != nil {
		return nil, err
	}
	for _, op := range pending {
		if op.State != "rename_pending" {
			continue
		}
		for _, row := range op.Media {
			if scope != "" && row.Path != scope && !strings.HasPrefix(row.Path, scope+"/") {
				continue
			}
			item, err := s.globalTreeItem(ctx, row, h)
			if err != nil {
				return nil, err
			}
			item.MutationState, item.MutationID, item.RenameTarget = op.State, op.ID, op.New
			if index, ok := byID[row.ID]; ok {
				items[index] = item
			}
		}
	}
	return items, nil
}
func (s *Service) globalTree(ctx context.Context, scope string) (Tree, error) {
	h, err := s.repository.HiddenPaths(ctx)
	if err != nil {
		return Tree{}, err
	}
	files, err := s.globalScan(ctx, scope, h)
	if err != nil {
		return Tree{}, err
	}
	found := map[string]TreeItem{}
	prefix := scope + "/"
	for _, file := range files {
		if !strings.HasPrefix(file.Path, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(file.Path, prefix)
		if strings.Contains(remainder, "/") {
			name := strings.Split(remainder, "/")[0]
			p := prefix + name
			found[p] = TreeItem{Name: name, Path: p, Kind: "directory", Hidden: hidden(p, h), HiddenDirect: h[p], Hideable: true}
		} else {
			found[file.Path] = file
		}
	}
	// Mark mixed directories too; unrelated active children must not erase the
	// operation label when map aggregation visits them later.
	for _, file := range files {
		if file.MutationState == "" || !strings.HasPrefix(file.Path, prefix) {
			continue
		}
		name := strings.Split(strings.TrimPrefix(file.Path, prefix), "/")[0]
		p := prefix + name
		item := found[p]
		item.MutationState, item.MutationID, item.RenameTarget = file.MutationState, file.MutationID, file.RenameTarget
		item.Hideable = false
		found[p] = item
	}
	result := Tree{Path: scope, Items: []TreeItem{}}
	for _, item := range found {
		result.Items = append(result.Items, item)
	}
	fold := cases.Fold()
	sort.Slice(result.Items, func(i, j int) bool {
		a, b := result.Items[i], result.Items[j]
		if a.Kind != b.Kind {
			return a.Kind == "directory"
		}
		fa, fb := fold.String(a.Name), fold.String(b.Name)
		if fa == fb {
			return a.Name < b.Name
		}
		return fa < fb
	})
	return result, nil
}
