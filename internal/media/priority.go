package media

import (
	"context"
	"os"
	"path"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (s *Service) priorityScope(ctx context.Context, name, kind string) (store.PriorityScope, error) {
	normalized, err := normalizeAdminPath(name, false)
	if err != nil || normalized != name || strings.HasPrefix(name, "lyrics") || (kind != "media" && kind != "directory") {
		return store.PriorityScope{}, ErrPath
	}
	scope := store.PriorityScope{Path: name, Kind: kind}
	role, err := s.role(ctx)
	if err != nil {
		return scope, err
	}
	if role == "Follower" {
		return scope, store.ErrNodeState
	}
	if role == "Master" {
		return scope, nil
	}
	entries, err := s.readDir(name)
	if err != nil {
		return scope, err
	}
	for _, entry := range entries {
		p := path.Join(name, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if kind == "directory" {
			if !entry.IsDir() || strings.Count(p, "/") > 2 {
				continue
			}
			scope.Objects = append(scope.Objects, store.MediaObject{Path: p, Kind: "directory"})
		} else if !entry.IsDir() && managedObject(p, false) {
			o, err := s.ValidateTrack(p)
			if err != nil {
				return scope, err
			}
			scope.Objects = append(scope.Objects, o)
		}
	}
	return scope, nil
}

func (s *Service) PriorityOrder(ctx context.Context, name, kind string) (store.PriorityOrder, error) {
	release, err := s.acquire(ctx, false)
	if err != nil {
		return store.PriorityOrder{}, err
	}
	defer release()
	if err := s.ready(); err != nil {
		return store.PriorityOrder{}, err
	}
	scope, err := s.priorityScope(ctx, name, kind)
	if err != nil {
		return store.PriorityOrder{}, err
	}
	return s.repository.PriorityOrder(ctx, scope)
}

func (s *Service) MovePriority(ctx context.Context, name, kind string, move store.PriorityMove, audit store.AdminAudit) (store.PriorityOrder, error) {
	release, err := s.acquire(ctx, false)
	if err != nil {
		return store.PriorityOrder{}, err
	}
	defer release()
	if err := s.ready(); err != nil {
		return store.PriorityOrder{}, err
	}
	scope, err := s.priorityScope(ctx, name, kind)
	if err != nil {
		return store.PriorityOrder{}, err
	}
	return s.repository.MovePriority(ctx, scope, move, audit)
}
