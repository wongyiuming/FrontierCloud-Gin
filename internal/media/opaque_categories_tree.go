package media

import (
	"context"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/text/cases"
)

type opaqueCategoryWork struct {
	parent   string
	category int
}
type opaqueCategoryCandidate struct {
	value      Category
	preference int
	found      bool
}

// PrepareOpaqueTreeCategories privately traverses authenticated tree pages and
// records every visited scope. It is unregistered until all tree mutations,
// recovery, S3 placements and the final admission fence share this contract.
// It never exposes a partial result on an error or resource-budget breach.
func (s *Service) PrepareOpaqueTreeCategories(ctx context.Context, tree *sealedtree.SQLStore, kind string, includeHidden bool, resolve CatalogOwnerResolver) ([]Category, *PreparedCatalogFence, error) {
	return s.prepareOpaqueTreeCategoriesAt(ctx, tree, kind, mediaRoot(kind), includeHidden, resolve)
}

// PrepareOpaqueTreeSubcategories preserves the old top-level-only nesting
// rule. It is an isolated pre-admission helper, not a visibility grant.
func (s *Service) PrepareOpaqueTreeSubcategories(ctx context.Context, tree *sealedtree.SQLStore, kind, parent string, includeHidden bool, resolve CatalogOwnerResolver) ([]Category, *PreparedCatalogFence, error) {
	if !categoryShape(parent, kind) || len(strings.Split(parent, "/")) != 2 {
		return nil, nil, ErrUnavailable
	}
	return s.prepareOpaqueTreeCategoriesAt(ctx, tree, kind, parent, includeHidden, resolve)
}

func (s *Service) prepareOpaqueTreeCategoriesAt(ctx context.Context, tree *sealedtree.SQLStore, kind, parentPath string, includeHidden bool, resolve CatalogOwnerResolver) ([]Category, *PreparedCatalogFence, error) {
	if s == nil || ctx == nil || tree == nil || resolve == nil || kind != "music" && kind != "video" {
		return nil, nil, ErrUnavailable
	}
	_, peer := network.AuthenticatedIngressFromContext(ctx)
	_, local := network.LocalCatalogPreflightFromContext(ctx)
	if !peer && !local {
		return nil, nil, ErrUnavailable
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Minute {
		return nil, nil, ErrUnavailable
	}
	select {
	case opaqueCatalogSlot <- struct{}{}:
		defer func() { <-opaqueCatalogSlot }()
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	var root string
	if parentPath == mediaRoot(kind) {
		root, err = tree.ResolveDirectoryWithLease(ctx, lease, parentPath, includeHidden)
	} else {
		root, includeHidden, err = resolveKnownCatalogDirectory(ctx, tree, lease, parentPath, includeHidden)
	}
	lease.Release()
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	var scopes []sealedtree.CatalogScopeCheck
	var candidates []opaqueCategoryCandidate
	var work []opaqueCategoryWork
	var used int64
	owners := map[string]CatalogOwnerSnapshot{}
	guard := &catalogResourceGuard{}
	release := guard.release
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	reserve := func(n int64) error {
		if n < 0 || n > opaqueCatalogMemoryBudget-used {
			return errOpaqueCatalogBudget
		}
		used += n
		return nil
	}
	scan := func(parent string, visit func(sealedtree.CatalogItem) (bool, error)) error {
		cursor := ""
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			lease, err := tree.AcquireReadFence(ctx)
			if err != nil {
				return ErrUnavailable
			}
			if cursor == "" {
				proof, e := tree.CaptureCatalogScopeWithLease(ctx, lease, parent, includeHidden)
				if e != nil {
					lease.Release()
					return ErrUnavailable
				}
				if e = reserve(1024); e != nil {
					lease.Release()
					return e
				}
				scopes = append(scopes, sealedtree.CatalogScopeCheck{ParentID: parent, IncludeHidden: includeHidden, Proof: proof})
			}
			page, next, e := tree.ListCatalogPageWithLease(ctx, lease, parent, cursor, opaqueCatalogPageSize, includeHidden)
			lease.Release()
			if e != nil {
				return ErrUnavailable
			}
			for _, item := range page {
				stop, e := visit(item)
				if e != nil {
					return e
				}
				if stop {
					return nil
				}
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
	if err = scan(root, func(item sealedtree.CatalogItem) (bool, error) {
		if item.Entry.Kind != "directory" {
			return false, nil
		}
		name := item.Entry.Name
		full := path.Join(parentPath, name)
		if !categoryShape(full, kind) {
			return false, ErrUnavailable
		}
		pref := 0
		if item.Facts.Playback != nil {
			pref = int(item.Facts.Playback.Preference)
			if int64(pref) != item.Facts.Playback.Preference {
				return false, ErrUnavailable
			}
		}
		if e := reserve(int64(2048 + 8*len(full))); e != nil {
			return false, e
		}
		candidates = append(candidates, opaqueCategoryCandidate{value: Category{Name: name, URL: categoryURL(kind, full, includeHidden)}, preference: pref})
		work = append(work, opaqueCategoryWork{parent: item.Entry.ObjectID, category: len(candidates) - 1})
		return false, nil
	}); err != nil {
		return nil, nil, err
	}
	for pos := 0; pos < len(work); pos++ {
		item := work[pos]
		if candidates[item.category].found {
			continue
		}
		if err = scan(item.parent, func(child sealedtree.CatalogItem) (bool, error) {
			if child.Entry.Kind == "directory" {
				if e := reserve(1024); e != nil {
					return false, e
				}
				work = append(work, opaqueCategoryWork{parent: child.Entry.ObjectID, category: item.category})
				return false, nil
			}
			if (child.Placement == nil) == (child.S3Placement == nil) || child.Placement != nil && child.Placement.State != "active" || child.Entry.Kind != "audio" && child.Entry.Kind != "video" {
				return false, ErrUnavailable
			}
			ownerID := ""
			if child.Placement != nil {
				ownerID = child.Placement.OwnerID
			} else {
				ownerID = child.S3Placement.MemberID
			}
			owner, ok := owners[ownerID]
			if !ok {
				var e error
				owner, e = resolve(ctx, ownerID)
				if e != nil || owner.Acquire == nil {
					return false, ErrUnavailable
				}
				owners[ownerID] = owner
			}
			if child.S3Placement != nil && (owner.Transport != "S3" || owner.CheckS3 == nil || owner.CheckS3(child.S3Placement) != nil) || child.Placement != nil && owner.Transport != "Local" && owner.Transport != "Direct" && owner.Transport != "Relay" {
				return false, ErrUnavailable
			}
			candidates[item.category].found = true
			return true, nil
		}); err != nil {
			return nil, nil, err
		}
	}
	selected := make([]opaqueCategoryCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.found {
			selected = append(selected, candidate)
		}
	}
	fold := cases.Fold()
	sort.Slice(selected, func(i, j int) bool {
		a, b := selected[i], selected[j]
		if a.preference != b.preference {
			return a.preference > b.preference
		}
		fa, fb := fold.String(a.value.Name), fold.String(b.value.Name)
		if fa == fb {
			return a.value.Name < b.value.Name
		}
		return fa < fb
	})
	result := make([]Category, 0, len(selected))
	for _, candidate := range selected {
		result = append(result, candidate.value)
	}
	ownerIDs := make([]string, 0, len(owners))
	for id := range owners {
		ownerIDs = append(ownerIDs, id)
	}
	sort.Strings(ownerIDs)
	var acquireOnce sync.Once
	var acquireErr error
	check := func(c context.Context, prerequisite store.IngressPrerequisite) error {
		if guard.begin(prerequisite) != nil {
			return ErrUnavailable
		}
		checker, ok := prerequisite.(catalogScopeChecker)
		if !ok {
			return ErrUnavailable
		}
		if checker.CheckCatalogScopes(c, tree, scopes) != nil {
			return ErrUnavailable
		}
		acquireOnce.Do(func() {
			for _, id := range ownerIDs {
				resource, e := owners[id].Acquire(c, prerequisite)
				if e != nil || !validCatalogResourceLease(resource) {
					if validCatalogResourceLease(resource) {
						resource.Release()
					}
					acquireErr = ErrUnavailable
					return
				}
				if !guard.add(resource) {
					resource.Release()
					acquireErr = ErrUnavailable
					return
				}
			}
		})
		if acquireErr != nil {
			return acquireErr
		}
		for _, resource := range guard.resources() {
			if resource.Check(c) != nil {
				return ErrUnavailable
			}
		}
		return c.Err()
	}
	transferred = true
	return result, &PreparedCatalogFence{Check: check, Release: release}, nil
}
