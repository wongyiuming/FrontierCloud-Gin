package resourcemigration

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"iter"
)

func (r *Runner) header(ctx context.Context, id string) (store.MigrationWork, error) {
	if repo, ok := r.Repository.(store.MigrationPagingRepository); ok {
		return repo.MigrationHeader(ctx, id)
	}
	return r.Repository.MigrationWork(ctx, id)
}
func (r *Runner) objects(ctx context.Context, id, unit string) iter.Seq2[store.MigrationCheckpoint, error] {
	return func(yield func(store.MigrationCheckpoint, error) bool) {
		if repo, ok := r.Repository.(store.MigrationPagingRepository); ok {
			after := ""
			for {
				page, e := repo.MigrationObjectPage(ctx, id, unit, after)
				if e != nil {
					yield(store.MigrationCheckpoint{}, e)
					return
				}
				for _, cp := range page {
					if cp.Object.ID <= after {
						yield(store.MigrationCheckpoint{}, store.ErrMigrationState)
						return
					}
					if !yield(cp, nil) {
						return
					}
					after = cp.Object.ID
				}
				if len(page) < store.MigrationPageObjects {
					return
				}
			}
		}
		w, e := r.Repository.MigrationWork(ctx, id)
		if e != nil {
			yield(store.MigrationCheckpoint{}, e)
			return
		}
		for _, cp := range w.Objects {
			if unit == "" || cp.UnitID == unit {
				if !yield(cp, nil) {
					return
				}
			}
		}
	}
}
func (r *Runner) units(ctx context.Context, id string) iter.Seq2[store.MigrationUnit, error] {
	return func(yield func(store.MigrationUnit, error) bool) {
		if repo, ok := r.Repository.(store.MigrationPagingRepository); ok {
			after := ""
			for {
				page, e := repo.MigrationUnitPage(ctx, id, after)
				if e != nil {
					yield(store.MigrationUnit{}, e)
					return
				}
				for _, u := range page {
					if u.ID <= after {
						yield(store.MigrationUnit{}, store.ErrMigrationState)
						return
					}
					if !yield(u, nil) {
						return
					}
					after = u.ID
				}
				if len(page) < store.MigrationPageObjects {
					return
				}
			}
		}
		w, e := r.Repository.MigrationWork(ctx, id)
		if e != nil {
			yield(store.MigrationUnit{}, e)
			return
		}
		for _, u := range w.Units {
			if !yield(u, nil) {
				return
			}
		}
	}
}
func (r *Runner) objectWork(ctx context.Context, id, logical string) (w store.MigrationWork, e error) {
	if repo, ok := r.Repository.(store.MigrationPagingRepository); ok {
		w, e = repo.MigrationHeader(ctx, id)
		if e != nil {
			return w, e
		}
		cp, e := repo.MigrationObject(ctx, id, logical)
		if e != nil {
			return w, e
		}
		u, e := repo.MigrationUnit(ctx, id, cp.UnitID)
		if e != nil {
			return w, e
		}
		w.Objects = []store.MigrationCheckpoint{cp}
		w.Units = []store.MigrationUnit{u}
		return w, nil
	}
	return r.Repository.MigrationWork(ctx, id)
}
func (r *Runner) unit(ctx context.Context, id, unit string) (store.MigrationUnit, error) {
	if repo, ok := r.Repository.(store.MigrationPagingRepository); ok {
		return repo.MigrationUnit(ctx, id, unit)
	}
	for u, e := range r.units(ctx, id) {
		if e != nil {
			return u, e
		}
		if u.ID == unit {
			return u, nil
		}
	}
	return store.MigrationUnit{}, store.ErrMigrationState
}
