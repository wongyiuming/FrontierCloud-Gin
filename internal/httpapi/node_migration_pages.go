package httpapi

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"iter"
)

func peerMigrationUnitObjects(ctx context.Context, repo store.MigrationPeerRepository, rel string, lease store.MigrationLease, grant store.MigrationUnitFinishGrant, cancelling bool) iter.Seq2[store.MigrationPeerObject, error] {
	return func(yield func(store.MigrationPeerObject, error) bool) {
		if paged, ok := repo.(store.MigrationPeerPagingRepository); ok {
			after := ""
			var count int64
			for {
				page, e := paged.PeerMigrationUnitWorkPage(ctx, rel, lease, grant, cancelling, after)
				if e != nil {
					yield(store.MigrationPeerObject{}, e)
					return
				}
				for _, o := range page {
					if o.Object.ID <= after {
						yield(store.MigrationPeerObject{}, store.ErrMigrationState)
						return
					}
					if !yield(o, nil) {
						return
					}
					after = o.Object.ID
					count++
				}
				if len(page) < store.MigrationPageObjects {
					if count != grant.Unit.ObjectCount {
						yield(store.MigrationPeerObject{}, store.ErrMigrationState)
					}
					return
				}
			}
		}
		var objects []store.MigrationPeerObject
		var e error
		if cancelling {
			objects, e = repo.PeerMigrationUnitCancelWork(ctx, rel, lease, grant)
		} else {
			objects, e = repo.PeerMigrationUnitFinishWork(ctx, rel, lease, grant)
		}
		if e != nil {
			yield(store.MigrationPeerObject{}, e)
			return
		}
		for _, o := range objects {
			if !yield(o, nil) {
				return
			}
		}
	}
}
