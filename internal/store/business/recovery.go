package business

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RecoverySamples reads existing identities only; it never registers a missing
// path or repairs metadata. Sampling supplements whole-archive byte verification.
func (r *Repository) RecoverySamples(ctx context.Context, limit int) ([]store.RecoverySample, error) {
	if limit < 1 || limit > 32 {
		limit = 16
	}
	n, e := r.ReadIdentity(ctx)
	if e != nil {
		return nil, e
	}
	query := "SELECT m.media_id,m.media_path,m.object_kind FROM media_objects m WHERE m.object_kind IN ('audio','video','lyric') AND NOT EXISTS (SELECT 1 FROM global_media_objects g WHERE g.media_id=m.media_id AND g.storage_member_id<>?) ORDER BY m.media_id LIMIT ?"
	rows, e := r.db.QueryContext(ctx, query, n.ID, limit)
	if e != nil {
		return nil, e
	}
	var samples []store.RecoverySample
	for rows.Next() {
		var s store.RecoverySample
		s.Root = "media"
		if e = rows.Scan(&s.ID, &s.Path, &s.Kind); e != nil {
			rows.Close()
			return nil, e
		}
		samples = append(samples, s)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for i := range samples {
		o, e := r.ObjectByID(ctx, samples[i].ID)
		if e != nil || o == nil {
			return nil, store.ErrNodeState
		}
		samples[i].MediaObject = *o
	}
	return samples, nil
}
