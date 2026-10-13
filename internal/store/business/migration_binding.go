package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"strings"
)

const peerBindingLimit = 16 << 10

func (r *Repository) peerObjectBinding(ctx context.Context, q queryer, task, id string) (o store.MigrationObject, e error) {
	var raw, expected string
	if e = q.QueryRowContext(ctx, "SELECT binding_json,binding_sha256 FROM migration_peer_bindings WHERE task_id=? AND logical_id=?"+r.lock(), task, id).Scan(&raw, &expected); e != nil {
		return o, e
	}
	if len(raw) > peerBindingLimit {
		return o, store.ErrMigrationState
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if e = d.Decode(&o); e != nil {
		return o, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return o, store.ErrMigrationState
	}
	actual, e := store.MigrationDigest(o)
	if e != nil || actual != expected || o.ID != id {
		return o, store.ErrMigrationState
	}
	return o, nil
}
func (r *Repository) persistPeerObjectBinding(ctx context.Context, q queryer, task string, o store.MigrationObject) error {
	raw, e := json.Marshal(o)
	if e != nil {
		return e
	}
	if len(raw) > peerBindingLimit {
		return store.ErrMigrationState
	}
	hash, e := store.MigrationDigest(o)
	if e != nil {
		return e
	}
	old, e := r.peerObjectBinding(ctx, q, task, o.ID)
	if e == nil {
		oldHash, e := store.MigrationDigest(old)
		if e != nil || oldHash != hash {
			return store.ErrMigrationState
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	_, e = q.ExecContext(ctx, "INSERT INTO migration_peer_bindings(task_id,logical_id,binding_sha256,binding_json) VALUES (?,?,?,?)", task, o.ID, hash, string(raw))
	return e
}
