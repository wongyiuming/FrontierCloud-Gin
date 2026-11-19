package business

import (
	"context"
	"database/sql"
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// CheckLegacyPhysicalWritesAllowed is a read-only, fail-closed observation.
// A tree root, missing table or unreadable database prohibits legacy physical
// writes. The caller must separately hold the actual runtime/maintenance fence
// until its decision is no longer actionable; a query alone cannot serialize
// against a concurrent tree initialization or protect other hosts/raw SQL.
func (r *Repository) CheckLegacyPhysicalWritesAllowed(ctx context.Context) error {
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	if err := legacyTreeAbsent(ctx, r.db); err != nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	return nil
}

// legacyCheckedQuery is private to one active write transaction. Nested
// helpers can reuse its check without rescanning for every item in a batch.
type legacyCheckedQuery struct{ queryer }

func legacyTreeAbsent(ctx context.Context, q queryer) error {
	if _, ok := q.(*legacyCheckedQuery); ok {
		return nil
	}
	if tx, ok := q.(*catalogWrite); ok && tx.mysql {
		// A locking read observes the current committed row without opening a
		// stale REPEATABLE READ snapshot before subsequent row locks. InnoDB's
		// At InnoDB REPEATABLE READ, the empty-index gap lock also prevents
		// cooperative insertion until this transaction completes. r.write uses
		// the server default isolation, so READ COMMITTED does not establish
		// that guarantee. MySQL tree activation remains disabled until an
		// explicit isolation and cross-host fence are implemented and tested.
		var singleton int
		err := q.QueryRowContext(ctx, `SELECT singleton FROM sealed_tree_meta LIMIT 1 FOR SHARE`).Scan(&singleton)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return store.ErrNodeState
	}
	var roots int64
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_meta`).Scan(&roots); err != nil || roots != 0 {
		return store.ErrNodeState
	}
	return nil
}

// legacyWrite checks the durable tree root inside the same write transaction
// as the old plaintext mutation. SQLite BEGIN IMMEDIATE serializes this with
// offline initialization; no MySQL tree-runtime/fence support is implied.
func (r *Repository) legacyWrite(ctx context.Context, fn func(queryer) error) error {
	return r.write(ctx, func(q queryer) error {
		if err := legacyTreeAbsent(ctx, q); err != nil {
			return err
		}
		return fn(&legacyCheckedQuery{queryer: q})
	})
}
