package sealedtree

import (
	"context"
	"database/sql"
)

// treeQuery is the common operation surface of an already-open transaction.
// Callers remain responsible for its locking, commit and rollback. It lets the
// SQLite BEGIN IMMEDIATE connection and a database/sql transaction share tree
// validation without opening a second transaction.
type treeQuery interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
