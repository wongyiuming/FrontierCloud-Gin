//go:build !linux

package sealedtree

import (
	"context"
	"database/sql"
)

func VerifyMasterSQLite(context.Context, *sql.DB, string, string, string) error {
	return ErrFenceRequired
}

func OpenMasterSQLite(context.Context, *sql.DB, string, string, string) (*SQLStore, func() error, error) {
	return nil, nil, ErrFenceRequired
}
