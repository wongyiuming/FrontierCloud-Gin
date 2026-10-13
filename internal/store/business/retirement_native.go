package business

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) RetirementDatabasePath(ctx context.Context) (string, error) {
	if r.backend != "sqlite" {
		return "", nil
	}
	rows, e := r.db.QueryContext(ctx, "PRAGMA database_list")
	if e != nil {
		return "", e
	}
	defer rows.Close()
	for rows.Next() {
		var sequence int
		var name, file string
		if e = rows.Scan(&sequence, &name, &file); e != nil {
			return "", e
		}
		if name == "main" && file != "" && len(file) <= 4096 {
			return file, nil
		}
	}
	if e = rows.Err(); e != nil {
		return "", e
	}
	return "", store.ErrNodeState
}
