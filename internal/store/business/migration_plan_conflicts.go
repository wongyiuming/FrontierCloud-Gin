package business

import (
	"context"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Binary path order keeps a directory's descendants contiguous. Retain only
// its ancestor stack, so many objects or sibling directories do not grow the
// application heap. A single SQL row stream replaces repeated path scans for
// each object page, and reports a split immediate-parent unit exactly once.
func (r *Repository) migrationCatalogConflicts(ctx context.Context, q queryer, c *store.MigrationCatalog) error {
	order := "media_path COLLATE BINARY"
	if r.backend == "mysql" {
		order = "BINARY media_path"
	}
	rows, e := q.QueryContext(ctx, "SELECT media_path,storage_member_id FROM global_media_objects WHERE state IN ('active','pending_delete','renaming') ORDER BY "+order)
	if e != nil {
		return e
	}
	defer rows.Close()
	type directory struct {
		name          string
		source, other bool
	}
	stack := []directory{{name: "."}}
	finish := func() {
		d := stack[len(stack)-1]
		if d.source && d.other {
			c.AddBlocker("split_directory_ownership", d.name)
		}
		stack = stack[:len(stack)-1]
	}
	last := ""
	for rows.Next() {
		var name, member string
		if e = rows.Scan(&name, &member); e != nil {
			return e
		}
		if name <= last || len(name) > 4096 || !utf8.ValidString(name) || path.Clean(name) != name || strings.HasPrefix(name, "/") {
			return store.ErrMigrationState
		}
		last = name
		for len(stack) > 1 && !strings.HasPrefix(name, stack[len(stack)-1].name+"/") {
			finish()
		}
		parent := path.Dir(name)
		if parent != "." {
			parts := strings.Split(parent, "/")
			for depth := len(stack) - 1; depth < len(parts); depth++ {
				stack = append(stack, directory{name: strings.Join(parts[:depth+1], "/")})
			}
		}
		d := &stack[len(stack)-1]
		if member == c.Source.ID {
			d.source = true
		} else {
			d.other = true
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	for len(stack) > 0 {
		finish()
	}
	return nil
}
