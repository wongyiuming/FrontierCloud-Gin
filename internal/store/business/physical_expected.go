package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Keyset pages retain no full roster and include no visibility/page filter.
func (r *Repository) ExpectedPhysicalInventory(ctx context.Context, rel, member, master, resource, after string) (store.ExpectedPhysicalPage, error) {
	return r.expectedPhysicalInventory(ctx, rel, member, master, resource, after, "")
}
func (r *Repository) ExpectedPhysicalObject(ctx context.Context, rel, member, master, resource, id string) (store.ExpectedPhysicalItem, error) {
	if resource != "media" && resource != "recording" || resource == "media" && !nodeHashPattern.MatchString(id) || resource == "recording" && !nodeIDPattern.MatchString(id) {
		return store.ExpectedPhysicalItem{}, store.ErrMigrationState
	}
	page, e := r.expectedPhysicalInventory(ctx, rel, member, master, resource, "", id)
	if e != nil {
		return store.ExpectedPhysicalItem{}, e
	}
	if !page.Complete || len(page.Items) != 1 || page.Items[0].ObjectID != id {
		return store.ExpectedPhysicalItem{}, store.ErrMigrationState
	}
	return page.Items[0], nil
}
func (r *Repository) expectedPhysicalInventory(ctx context.Context, rel, member, master, resource, after, selected string) (store.ExpectedPhysicalPage, error) {
	page := store.ExpectedPhysicalPage{Resource: resource, After: after, Next: after, Items: []store.ExpectedPhysicalItem{}}
	if !nodeIDPattern.MatchString(rel) || !nodeIDPattern.MatchString(member) || !nodeIDPattern.MatchString(master) || resource != "media" && resource != "recording" && resource != "backup" && resource != "backup_chunk" || after != "" && (resource == "media" && !nodeHashPattern.MatchString(after) || resource == "recording" && !nodeIDPattern.MatchString(after)) {
		return page, store.ErrMigrationState
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return page, e
	}
	defer tx.Rollback()
	if e = inventoryIdentity(ctx, tx, rel, member, master); e != nil {
		return page, e
	}
	candidates := make([]store.ExpectedPhysicalItem, 0, 17)
	if resource == "media" {
		query := "SELECT media_id,media_path,object_kind FROM media_objects WHERE object_kind IN ('audio','video') AND media_id>? ORDER BY media_id LIMIT 17"
		value := after
		if selected != "" {
			query = "SELECT media_id,media_path,object_kind FROM media_objects WHERE object_kind IN ('audio','video') AND media_id=?"
			value = selected
		}
		rows, e := tx.QueryContext(ctx, query, value)
		if e != nil {
			return page, e
		}
		objects := []store.MediaObject{}
		for rows.Next() {
			var o store.MediaObject
			if e = rows.Scan(&o.ID, &o.Path, &o.Kind); e != nil {
				rows.Close()
				return page, e
			}
			objects = append(objects, o)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return page, e
		}
		for _, o := range objects {
			if !nodeHashPattern.MatchString(o.ID) {
				return page, store.ErrMigrationState
			}
			o.Encryption, e = readEncryption(ctx, tx, o.ID, "")
			if e != nil {
				return page, e
			}
			digest, e := store.MigrationDigest(o)
			if e != nil {
				return page, e
			}
			item := store.ExpectedPhysicalItem{ObjectID: o.ID, Path: "media/" + o.Path, MetadataSHA256: digest}
			if o.Encryption != nil {
				size := o.Encryption.CiphertextSize
				item.ExpectedBytes = &size
			}
			candidates = append(candidates, item)
		}
	} else if resource == "recording" {
		query := "SELECT recording_id,user_id,size_bytes,sha256,filename,content_type FROM karaoke_recordings WHERE storage_member_id=? AND state='ready' AND recording_id>? ORDER BY recording_id LIMIT 17"
		value := after
		if selected != "" {
			query = "SELECT recording_id,user_id,size_bytes,sha256,filename,content_type FROM karaoke_recordings WHERE storage_member_id=? AND state='ready' AND recording_id=?"
			value = selected
		}
		rows, e := tx.QueryContext(ctx, query, member, value)
		if e != nil {
			return page, e
		}
		for rows.Next() {
			var id, user, filename, contentType string
			var size int64
			var sha sql.NullString
			if e = rows.Scan(&id, &user, &size, &sha, &filename, &contentType); e != nil {
				rows.Close()
				return page, e
			}
			if !nodeIDPattern.MatchString(id) || !nodeIDPattern.MatchString(user) || size < 0 {
				rows.Close()
				return page, store.ErrMigrationState
			}
			digest, e := store.MigrationDigest([]any{id, member, user, filename, contentType, "ready", size, sha.String})
			if e != nil {
				rows.Close()
				return page, e
			}
			candidates = append(candidates, store.ExpectedPhysicalItem{ObjectID: id, Path: "recordings/" + rel + "/" + user + "/" + id + ".bin", ExpectedBytes: &size, MetadataSHA256: digest})
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return page, e
		}
	}
	if resource == "backup" || resource == "backup_chunk" {
		candidates, e = r.expectedBackups(ctx, tx, resource, after)
		if e != nil {
			return page, e
		}
	}
	encodedBytes := 0
	for _, item := range candidates {
		raw, e := json.Marshal(item)
		if e != nil {
			return page, e
		}
		if len(raw) > 32<<10 {
			return page, store.ErrMigrationInventoryLimit
		}
		if len(page.Items) == 16 || encodedBytes+len(raw) > 32<<10 {
			break
		}
		page.Items = append(page.Items, item)
		page.Next = item.ObjectID
		if item.Cursor != "" {
			page.Next = item.Cursor
		}
		encodedBytes += len(raw)
	}
	page.Complete = len(page.Items) == len(candidates) && len(candidates) < 17
	if e = tx.Commit(); e != nil {
		return page, e
	}
	return page, nil
}
