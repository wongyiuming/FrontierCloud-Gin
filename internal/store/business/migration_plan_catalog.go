package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"path"
	"sort"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Both resources are queried independently with the same keyset boundary and
// merged into one small page. No OFFSET or growing selected-object map is used.
func (r *Repository) migrationCatalogPage(ctx context.Context, q queryer, c store.MigrationCatalog, after string) (objects []store.MigrationObject, err error) {
	return r.migrationCatalogSelection(ctx, q, c, after, "")
}

// exact selects one current authoritative object without scanning its siblings.
func (r *Repository) migrationCatalogSelection(ctx context.Context, q queryer, c store.MigrationCatalog, after, exact string) (objects []store.MigrationObject, err error) {
	query := "SELECT g.media_id,g.object_id,g.media_path,g.object_kind,g.size_bytes,g.etag,g.state,g.updated_at,e.descriptor_json FROM global_media_objects g LEFT JOIN media_encryption e ON e.object_kind='media' AND e.object_id=g.media_id WHERE g.storage_member_id=? AND g.media_id>?"
	args := []any{c.Source.ID, after}
	if exact != "" {
		query += " AND g.media_id=?"
		args = append(args, exact)
	}
	query += " ORDER BY g.media_id LIMIT ?"
	if exact != "" {
		query += r.lock()
	}
	args = append(args, store.MigrationPageObjects)
	rows, e := q.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var o store.MigrationObject
		var state string
		var updated int64
		var descriptor sql.NullString
		if e = rows.Scan(&o.ID, &o.ObjectID, &o.Path, &o.Kind, &o.Bytes, &o.ETag, &state, &updated, &descriptor); e != nil {
			rows.Close()
			return nil, e
		}
		if state != "active" || !utf8.ValidString(o.Path) || !poolPath(store.LocalMedia{MediaObject: store.MediaObject{Path: o.Path, Kind: o.Kind}, Bytes: o.Bytes}) || !nodeHashPattern.MatchString(o.ID) || !nodeHashPattern.MatchString(o.ObjectID) || o.Bytes <= 0 {
			rows.Close()
			return nil, store.ErrMigrationState
		}
		o.Resource = "media"
		o.Parent = path.Dir(o.Path)
		o.TargetPath = o.Path
		o.Version, e = store.MigrationDigest(struct {
			ID, Object, Path, Kind, ETag, State string
			Bytes, Updated                      int64
		}{o.ID, o.ObjectID, o.Path, o.Kind, o.ETag, state, o.Bytes, updated})
		if e != nil {
			rows.Close()
			return nil, e
		}
		if descriptor.Valid {
			var metadata mediacrypto.Metadata
			if json.Unmarshal([]byte(descriptor.String), &metadata) != nil || metadata.Validate() != nil || metadata.CiphertextSize != o.Bytes {
				rows.Close()
				return nil, store.ErrMigrationState
			}
			o.Encryption = &metadata
		}
		o.Version, e = store.MigrationDigest(struct {
			Version    string
			Encryption any
		}{o.Version, o.Encryption})
		if e != nil {
			rows.Close()
			return nil, e
		}
		objects = append(objects, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}

	query = "SELECT " + recordingColumns + " FROM karaoke_recordings WHERE storage_member_id=? AND state='ready' AND recording_id>?"
	args = []any{c.Source.ID, after}
	if exact != "" {
		query += " AND recording_id=?"
		args = append(args, exact)
	}
	query += " ORDER BY recording_id LIMIT ?"
	if exact != "" {
		query += r.lock()
	}
	args = append(args, store.MigrationPageObjects)
	rows, e = q.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		v, e := scanRecording(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		if !nodeIDPattern.MatchString(v.ID) || !nodeIDPattern.MatchString(v.UserID) || v.SHA256 == nil || !nodeHashPattern.MatchString(*v.SHA256) || !validRecording(v) {
			rows.Close()
			return nil, store.ErrMigrationState
		}
		metadata, e := store.EncodeRecordingReservation(v)
		if e != nil {
			rows.Close()
			return nil, e
		}
		version, e := store.MigrationDigest(struct {
			ID, User, Owner, Filename, Type string
			Bytes, Updated                  int64
			SHA                             *string
			Metadata                        json.RawMessage
		}{v.ID, v.UserID, v.MemberID, v.Filename, v.ContentType, v.Bytes, v.UpdatedAt, v.SHA256, json.RawMessage(metadata)})
		if e != nil {
			rows.Close()
			return nil, e
		}
		o := store.MigrationObject{ID: v.ID, ObjectID: v.ID, Resource: "recording", Kind: "recording", Path: *c.Source.RelationshipID + "/" + v.UserID + "/" + v.ID + ".bin", TargetPath: *c.Target.RelationshipID + "/" + v.UserID + "/" + v.ID + ".bin", Parent: v.UserID, Bytes: v.Bytes, Version: version, ETag: *v.SHA256}
		o.Recording = &store.RecordingProof{ID: v.ID, UserID: v.UserID, Filename: v.Filename, ContentType: v.ContentType, Bytes: v.Bytes, SHA256: o.ETag, CreatedAt: v.CreatedAt}
		if v.EncryptedLyrics != nil {
			o.Recording.EncryptedLyricsEncryption = &v.EncryptedLyrics.Encryption
			o.Recording.MetadataSHA256 = store.RecordingMetadataSHA256(store.RecordingMetadataFor(v))
		}
		objects = append(objects, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	return objects[:min(len(objects), store.MigrationPageObjects)], nil
}

func pagedCatalogSHA(c store.MigrationCatalog, objects string, count int64) (string, error) {
	c.Objects = nil
	c.Blockers = nil
	c.BlockerCount = 0
	c.Version = ""
	c.Source.UpdatedAt = 0
	c.Target.UpdatedAt = 0
	c.Source.PhysicalFree = 0
	c.Target.PhysicalFree = 0
	c.Source.Health = ""
	c.Target.Health = ""
	return store.MigrationDigest(struct {
		Format     string
		Catalog    store.MigrationCatalog
		ObjectsSHA string
		Count      int64
	}{"frontiercloud-paged-catalog-v1", c, objects, count})
}

func (r *Repository) scanMigrationCatalog(ctx context.Context, q queryer, source, target string, visit func([]store.MigrationObject) error) (store.MigrationCatalog, string, int64, error) {
	c, e := r.migrationCatalogHeader(ctx, q, source, target)
	if e != nil {
		return c, "", 0, e
	}
	var sequence store.MigrationSequence
	after := ""
	for {
		page, e := r.migrationCatalogPage(ctx, q, c, after)
		if e != nil {
			return c, "", 0, e
		}
		for _, o := range page {
			if c.TotalBytes > store.MaxStorageAllocation-o.Bytes {
				return c, "", 0, store.ErrMigrationState
			}
			c.TotalBytes += o.Bytes
			if e = sequence.Add(o.ID, o); e != nil {
				return c, "", 0, e
			}
		}
		if visit != nil && len(page) > 0 {
			if e = visit(page); e != nil {
				return c, "", 0, e
			}
		}
		if len(page) < store.MigrationPageObjects {
			break
		}
		after = page[len(page)-1].ID
	}
	if e = r.migrationCatalogConflicts(ctx, q, &c); e != nil {
		return c, "", 0, e
	}
	if c.Source.Used < c.TotalBytes {
		c.AddBlocker("source_accounting_shortfall", source)
	}
	if capacity(c.Target) < c.TotalBytes {
		c.AddBlocker("target_capacity_insufficient", target)
	}
	c.Version, e = pagedCatalogSHA(c, sequence.Sum(), sequence.Count())
	return c, sequence.Sum(), sequence.Count(), e
}

func migrationPlanIsolation(backend string) sql.IsolationLevel {
	if backend == "mysql" {
		return sql.LevelRepeatableRead
	}
	return sql.LevelSerializable
}
