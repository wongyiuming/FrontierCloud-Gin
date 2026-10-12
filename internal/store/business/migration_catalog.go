package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) MigrationCatalog(ctx context.Context, source, target string) (store.MigrationCatalog, error) {
	if !nodeIDPattern.MatchString(source) || !nodeIDPattern.MatchString(target) || source == target {
		return store.MigrationCatalog{}, store.ErrMigrationState
	}
	level := sql.LevelSerializable
	if r.backend == "mysql" {
		level = sql.LevelRepeatableRead
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: level, ReadOnly: true})
	if e != nil {
		return store.MigrationCatalog{}, e
	}
	defer tx.Rollback()
	c, e := r.migrationCatalog(ctx, tx, source, target)
	if e != nil {
		return c, e
	}
	return c, tx.Commit()
}

func migrationBinding(rel store.Relationship) (string, error) {
	return store.MigrationDigest(struct {
		ID, Peer, Endpoint, PublicKey, Credential, Direction, Mode, State string
		Protocol                                                          int
	}{rel.ID, rel.PeerID, rel.Endpoint, rel.PublicKey, rel.Credential, rel.Direction, rel.Mode, rel.State, rel.Protocol})
}
func (r *Repository) migrationCatalog(ctx context.Context, q queryer, source, target string) (c store.MigrationCatalog, e error) {
	n, e := readNode(ctx, q, "")
	if e != nil {
		return c, e
	}
	if n.Role != "Master" || source == target || source == n.ID || target == n.ID {
		return c, store.ErrMigrationState
	}
	c.MasterID = n.ID
	c.Objects = []store.MigrationObject{}
	c.Blockers = []store.MigrationBlocker{}
	block := func(code, resource string) {
		c.Blockers = append(c.Blockers, store.MigrationBlocker{Code: code, Resource: resource})
	}
	c.Source, e = scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?", source))
	if e != nil {
		return c, e
	}
	c.Target, e = scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?", target))
	if e != nil {
		return c, e
	}
	c.Source.Draining, e = r.migrationDraining(ctx, q, source)
	if e != nil {
		return c, e
	}
	c.Target.Draining, e = r.migrationDraining(ctx, q, target)
	if e != nil {
		return c, e
	}
	if e = q.QueryRowContext(ctx, "SELECT enabled,generation,checksum,state FROM cluster_backup_members WHERE member_id=?", source).Scan(&c.SourceBackup.Enabled, &c.SourceBackup.Generation, &c.SourceBackup.Checksum, &c.SourceBackup.State); e != nil {
		return c, e
	}
	for _, m := range []store.StorageMember{c.Source, c.Target} {
		if m.Kind != "Follower" || m.RelationshipID == nil {
			return c, store.ErrMigrationState
		}
		rel, e := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?", *m.RelationshipID))
		if e != nil {
			return c, e
		}
		binding, e := migrationBinding(rel)
		if e != nil {
			return c, e
		}
		if m.ID == source {
			c.SourceBinding = binding
		} else {
			c.TargetBinding = binding
		}
		if rel.PeerID != m.ID || rel.State != "active" || rel.Direction != "downstream" || rel.Protocol != protocol.Version || (rel.Mode != "Direct" && rel.Mode != "Relay") || rel.Mode != m.Transport {
			block("untrusted_or_incompatible_relationship", m.ID)
		}
		if rel.Status != "online" || rel.LastHeartbeat > time.Now().Unix()+30 || time.Now().Unix()-rel.LastHeartbeat >= 120 || m.Health != "online" {
			block("node_not_healthy", m.ID)
		}
		caps, e := protocol.ReadCapabilities(rel.Summary)
		if e != nil || !slices.Contains(caps, store.MigrationCapability) {
			block("migration_protocol_unavailable", m.ID)
		}
		if m.ID == target && (m.Enabled == 0 || m.Writable == 0) {
			block("target_not_writable", m.ID)
		}
	}
	for _, check := range []struct {
		code, query string
		args        []any
	}{
		{"source_pending_uploads", "SELECT COUNT(*) FROM cluster_upload_sessions WHERE storage_member_id=? AND state NOT IN ('complete','cancelled')", []any{source}},
		{"source_pending_recordings", "SELECT COUNT(*) FROM karaoke_recordings WHERE storage_member_id=? AND state NOT IN ('ready','deleted')", []any{source}},
		{"source_recording_account_deleting", "SELECT COUNT(*) FROM karaoke_recordings r JOIN karaoke_users u ON u.user_id=r.user_id WHERE r.storage_member_id=? AND r.state='ready' AND u.status='deleting'", []any{source}},
		{"source_recording_account_missing", "SELECT COUNT(*) FROM karaoke_recordings r WHERE r.storage_member_id=? AND r.state='ready' AND NOT EXISTS (SELECT 1 FROM karaoke_users u WHERE u.user_id=r.user_id AND u.status IN ('active','banned'))", []any{source}},
		{"source_reserved_capacity", "SELECT COUNT(*) FROM cluster_storage_members WHERE member_id=? AND reserved_bytes<>0", []any{source}},
		{"source_in_other_migration", "SELECT COUNT(*) FROM migration_tasks WHERE (source_id=? OR target_id=?) AND state NOT IN ('completed','cancelled')", []any{source, source}},
		{"target_draining", "SELECT COUNT(*) FROM migration_drains WHERE member_id=?", []any{target}},
		{"source_backup_delivery_pending", "SELECT COUNT(*) FROM cluster_backup_members WHERE member_id=? AND enabled=1 AND state NOT IN ('ready','disabled','failed')", []any{source}},
	} {
		var count int
		if e = q.QueryRowContext(ctx, check.query, check.args...).Scan(&count); e != nil {
			return c, e
		}
		if count != 0 {
			block(check.code, source)
		}
	}
	rows, e := q.QueryContext(ctx, "SELECT media_id,object_id,media_path,object_kind,size_bytes,etag,state,updated_at FROM global_media_objects WHERE storage_member_id=? ORDER BY media_id LIMIT ?", source, store.MaxMigrationObjects+1)
	if e != nil {
		return c, e
	}
	parents := map[string]bool{}
	for rows.Next() {
		var o store.MigrationObject
		var state string
		var updated int64
		if e = rows.Scan(&o.ID, &o.ObjectID, &o.Path, &o.Kind, &o.Bytes, &o.ETag, &state, &updated); e != nil {
			rows.Close()
			return c, e
		}
		if state != "active" {
			block("source_pending_placement", o.ID)
		}
		if !utf8.ValidString(o.Path) || !poolPath(store.LocalMedia{MediaObject: store.MediaObject{Path: o.Path, Kind: o.Kind}, Bytes: o.Bytes}) || !nodeHashPattern.MatchString(o.ID) || !nodeHashPattern.MatchString(o.ObjectID) || o.Bytes <= 0 {
			block("invalid_managed_media", o.ID)
		}
		o.Resource = "media"
		o.Parent = path.Dir(o.Path)
		o.TargetPath = o.Path
		o.Version, _ = store.MigrationDigest(struct {
			ID, Object, Path, Kind, ETag, State string
			Bytes, Updated                      int64
		}{o.ID, o.ObjectID, o.Path, o.Kind, o.ETag, state, o.Bytes, updated})
		parents[o.Parent] = true
		c.Objects = append(c.Objects, o)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return c, e
	}
	if len(c.Objects) > store.MaxMigrationObjects {
		return c, store.ErrMigrationInventoryLimit
	}
	for i := range c.Objects {
		o := &c.Objects[i]
		o.Encryption, e = readEncryption(ctx, q, o.ID, "")
		if e != nil {
			return c, e
		}
		if o.Encryption != nil && o.Encryption.CiphertextSize != o.Bytes {
			block("ciphertext_length_mismatch", o.ID)
		}
		o.Version, e = store.MigrationDigest(struct {
			Version    string
			Encryption any
		}{o.Version, o.Encryption})
		if e != nil {
			return c, e
		}
	}
	// Inspect all other placements as a stream. Only selected parent names are
	// retained, so unrelated catalog size does not grow this plan's memory.
	rows, e = q.QueryContext(ctx, "SELECT media_path,storage_member_id FROM global_media_objects WHERE storage_member_id<>? AND state IN ('active','pending_delete','renaming')", source)
	if e != nil {
		return c, e
	}
	conflicts := map[string]bool{}
	for rows.Next() {
		var name, owner string
		if e = rows.Scan(&name, &owner); e != nil {
			rows.Close()
			return c, e
		}
		parent := path.Dir(name)
		if parents[parent] && !conflicts[parent] {
			conflicts[parent] = true
			block("split_directory_ownership", parent)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return c, e
	}
	rows, e = q.QueryContext(ctx, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE storage_member_id=? AND state='ready' ORDER BY recording_id LIMIT ?", source, store.MaxMigrationObjects-len(c.Objects)+1)
	if e != nil {
		return c, e
	}
	for rows.Next() {
		v, e := scanRecording(rows)
		if e != nil {
			rows.Close()
			return c, e
		}
		if !nodeIDPattern.MatchString(v.ID) || !nodeIDPattern.MatchString(v.UserID) || v.SHA256 == nil || !nodeHashPattern.MatchString(*v.SHA256) || !validRecording(v) {
			block("invalid_managed_recording", v.ID)
		}
		metadata, e := store.EncodeRecordingReservation(v)
		if e != nil {
			rows.Close()
			return c, e
		}
		version, e := store.MigrationDigest(struct {
			ID, User, Owner, Filename, Type string
			Bytes, Updated                  int64
			SHA                             *string
			Metadata                        json.RawMessage
		}{v.ID, v.UserID, v.MemberID, v.Filename, v.ContentType, v.Bytes, v.UpdatedAt, v.SHA256, json.RawMessage(metadata)})
		if e != nil {
			rows.Close()
			return c, e
		}
		o := store.MigrationObject{ID: v.ID, ObjectID: v.ID, Resource: "recording", Kind: "recording", Path: *c.Source.RelationshipID + "/" + v.UserID + "/" + v.ID + ".bin", TargetPath: *c.Target.RelationshipID + "/" + v.UserID + "/" + v.ID + ".bin", Parent: v.UserID, Bytes: v.Bytes, Version: version}
		if v.SHA256 != nil {
			o.ETag = *v.SHA256
		}
		c.Objects = append(c.Objects, o)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return c, e
	}
	if len(c.Objects) > store.MaxMigrationObjects {
		return c, store.ErrMigrationInventoryLimit
	}
	sort.Slice(c.Objects, func(i, j int) bool { return c.Objects[i].ID < c.Objects[j].ID })
	for _, o := range c.Objects {
		if o.Bytes < 0 || c.TotalBytes > store.MaxStorageAllocation-o.Bytes {
			return c, store.ErrMigrationState
		}
		c.TotalBytes += o.Bytes
	}
	if c.Source.Used < c.TotalBytes {
		block("source_accounting_shortfall", source)
	}
	if capacity(c.Target) < c.TotalBytes {
		block("target_capacity_insufficient", target)
	}
	// Heartbeat timestamps/free-space are transient observations, not content
	// identity. Start checks their current values and capacity independently.
	stable := c
	stable.Source.UpdatedAt = 0
	stable.Target.UpdatedAt = 0
	stable.Source.PhysicalFree = 0
	stable.Target.PhysicalFree = 0
	stable.Source.Health = ""
	stable.Target.Health = ""
	stable.Blockers = nil
	stable.Version = ""
	c.Version, e = store.MigrationDigest(stable)
	return c, e
}

func (r *Repository) migrationDraining(ctx context.Context, q queryer, id string) (bool, error) {
	var count int
	e := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_drains WHERE member_id=?", id).Scan(&count)
	return count != 0, e
}
func (r *Repository) checkMigrationRecording(ctx context.Context, q queryer, member, user string) error {
	var count int
	e := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_scopes WHERE member_id=? AND resource_kind='recording' AND parent_path=?", member, user).Scan(&count)
	if e != nil {
		return e
	}
	if count != 0 {
		return store.ErrMigrationState
	}
	return nil
}
func migrationUnit(o store.MigrationObject) string { return locator(o.Resource + ":" + o.Parent) }
func migrationScope(o store.MigrationObject, member string) string {
	return locator(member + ":" + o.Resource + ":" + o.Parent)
}
func migrationPlanBytes(p store.MigrationPlan) ([]byte, error) {
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > store.MaxMigrationPlanBytes {
		return nil, store.ErrMigrationState
	}
	return raw, nil
}

// A file write conflicts only with its immediate parent unit. Directory-wide
// mutations also conflict with descendant units. Nested independent parents
// therefore continue to work during a transfer.
func (r *Repository) checkMigrationScopes(ctx context.Context, q queryer, kind string, scopes []store.DeleteItem) error {
	rows, e := q.QueryContext(ctx, "SELECT DISTINCT parent_path FROM migration_scopes WHERE resource_kind=?", kind)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var parent string
		if e = rows.Scan(&parent); e != nil {
			return e
		}
		for _, scope := range scopes {
			if !scope.Directory && path.Dir(scope.Path) == parent || scope.Directory && (scope.Path == parent || strings.HasPrefix(parent, scope.Path+"/")) {
				return store.ErrMigrationState
			}
		}
	}
	return rows.Err()
}
