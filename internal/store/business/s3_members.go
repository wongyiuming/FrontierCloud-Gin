package business

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const s3MemberColumns = "s.member_id,s.relationship_id,s.member_kind,s.transport,s.storage_enabled,s.allocated_bytes,s.used_bytes,s.reserved_bytes,s.physical_free_bytes,s.health,s.writable,s.updated_at,m.name,m.endpoint,m.region,m.bucket,m.prefix,m.address_style,m.sealed_credentials,m.credential_expires_at,m.credential_revision,m.revision,m.probe_revision,m.probe_state,m.cleanup_only,m.error_code"
const s3MemberTables = " FROM s3_members m JOIN cluster_storage_members s ON s.member_id=m.member_id"

func scanS3Member(row rowScanner) (v store.S3Member, err error) {
	err = row.Scan(&v.ID, &v.RelationshipID, &v.Kind, &v.Transport, &v.Enabled,
		&v.Allocation, &v.Used, &v.Reserved, &v.PhysicalFree, &v.Health, &v.Writable, &v.UpdatedAt,
		&v.Name, &v.Location.Endpoint, &v.Location.Region, &v.Location.Bucket, &v.Location.Prefix, &v.Location.Style,
		&v.SealedCredentials, &v.CredentialExpiresAt, &v.CredentialRevision, &v.Revision,
		&v.ProbeRevision, &v.ProbeState, &v.CleanupOnly, &v.ErrorCode)
	if err == nil && (v.Kind != "S3" || v.Transport != "S3" || v.RelationshipID != nil) {
		err = nodeConflict("S3 member has an invalid native relationship")
	}
	if err == nil {
		v.Available = capacity(v.StorageMember)
		v.OnlineWritable = v.Available
		v.CurrentAllocation, v.ProjectUsed = v.Allocation, v.Used
		if v.Health != "online" {
			v.OfflineStored = v.Used
		}
	}
	return
}

func s3Master(ctx context.Context, q queryer, lock string) error {
	node, err := readNode(ctx, q, lock)
	if err != nil {
		return err
	}
	if node.Role != "Master" {
		return nodeConflict("S3 storage requires Master authority")
	}
	return nil
}

func (r *Repository) s3Member(ctx context.Context, q queryer, id, lock string) (store.S3Member, error) {
	if !nodeIDPattern.MatchString(id) {
		return store.S3Member{}, nodeConflict("invalid S3 member identity")
	}
	v, err := scanS3Member(q.QueryRowContext(ctx, "SELECT "+s3MemberColumns+s3MemberTables+" WHERE m.member_id=?"+lock, id))
	if errors.Is(err, sql.ErrNoRows) {
		err = nodeConflict("S3 member not found")
	}
	return v, err
}

func (r *Repository) S3Member(ctx context.Context, id string) (store.S3Member, error) {
	if err := s3Master(ctx, r.db, ""); err != nil {
		return store.S3Member{}, err
	}
	return r.s3Member(ctx, r.db, id, "")
}

func (r *Repository) S3Members(ctx context.Context) ([]store.S3Member, error) {
	if err := s3Master(ctx, r.db, ""); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, "SELECT "+s3MemberColumns+s3MemberTables+" ORDER BY m.member_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []store.S3Member{}
	for rows.Next() {
		v, err := scanS3Member(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}

func s3Opaque(value string, max int) bool {
	if len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func s3Code(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 64 {
		return false
	}
	for _, c := range value {
		if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func normalizedS3Configuration(c store.S3MemberConfiguration) (store.S3MemberConfiguration, s3store.Namespace, error) {
	config, err := s3store.Normalize(s3store.Config{Endpoint: c.Location.Endpoint, Bucket: c.Location.Bucket,
		Region: c.Location.Region, Prefix: c.Location.Prefix, AddressStyle: c.Location.Style})
	if err != nil {
		return c, s3store.Namespace{}, nodeConflict("invalid S3 location")
	}
	namespace, err := config.Namespace()
	if err != nil {
		return c, namespace, nodeConflict("invalid S3 namespace")
	}
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || !s3Opaque(c.Name, 128) || c.Quota < 0 || c.Quota > store.MaxStorageAllocation ||
		c.Enabled && c.Quota < store.GiB || c.CredentialExpiresAt < 0 {
		return c, namespace, nodeConflict("invalid S3 member configuration")
	}
	if c.SealedCredentials != nil && (*c.SealedCredentials == "" || !s3Opaque(*c.SealedCredentials, 32768)) {
		return c, namespace, nodeConflict("S3 requires an opaque sealed credential")
	}
	c.Location = store.S3Location{Endpoint: config.Endpoint, Bucket: config.Bucket, Region: config.Region,
		Prefix: config.Prefix, Style: config.AddressStyle}
	return c, namespace, nil
}

func (r *Repository) s3NamespaceAvailable(ctx context.Context, q queryer, exclude string, namespace s3store.Namespace) error {
	rows, err := q.QueryContext(ctx, "SELECT member_id,namespace_key,prefix FROM s3_members"+r.lock())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, originBucket, prefix string
		if err = rows.Scan(&id, &originBucket, &prefix); err != nil {
			return err
		}
		if id == exclude {
			continue
		}
		parts := strings.SplitN(originBucket, "\n", 2)
		if len(parts) != 2 {
			return nodeConflict("stored S3 namespace is invalid")
		}
		if namespace.Overlaps(s3store.Namespace{Origin: parts[0], Bucket: parts[1], Prefix: prefix}) {
			return nodeConflict("S3 namespace overlaps an existing member")
		}
	}
	return rows.Err()
}

// All calls occur after the Master identity write lock. That lock serializes
// namespace admission, quota, grants and transitions across SQLite and MySQL.
func s3BoundState(ctx context.Context, q queryer, id string, now int64) (objects, pending, probes int64, err error) {
	queries := []struct {
		query  string
		target *int64
		args   []any
	}{
		{"SELECT (SELECT COUNT(*) FROM global_media_objects WHERE storage_member_id=?)+(SELECT COUNT(*) FROM s3_objects WHERE member_id=?)", &objects, []any{id, id}},
		{"SELECT COUNT(*) FROM s3_uploads WHERE member_id=? AND state NOT IN ('published','aborted')", &pending, []any{id}},
		{"SELECT COUNT(*) FROM s3_probe_journal WHERE member_id=? AND (state<>'settled' OR grant_until>?)", &probes, []any{id, now}},
	}
	for _, check := range queries {
		if err = q.QueryRowContext(ctx, check.query, check.args...).Scan(check.target); err != nil {
			return
		}
	}
	return
}

func (r *Repository) S3AddMember(ctx context.Context, c store.S3MemberConfiguration, a store.NodeAudit) (result store.S3Member, err error) {
	c, namespace, err := normalizedS3Configuration(c)
	if err != nil {
		return result, err
	}
	if c.Enabled || c.SealedCredentials == nil {
		return result, nodeConflict("new S3 members require credentials and start disabled")
	}
	id, err := randomID()
	if err != nil {
		return result, err
	}
	id = id[:32]
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		if err := r.s3NamespaceAvailable(ctx, q, "", namespace); err != nil {
			return err
		}
		now := time.Now().Unix()
		member := store.StorageMember{ID: id, Kind: "S3", Transport: "S3", Allocation: c.Quota, Health: "unchecked", UpdatedAt: now}
		if _, err := q.ExecContext(ctx, "INSERT INTO cluster_storage_members("+memberColumns+") VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
			member.ID, nil, member.Kind, member.Transport, 0, member.Allocation, 0, 0, 0, member.Health, 0, now); err != nil {
			return err
		}
		_, err := q.ExecContext(ctx, "INSERT INTO s3_members(member_id,name,endpoint,region,bucket,prefix,address_style,namespace_key,sealed_credentials,credential_expires_at,credential_revision,revision,probe_revision,probe_state,cleanup_only,error_code,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,1,1,0,'unchecked',0,'',?,?)",
			id, c.Name, c.Location.Endpoint, c.Location.Region, c.Location.Bucket, c.Location.Prefix, c.Location.Style,
			namespace.Origin+"\n"+namespace.Bucket, *c.SealedCredentials, c.CredentialExpiresAt, now, now)
		if err != nil {
			return err
		}
		if err = r.nodeAudit(ctx, q, "s3-member-added", id, map[string]any{"revision": 1}, a); err != nil {
			return err
		}
		result, err = r.s3Member(ctx, q, id, "")
		return err
	})
	return
}

func (r *Repository) S3ConfigureMember(ctx context.Context, id string, revision int64, c store.S3MemberConfiguration, a store.NodeAudit) (result store.S3Member, err error) {
	c, namespace, err := normalizedS3Configuration(c)
	if err != nil {
		return result, err
	}
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		old, err := r.s3Member(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if old.Revision != revision {
			return nodeConflict("S3 configuration revision changed")
		}
		now := time.Now().Unix()
		objects, pending, probes, err := s3BoundState(ctx, q, id, now)
		if err != nil {
			return err
		}
		locationChanged := c.Location != old.Location
		credentialChanged := c.SealedCredentials != nil && (*c.SealedCredentials != old.SealedCredentials || c.CredentialExpiresAt != old.CredentialExpiresAt)
		rebindingRestore := old.SealedCredentials == "" && old.Enabled == 0 && !locationChanged && pending == 0 && probes == 0
		if (locationChanged || credentialChanged && !rebindingRestore) && (objects != 0 || pending != 0 || probes != 0) {
			return nodeConflict("S3 location and credentials are frozen while owned data or intent remains")
		}
		if locationChanged {
			if err = r.s3NamespaceAvailable(ctx, q, id, namespace); err != nil {
				return err
			}
		}
		if c.Quota < old.Used+old.Reserved {
			return nodeConflict("S3 quota is below committed and reserved bytes")
		}
		cleanupOnly := old.CleanupOnly
		if cleanupOnly && objects == 0 && pending == 0 && probes == 0 {
			cleanupOnly = false
		}
		providerChanged := locationChanged || credentialChanged || old.CleanupOnly != cleanupOnly
		probeRevision, probeState := int64(0), "unchecked"
		if !providerChanged && old.ProbeRevision == old.Revision && old.ProbeState == "ready" {
			probeRevision, probeState = revision+1, "ready"
		}
		sealed, expiry, credentialRevision := old.SealedCredentials, old.CredentialExpiresAt, old.CredentialRevision
		if credentialChanged {
			sealed, expiry, credentialRevision = *c.SealedCredentials, c.CredentialExpiresAt, old.CredentialRevision+1
		}
		if c.Enabled && (probeState != "ready" || cleanupOnly || sealed == "" || expiry != 0 && expiry <= now) {
			return nodeConflict("S3 placement requires current credentials and a matching completed probe")
		}
		health, writable := probeState, 0
		if probeState == "ready" {
			health = "online"
			if c.Enabled {
				writable = 1
			}
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_members SET name=?,endpoint=?,region=?,bucket=?,prefix=?,address_style=?,namespace_key=?,sealed_credentials=?,credential_expires_at=?,credential_revision=?,revision=?,probe_revision=?,probe_state=?,cleanup_only=?,error_code='',updated_at=? WHERE member_id=?",
			c.Name, c.Location.Endpoint, c.Location.Region, c.Location.Bucket, c.Location.Prefix, c.Location.Style, namespace.Origin+"\n"+namespace.Bucket,
			sealed, expiry, credentialRevision, revision+1, probeRevision, probeState, cleanupOnly, now, id); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE cluster_storage_members SET storage_enabled=?,allocated_bytes=?,health=?,writable=?,updated_at=? WHERE member_id=?", c.Enabled, c.Quota, health, writable, now, id); err != nil {
			return err
		}
		if err = r.nodeAudit(ctx, q, "s3-member-configured", id, map[string]any{"revision": revision + 1, "credential_changed": credentialChanged}, a); err != nil {
			return err
		}
		result, err = r.s3Member(ctx, q, id, "")
		return err
	})
	return
}

func (r *Repository) S3RecoveryCredentials(ctx context.Context, id string, revision int64, sealed string, expires int64, a store.NodeAudit) (result store.S3Member, err error) {
	if sealed == "" || !s3Opaque(sealed, 32768) || expires < 0 {
		return result, nodeConflict("invalid sealed S3 recovery credentials")
	}
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		member, err := r.s3Member(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if member.Revision != revision || member.Enabled != 0 {
			return nodeConflict("S3 recovery rotation requires a disabled matching configuration")
		}
		now := time.Now().Unix()
		checks := []struct {
			query string
			args  []any
		}{
			{"SELECT COUNT(*) FROM s3_uploads WHERE member_id=? AND (grant_until>? OR state NOT IN ('aborting','aborted','published'))", []any{id, now}},
			{"SELECT COUNT(*) FROM s3_objects WHERE member_id=? AND grant_until>?", []any{id, now}},
			{"SELECT COUNT(*) FROM s3_probe_journal WHERE member_id=? AND grant_until>?", []any{id, now}},
		}
		for _, check := range checks {
			var count int64
			if err = q.QueryRowContext(ctx, check.query, check.args...).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				return nodeConflict("old S3 grants or upload operations have not settled")
			}
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_members SET sealed_credentials=?,credential_expires_at=?,credential_revision=credential_revision+1,revision=revision+1,probe_revision=0,probe_state='unchecked',cleanup_only=1,error_code='',updated_at=? WHERE member_id=?", sealed, expires, now, id); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE cluster_storage_members SET writable=0,health='cleanup_only',updated_at=? WHERE member_id=?", now, id); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_uploads SET credential_revision=?,revision=revision+1,updated_at=? WHERE member_id=? AND state='aborting'", member.CredentialRevision+1, now, id); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_probe_journal SET credential_revision=?,updated_at=? WHERE member_id=? AND state<>'settled'", member.CredentialRevision+1, now, id); err != nil {
			return err
		}
		if err = r.nodeAudit(ctx, q, "s3-cleanup-credentials", id, map[string]any{"revision": revision + 1}, a); err != nil {
			return err
		}
		result, err = r.s3Member(ctx, q, id, "")
		return err
	})
	return
}

func (r *Repository) S3RemoveMember(ctx context.Context, id string, revision int64, a store.NodeAudit) error {
	return r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Member(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if v.Revision != revision || v.Enabled != 0 {
			return nodeConflict("S3 removal requires a disabled matching member")
		}
		objects, pending, probes, err := s3BoundState(ctx, q, id, time.Now().Unix())
		if err != nil {
			return err
		}
		var grants int64
		if err = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM s3_objects WHERE member_id=? AND grant_until>?", id, time.Now().Unix()).Scan(&grants); err != nil {
			return err
		}
		if objects != 0 || pending != 0 || probes != 0 || grants != 0 || v.Used != 0 || v.Reserved != 0 {
			return nodeConflict("S3 member still owns objects, reservations, grants or recovery work")
		}
		for _, query := range []string{
			"DELETE FROM s3_upload_parts WHERE upload_id IN (SELECT upload_id FROM s3_uploads WHERE member_id=?)",
			"DELETE FROM s3_uploads WHERE member_id=?", "DELETE FROM s3_probe_journal WHERE member_id=?",
			"DELETE FROM cluster_upload_sessions WHERE storage_member_id=? AND state IN ('complete','cancelled')",
			"DELETE FROM s3_members WHERE member_id=?", "DELETE FROM cluster_storage_members WHERE member_id=?",
		} {
			if _, err = q.ExecContext(ctx, query, id); err != nil {
				return err
			}
		}
		return r.nodeAudit(ctx, q, "s3-member-removed", id, map[string]any{"revision": revision}, a)
	})
}

func s3Revision(actual, expected int64) error {
	if expected < 1 || actual != expected {
		return nodeConflict("S3 operation revision changed")
	}
	return nil
}

func s3Missing(what string) error { return fmt.Errorf("%w: S3 %s not found", store.ErrNodeState, what) }
