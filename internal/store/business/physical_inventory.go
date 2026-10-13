package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var inventoryTransactionName = regexp.MustCompile(`^(\.delete-[a-f0-9]{32}|\.rename-[a-f0-9]{32}(\.json)?|\.upload-[a-f0-9]{32}\.(part|json|lock)|\.recording-[a-f0-9]{32}\.(json|part|tmp|deleted|lock))$`)
var inventoryMigrationName = regexp.MustCompile(`^\.migration-data-[a-f0-9]{32}-[a-f0-9]{64}\.(part|json|lock)$`)
var inventoryRecordingLeaseName = regexp.MustCompile(`^\.recording-([a-f0-9]{32})\.lease$`)

// Short read-only SQL snapshots add metadata facts to one bounded native page.
// No filesystem I/O, account/key query, reservation or mutation occurs here.
func (r *Repository) ClassifyPhysicalInventory(ctx context.Context, relationship, member, master string, entries []store.PhysicalInventoryEntry) ([]store.PhysicalInventoryFact, error) {
	if len(entries) > 64 || !nodeIDPattern.MatchString(relationship) || !nodeIDPattern.MatchString(member) || !nodeIDPattern.MatchString(master) {
		return nil, store.ErrMigrationState
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = inventoryIdentity(ctx, tx, relationship, member, master); e != nil {
		return nil, e
	}
	facts := make([]store.PhysicalInventoryFact, 0, len(entries))
	for _, entry := range entries {
		name := entry.Path
		if !utf8.ValidString(name) || name == "." || name == ".." || len(name) > 4096 || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00:") || entry.LogicalBytes < 0 {
			return nil, store.ErrMigrationState
		}
		fact := store.PhysicalInventoryFact{Category: "unmanaged_file", Blocking: true, Reason: "no_managed_metadata"}
		switch entry.Kind {
		case "directory":
			fact = store.PhysicalInventoryFact{Category: "directory"}
			parts := strings.Split(name, "/")
			if len(parts) > 1 && (parts[0] == "media" || parts[0] == "recordings") && inventoryTransactionName.MatchString(parts[1]) {
				fact = store.PhysicalInventoryFact{Category: "transaction_material", Blocking: true, Reason: "reconcile_native_transaction"}
			}
		case "symlink", "special":
			fact.Category = "unsupported_entry"
			fact.Reason = "inspect_link_or_special"
		case "regular":
			parts := strings.Split(name, "/")
			if parts[0] == "recordings" && len(parts) == 2 && inventoryRecordingLeaseName.MatchString(parts[1]) {
				id := inventoryRecordingLeaseName.FindStringSubmatch(parts[1])[1]
				var owner, state string
				var updated int64
				err := tx.QueryRowContext(ctx, "SELECT storage_member_id,state,updated_at FROM karaoke_recordings WHERE recording_id=?", id).Scan(&owner, &state, &updated)
				fact = store.PhysicalInventoryFact{Category: "recording_lease_unverified", ObjectID: id, Blocking: true, Reason: "reconcile_recording_tombstone_and_native_lease"}
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}
				if err == nil && owner == member && state == "deleted" && entry.LogicalBytes == 0 {
					digest, err := store.MigrationDigest([]any{id, owner, state, updated})
					if err != nil {
						return nil, err
					}
					fact = store.PhysicalInventoryFact{Category: "deleted_recording_lease", ObjectID: id, State: state, Blocking: true, Reason: "verify_idle_native_inode", MetadataSHA256: digest}
				}
			} else if (parts[0] == "media" || parts[0] == "recordings") && len(parts) > 1 && inventoryTransactionName.MatchString(parts[1]) {
				fact.Category = "transaction_material"
				fact.Reason = "reconcile_native_transaction"
			} else if (parts[0] == "media" || parts[0] == "recordings") && len(parts) == 2 && inventoryMigrationName.MatchString(parts[1]) {
				fact.Category = "migration_material"
				fact.Reason = "verify_checkpoint_and_retention"
			} else if parts[0] == "media" && len(parts) > 1 {
				fact, e = r.inventoryMedia(ctx, tx, strings.TrimPrefix(name, "media/"), entry.LogicalBytes)
			} else if parts[0] == "recordings" && len(parts) == 4 && parts[1] == relationship && nodeIDPattern.MatchString(parts[2]) && strings.HasSuffix(parts[3], ".bin") {
				fact, e = r.inventoryRecording(ctx, tx, member, parts[2], strings.TrimSuffix(parts[3], ".bin"), entry.LogicalBytes)
			} else if parts[0] == ".cold-backups" && len(parts) == 2 {
				fact, e = r.inventoryColdBackup(ctx, tx, master, parts[1], entry.LogicalBytes)
			} else if parts[0] == ".business-backups" {
				fact.Category = "backup_material"
				fact.Reason = "verify_recovery_artifact"
			}
		default:
			return nil, store.ErrMigrationState
		}
		if e != nil {
			return nil, e
		}
		facts = append(facts, fact)
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return facts, nil
}
func (r *Repository) inventoryMedia(ctx context.Context, q queryer, name string, size int64) (store.PhysicalInventoryFact, error) {
	fact := store.PhysicalInventoryFact{Category: "unmanaged_file", Blocking: true, Reason: "no_media_metadata"}
	var id, kind, stored string
	e := q.QueryRowContext(ctx, "SELECT media_id,object_kind,media_path FROM media_objects WHERE path_locator=?", locator(name)).Scan(&id, &kind, &stored)
	if errors.Is(e, sql.ErrNoRows) {
		return fact, nil
	}
	if e != nil {
		return fact, e
	}
	if !nodeHashPattern.MatchString(id) || stored != name || kind != "audio" && kind != "video" {
		fact.Category = "metadata_mismatch"
		fact.Reason = "unexpected_media_identity_or_kind"
		return fact, nil
	}
	encryption, e := readEncryption(ctx, q, id, "")
	if e != nil {
		return fact, e
	}
	if encryption != nil && encryption.CiphertextSize != size {
		fact.Category = "metadata_mismatch"
		fact.ObjectID = id
		fact.Reason = "ciphertext_length_mismatch"
		return fact, nil
	}
	o := store.MediaObject{ID: id, Kind: kind, Path: stored, Encryption: encryption}
	digest, e := store.MigrationDigest(o)
	if e != nil {
		return fact, e
	}
	return store.PhysicalInventoryFact{Category: "managed_media", ObjectID: id, State: "present", Blocking: true, Reason: "managed_resource_remains", MetadataSHA256: digest}, nil
}
func (r *Repository) inventoryRecording(ctx context.Context, q queryer, member, user, id string, size int64) (store.PhysicalInventoryFact, error) {
	fact := store.PhysicalInventoryFact{Category: "unmanaged_file", Blocking: true, Reason: "no_recording_metadata"}
	if !nodeIDPattern.MatchString(id) {
		return fact, nil
	}
	var owner, storedUser, filename, contentType, state string
	var count int64
	var sha sql.NullString
	e := q.QueryRowContext(ctx, "SELECT storage_member_id,user_id,filename,content_type,state,size_bytes,sha256 FROM karaoke_recordings WHERE recording_id=?", id).Scan(&owner, &storedUser, &filename, &contentType, &state, &count, &sha)
	if errors.Is(e, sql.ErrNoRows) {
		return fact, nil
	}
	if e != nil {
		return fact, e
	}
	if owner != member || storedUser != user || state != "ready" || count != size || !sha.Valid || !nodeHashPattern.MatchString(sha.String) {
		fact.Category = "metadata_mismatch"
		fact.ObjectID = id
		fact.State = state
		fact.Reason = "recording_binding_or_length_mismatch"
		return fact, nil
	}
	digest, e := store.MigrationDigest([]any{id, owner, storedUser, filename, contentType, state, count, sha.String})
	if e != nil {
		return fact, e
	}
	return store.PhysicalInventoryFact{Category: "managed_recording", ObjectID: id, State: state, ExpectedBytes: count, Blocking: true, Reason: "managed_resource_remains", MetadataSHA256: digest}, nil
}
func (r *Repository) inventoryColdBackup(ctx context.Context, q queryer, master, name string, size int64) (store.PhysicalInventoryFact, error) {
	fact := store.PhysicalInventoryFact{Category: "backup_material", Blocking: true, Reason: "unmatched_recovery_artifact"}
	if !coldFileName.MatchString(name) {
		return fact, nil
	}
	parts := strings.Split(name, ".")
	if parts[1] != master {
		fact.Reason = "foreign_backup_identity"
		return fact, nil
	}
	gen, e := strconv.ParseInt(parts[2], 10, 64)
	if e != nil || gen <= 0 {
		return fact, nil
	}
	m, e := scanBackup(q.QueryRowContext(ctx, "SELECT "+backupColumns+" FROM cluster_business_backups WHERE master_id=? AND generation=?", master, gen))
	if errors.Is(e, sql.ErrNoRows) {
		return fact, nil
	}
	if e != nil {
		return fact, e
	}
	expected := m.Bytes
	if parts[0] == "artifact" {
		if name != backupArtifactName(m) {
			return fact, nil
		}
	} else {
		index, e := strconv.ParseInt(parts[3], 10, 64)
		if e != nil || index < 0 || index > store.MaxBackupChunkIndex {
			return fact, nil
		}
		var prefix []byte
		var length int64
		markerBytes := len(coldChunkMagic) + 36
		e = q.QueryRowContext(ctx, "SELECT SUBSTR(payload,1,?),LENGTH(payload) FROM cluster_business_backup_chunks WHERE master_id=? AND generation=? AND chunk_index=?", markerBytes, master, gen, index).Scan(&prefix, &length)
		if errors.Is(e, sql.ErrNoRows) {
			return fact, nil
		}
		if e != nil {
			return fact, e
		}
		if length != int64(markerBytes) || len(prefix) != markerBytes || !bytes.HasPrefix(prefix, coldChunkMagic) || hex.EncodeToString(prefix[len(coldChunkMagic):len(coldChunkMagic)+32]) != parts[4] {
			return fact, nil
		}
		expected = int64(binary.BigEndian.Uint32(prefix[len(coldChunkMagic)+32:]))
	}
	if expected != size {
		fact.Category = "metadata_mismatch"
		fact.Generation = gen
		fact.Reason = "backup_length_mismatch"
		return fact, nil
	}
	digest, e := store.MigrationDigest(m)
	if e != nil {
		return fact, e
	}
	return store.PhysicalInventoryFact{Category: "managed_backup", ObjectID: master, State: m.State, ExpectedBytes: expected, Generation: gen, Blocking: true, Reason: "retain_or_replace_verified_backup", MetadataSHA256: digest}, nil
}

func inventoryIdentity(ctx context.Context, q queryer, relationship, member, master string) error {
	var e error
	var nodeID, role, peer, direction, state string
	var protocol int
	if e = q.QueryRowContext(ctx, "SELECT node_id,role FROM node_identity WHERE singleton=1").Scan(&nodeID, &role); e != nil {
		return e
	}
	if e = q.QueryRowContext(ctx, "SELECT peer_id,direction,state,protocol FROM node_relationships WHERE relationship_id=?", relationship).Scan(&peer, &direction, &state, &protocol); e != nil {
		return e
	}
	if nodeID != member || role != "Follower" || peer != master || state != "active" || direction != "upstream" || protocol != 2 {
		return store.ErrNodeState
	}
	return nil
}
