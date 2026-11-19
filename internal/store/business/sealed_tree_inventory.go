package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// No error emitted by this inventory includes a stored path or identifier.
var errSealedInventory = errors.New("sealed tree inventory unavailable or incompatible")
var sealedLegacyID = regexp.MustCompile(`^[a-f0-9]{64}$`)

const sealedInventoryMaxRows int64 = 25000

func inventoryConsume(remaining *int64) error {
	if *remaining <= 0 {
		return store.ErrSealedTreeInventoryLimit
	}
	*remaining--
	return nil
}

// Only fixed internal COUNT queries reach this helper. Limit matched rows in
// SQL as well as in Go; never silently report a truncated count as complete.
func inventoryCount(ctx context.Context, tx *sql.Tx, query string, remaining *int64) (int64, error) {
	const prefix = "SELECT COUNT(*) "
	if !strings.HasPrefix(query, prefix) || *remaining < 0 {
		return 0, errSealedInventory
	}
	bounded := "SELECT COUNT(*) FROM (SELECT 1 " + strings.TrimPrefix(query, prefix) + " LIMIT ?) AS inventory_count"
	var count int64
	if err := tx.QueryRowContext(ctx, bounded, *remaining+1).Scan(&count); err != nil || count < 0 {
		return 0, errSealedInventory
	}
	if count > *remaining {
		return 0, store.ErrSealedTreeInventoryLimit
	}
	*remaining -= count
	return count, nil
}

// Fixed internal SELECTs receive a database-side limit as well as a Go-side
// budget; SQL engines may still examine more rows to satisfy a predicate.
func inventoryRows(ctx context.Context, tx *sql.Tx, query string, remaining *int64) (*sql.Rows, error) {
	if *remaining < 0 {
		return nil, errSealedInventory
	}
	rows, err := tx.QueryContext(ctx, query+" LIMIT ?", *remaining+1)
	if err != nil {
		return nil, errSealedInventory
	}
	return rows, nil
}

func inventoryCanonicalPath(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) || strings.ContainsAny(value, "\\\x00") || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || len(part) > 1024 {
			return false
		}
	}
	return true
}

func inventoryPath(report *store.SealedTreeInventory, value string) {
	if !inventoryCanonicalPath(value) {
		report.NonCanonicalPathValues++
	}
}

func inventoryID(report *store.SealedTreeInventory, id, name string) {
	if !sealedLegacyID.MatchString(id) {
		report.UnsupportedMediaIDValues++
	}
	if id == locator(name) {
		report.PathDerivedMediaIDValues++
	}
}

func inventoryLocator(report *store.SealedTreeInventory, value sql.NullString, name string) {
	if !value.Valid {
		return
	}
	if value.String == locator(name) {
		report.UnkeyedPathLocatorValues++
	} else {
		report.OtherPathLocatorValues++
	}
}

func inventoryObjectRows(ctx context.Context, tx *sql.Tx, query string, report *store.SealedTreeInventory, count, remaining *int64, tree *sealedtree.MigrationPathPreflight) error {
	rows, err := inventoryRows(ctx, tx, query, remaining)
	if err != nil {
		return errSealedInventory
	}
	defer rows.Close()
	for rows.Next() {
		if err = inventoryConsume(remaining); err != nil {
			return err
		}
		var id, name string
		var kind string
		var index sql.NullString
		if tree != nil {
			err = rows.Scan(&id, &name, &index, &kind)
		} else {
			err = rows.Scan(&id, &name, &index)
		}
		if err != nil {
			return errSealedInventory
		}
		*count++
		inventoryPath(report, name)
		inventoryID(report, id, name)
		inventoryLocator(report, index, name)
		if tree != nil && !report.LocalTreePreflightFailed {
			if kind != "directory" && kind != "audio" && kind != "video" && kind != "lyric" {
				report.LocalTreePreflightFailed = true
			} else if tree.Add(name, kind == "directory") != nil {
				report.LocalTreePreflightFailed = true
			}
			if report.LocalTreePreflightFailed {
				tree.Close()
			}
		}
	}
	if rows.Err() != nil {
		return errSealedInventory
	}
	return nil
}

func inventoryPaths(ctx context.Context, tx *sql.Tx, query string, report *store.SealedTreeInventory, count, remaining *int64) error {
	rows, err := inventoryRows(ctx, tx, query, remaining)
	if err != nil {
		return errSealedInventory
	}
	defer rows.Close()
	for rows.Next() {
		if err = inventoryConsume(remaining); err != nil {
			return err
		}
		var first string
		err = rows.Scan(&first)
		if err != nil {
			return errSealedInventory
		}
		*count++
		inventoryPath(report, first)
	}
	if rows.Err() != nil {
		return errSealedInventory
	}
	return nil
}

func inventoryLyricLinks(ctx context.Context, tx *sql.Tx, report *store.SealedTreeInventory, remaining *int64) error {
	rows, err := inventoryRows(ctx, tx, `SELECT media_path,lyric_id,lyric_path FROM media_lyric_links`, remaining)
	if err != nil {
		return errSealedInventory
	}
	defer rows.Close()
	for rows.Next() {
		if err = inventoryConsume(remaining); err != nil {
			return err
		}
		var mediaPath, lyricID, lyricPath string
		if err = rows.Scan(&mediaPath, &lyricID, &lyricPath); err != nil {
			return errSealedInventory
		}
		report.LyricLinkRows++
		inventoryPath(report, mediaPath)
		inventoryPath(report, lyricPath)
		if !sealedLegacyID.MatchString(lyricID) {
			report.UnsupportedLyricIDValues++
		}
		if lyricID == locator(lyricPath) {
			report.PathDerivedLyricIDValues++
		}
	}
	if rows.Err() != nil {
		return errSealedInventory
	}
	return nil
}

// SealedTreeInventory reads only one SQL snapshot, on the authoritative
// Master/Standalone. It performs bounded streaming without emitting paths. It
// never asserts that bytes, permissions, all nodes, old logs or backups match.
// No claim is made that the snapshot remains current after this call.
func (r *Repository) SealedTreeInventory(ctx context.Context) (store.SealedTreeInventory, error) {
	return r.sealedTreeInventory(ctx, sealedInventoryMaxRows)
}

func (r *Repository) sealedTreeInventory(ctx context.Context, rowLimit int64) (store.SealedTreeInventory, error) {
	var report store.SealedTreeInventory
	if r == nil || r.db == nil || ctx == nil || rowLimit <= 0 || rowLimit > sealedInventoryMaxRows || (r.backend != "sqlite" && r.backend != "mysql") {
		return report, errSealedInventory
	}
	// One explicit request is capped and cancellable. Larger inventories need a
	// separately designed fenced, resumable idle job; do not scan indefinitely.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	remaining := rowLimit
	opts := &sql.TxOptions{ReadOnly: true}
	if r.backend == "mysql" {
		opts.Isolation = sql.LevelRepeatableRead
	}
	tx, err := r.db.BeginTx(ctx, opts)
	if err != nil {
		return report, errSealedInventory
	}
	defer tx.Rollback()
	var role string
	if err = tx.QueryRowContext(ctx, "SELECT `role` FROM node_identity WHERE singleton=1").Scan(&role); err != nil || (role != "Master" && role != "Standalone") {
		return report, errSealedInventory
	}
	if err = tx.QueryRowContext(ctx, `SELECT generation FROM frontiercloud_schema WHERE singleton=1`).Scan(&report.SchemaGeneration); err != nil || report.SchemaGeneration != migrations.Generation {
		return store.SealedTreeInventory{}, errSealedInventory
	}
	var localTree sealedtree.MigrationPathPreflight
	defer localTree.Close()
	for _, v := range []struct {
		query string
		count *int64
		tree  *sealedtree.MigrationPathPreflight
	}{
		{`SELECT media_id,media_path,path_locator,object_kind FROM media_objects`, &report.LocalObjectRows, &localTree},
		{`SELECT media_id,media_path,path_locator FROM global_media_objects`, &report.GlobalObjectRows, nil},
		{`SELECT media_id,media_path,path_locator FROM cluster_upload_sessions`, &report.UploadRows, nil},
	} {
		if err = inventoryObjectRows(ctx, tx, v.query, &report, v.count, &remaining, v.tree); err != nil {
			return store.SealedTreeInventory{}, err
		}
	}
	if !report.LocalTreePreflightFailed {
		report.LocalTreePreflightNodes, err = localTree.Counts()
		if err != nil {
			return store.SealedTreeInventory{}, errSealedInventory
		}
	}
	localTree.Close() // release path references before unrelated inventory queries
	for _, v := range []struct {
		query string
		count *int64
	}{
		{`SELECT relative_path FROM media_visibility`, &report.VisibilityRows},
		{`SELECT media_path FROM media_playback_stats`, &report.PlaybackStatRows},
		{`SELECT filename FROM karaoke_recordings`, &report.RecordingRows},
	} {
		if err = inventoryPaths(ctx, tx, v.query, &report, v.count, &remaining); err != nil {
			return store.SealedTreeInventory{}, err
		}
	}
	if err = inventoryLyricLinks(ctx, tx, &report, &remaining); err != nil {
		return store.SealedTreeInventory{}, err
	}
	rows, err := inventoryRows(ctx, tx, `SELECT file_id,descriptor_json FROM media_encryption WHERE descriptor_json IS NOT NULL`, &remaining)
	if err != nil {
		return store.SealedTreeInventory{}, errSealedInventory
	}
	for rows.Next() {
		if err = inventoryConsume(&remaining); err != nil {
			rows.Close()
			return store.SealedTreeInventory{}, err
		}
		var id, raw string
		if err = rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return store.SealedTreeInventory{}, errSealedInventory
		}
		report.EncryptedDescriptorRows++
		var metadata mediacrypto.Metadata
		if json.Unmarshal([]byte(raw), &metadata) != nil || metadata.Validate() != nil || metadata.FileID != id {
			report.InvalidDescriptorRows++
		}
	}
	if rows.Err() != nil {
		rows.Close()
		return store.SealedTreeInventory{}, errSealedInventory
	}
	if rows.Close() != nil {
		return store.SealedTreeInventory{}, errSealedInventory
	}
	rows, err = inventoryRows(ctx, tx, `SELECT allocated_bytes,used_bytes,reserved_bytes FROM cluster_storage_members`, &remaining)
	if err != nil {
		return store.SealedTreeInventory{}, errSealedInventory
	}
	for rows.Next() {
		if err = inventoryConsume(&remaining); err != nil {
			rows.Close()
			return store.SealedTreeInventory{}, err
		}
		var allocated, used, reserved int64
		if err = rows.Scan(&allocated, &used, &reserved); err != nil {
			rows.Close()
			return store.SealedTreeInventory{}, errSealedInventory
		}
		report.StorageMemberRows++
		if allocated < 0 || used < 0 || reserved < 0 || (used >= 0 && reserved >= 0 && used > math.MaxInt64-reserved) {
			report.InvalidQuotaValues++
		}
	}
	if rows.Err() != nil {
		rows.Close()
		return store.SealedTreeInventory{}, errSealedInventory
	}
	if rows.Close() != nil {
		return store.SealedTreeInventory{}, errSealedInventory
	}
	for _, v := range []struct {
		query  string
		target *int64
	}{
		{`SELECT COUNT(*) FROM migration_plan_paths`, &report.MigrationPathIndexRows},
		{`SELECT COUNT(*) FROM migration_scopes`, &report.MigrationScopePathRows},
		{`SELECT COUNT(*) FROM migration_units`, &report.MigrationUnitPathRows},
		{`SELECT COUNT(*) FROM migration_objects`, &report.MigrationObjectPathRows},
		{`SELECT COUNT(*) FROM migration_storage_journal`, &report.MigrationJournalPathRows},
		{`SELECT COUNT(*) FROM media_encryption WHERE descriptor_json IS NULL`, &report.EncryptionTombstoneRows},
		{`SELECT COUNT(*) FROM global_media_objects g LEFT JOIN cluster_storage_members s ON s.member_id=g.storage_member_id WHERE s.member_id IS NULL`, &report.GlobalMissingOwnerRows},
		{`SELECT COUNT(*) FROM media_lyric_links l LEFT JOIN media_objects y ON y.media_id=l.lyric_id AND y.object_kind='lyric' WHERE y.media_id IS NULL`, &report.LyricMissingTargetRows},
		{`SELECT COUNT(*) FROM media_lyric_links l LEFT JOIN media_objects m ON m.media_id=l.media_id AND m.object_kind='audio' LEFT JOIN global_media_objects g ON g.media_id=l.media_id AND g.object_kind='audio' WHERE m.media_id IS NULL AND g.media_id IS NULL`, &report.LyricInvalidTrackRows},
		{`SELECT COUNT(*) FROM media_delete_operations`, &report.DeleteJournalRows},
		{`SELECT COUNT(*) FROM node_audit`, &report.NodeAuditRows},
		{`SELECT COUNT(*) FROM admin_audit_log`, &report.AdminAuditRows},
	} {
		count, countErr := inventoryCount(ctx, tx, v.query, &remaining)
		if countErr != nil {
			return store.SealedTreeInventory{}, countErr
		}
		*v.target = count
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM media_delete_operations WHERE state<>'rename_done'`,
		`SELECT COUNT(*) FROM cluster_upload_sessions WHERE state NOT IN ('complete','cancelled')`,
		`SELECT COUNT(*) FROM global_media_objects WHERE state<>'active'`,
		`SELECT COUNT(*) FROM karaoke_recordings WHERE state<>'ready'`,
		`SELECT COUNT(*) FROM karaoke_users WHERE status='deleting'`,
		`SELECT COUNT(*) FROM cluster_storage_members WHERE reserved_bytes<>0`,
		`SELECT COUNT(*) FROM migration_tasks WHERE state NOT IN ('completed','cancelled')`,
		`SELECT COUNT(*) FROM migration_capacity WHERE reserved_bytes<>0`,
		`SELECT COUNT(*) FROM migration_scopes`,
		`SELECT COUNT(*) FROM migration_storage_journal WHERE state NOT IN ('published','deleted','aborted')`,
		`SELECT COUNT(*) FROM migration_peer_bindings b LEFT JOIN migration_storage_journal j ON b.task_id=j.task_id AND b.logical_id=j.logical_id WHERE j.task_id IS NULL`,
	} {
		n, countErr := inventoryCount(ctx, tx, query, &remaining)
		if countErr != nil {
			return store.SealedTreeInventory{}, countErr
		}
		if n > math.MaxInt64-report.UnsettledIndicators {
			return store.SealedTreeInventory{}, errSealedInventory
		}
		report.UnsettledIndicators += n
	}
	if err = tx.Commit(); err != nil {
		return store.SealedTreeInventory{}, errSealedInventory
	}
	report.DatabaseSnapshotOnly = true
	// This read-only report is deliberately never a readiness or permission.
	report.RuntimeReady = false
	return report, nil
}

var _ store.SealedTreeInventoryRepository = (*Repository)(nil)
