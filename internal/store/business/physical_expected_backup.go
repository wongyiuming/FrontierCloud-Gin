package business

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strconv"
	"strings"
)

func backupInventoryCursor(master string, gen, index int64, chunks bool) string {
	if chunks {
		return fmt.Sprintf("%s:%020d:%010d", master, gen, index)
	}
	return fmt.Sprintf("%s:%020d", master, gen)
}
func parseBackupInventoryCursor(value string, chunks bool) (string, int64, int64, error) {
	if value == "" {
		return "", 0, -1, nil
	}
	parts := strings.Split(value, ":")
	count := 2
	if chunks {
		count = 3
	}
	if len(parts) != count || !nodeIDPattern.MatchString(parts[0]) {
		return "", 0, 0, store.ErrMigrationState
	}
	gen, e := strconv.ParseInt(parts[1], 10, 64)
	if e != nil || gen <= 0 {
		return "", 0, 0, store.ErrMigrationState
	}
	index := int64(-1)
	if chunks {
		index, e = strconv.ParseInt(parts[2], 10, 64)
		if e != nil || index < 0 || index > store.MaxBackupChunkIndex {
			return "", 0, 0, store.ErrMigrationState
		}
	}
	if backupInventoryCursor(parts[0], gen, index, chunks) != value {
		return "", 0, 0, store.ErrMigrationState
	}
	return parts[0], gen, index, nil
}

// Read only metadata and bounded marker prefixes; never return recovery payloads.
// Historical foreign-Master generations are included so re-pairing cannot hide
// a recovery point from the current node inventory.
func (r *Repository) expectedBackups(ctx context.Context, q queryer, resource, after string) ([]store.ExpectedPhysicalItem, error) {
	chunks := resource == "backup_chunk"
	master, gen, index, e := parseBackupInventoryCursor(after, chunks)
	if e != nil {
		return nil, e
	}
	items := make([]store.ExpectedPhysicalItem, 0, 17)
	if !chunks {
		rows, e := q.QueryContext(ctx, "SELECT "+backupColumns+" FROM cluster_business_backups WHERE master_id>? OR (master_id=? AND generation>?) ORDER BY master_id,generation LIMIT 17", master, master, gen)
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		for rows.Next() {
			m, e := scanBackup(rows)
			if e != nil {
				return nil, e
			}
			if !nodeIDPattern.MatchString(m.MasterID) || m.Generation <= 0 || m.Bytes < 0 || m.State != "ready" && m.State != "receiving" {
				return nil, store.ErrBackupState
			}
			digest, e := store.MigrationDigest(m)
			if e != nil {
				return nil, e
			}
			size := m.Bytes
			item := store.ExpectedPhysicalItem{Cursor: backupInventoryCursor(m.MasterID, m.Generation, -1, false), ObjectID: m.MasterID + "." + strconv.FormatInt(m.Generation, 10), MasterID: m.MasterID, Generation: m.Generation, ExpectedBytes: &size, State: m.State, MetadataSHA256: digest, Backing: "database"}
			if m.State == "receiving" {
				item.Backing = "pending"
			} else if r.backupFiles != nil {
				if !nodeHashPattern.MatchString(m.Checksum) {
					return nil, store.ErrBackupState
				}
				item.Backing = "cold_file"
				item.Path = ".cold-backups/" + backupArtifactName(m)
			}
			items = append(items, item)
		}
		return items, rows.Err()
	}
	markerBytes := len(coldChunkMagic) + 36
	rows, e := q.QueryContext(ctx, "SELECT master_id,generation,chunk_index,SUBSTR(payload,1,?),LENGTH(payload) FROM cluster_business_backup_chunks WHERE master_id>? OR (master_id=? AND generation>?) OR (master_id=? AND generation=? AND chunk_index>?) ORDER BY master_id,generation,chunk_index LIMIT 17", markerBytes, master, master, gen, master, gen, index)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var owner string
		var generation, position, length int64
		var prefix []byte
		if e = rows.Scan(&owner, &generation, &position, &prefix, &length); e != nil {
			return nil, e
		}
		if !nodeIDPattern.MatchString(owner) || generation <= 0 || position < 0 || position > store.MaxBackupChunkIndex || length < 0 || length > store.MaxBackupChunk {
			return nil, store.ErrBackupState
		}
		digest, e := store.MigrationDigest([]any{owner, generation, position, length, hex.EncodeToString(prefix)})
		if e != nil {
			return nil, e
		}
		size := length
		item := store.ExpectedPhysicalItem{Cursor: backupInventoryCursor(owner, generation, position, true), ObjectID: owner + "." + strconv.FormatInt(generation, 10) + "." + strconv.FormatInt(position, 10), MasterID: owner, Generation: generation, ChunkIndex: &position, ExpectedBytes: &size, MetadataSHA256: digest, Backing: "database", State: "stored"}
		if bytes.HasPrefix(prefix, coldChunkMagic) && length == int64(markerBytes) {
			if len(prefix) != markerBytes {
				return nil, store.ErrBackupState
			}
			size = int64(binary.BigEndian.Uint32(prefix[len(coldChunkMagic)+32:]))
			if size <= 0 || size > store.MaxBackupChunk {
				return nil, store.ErrBackupState
			}
			item.Backing = "cold_file"
			item.Path = ".cold-backups/" + backupChunkName(owner, generation, int(position), prefix[len(coldChunkMagic):len(coldChunkMagic)+32])
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
