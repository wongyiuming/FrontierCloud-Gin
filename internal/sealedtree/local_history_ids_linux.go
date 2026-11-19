//go:build linux

package sealedtree

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// importLocalHistoryIDsOffline reserves only the IDs in the existing local
// business database. It does not migrate media or authorize runtime startup.
// The maintenance gate excludes cooperating writers across all batches; direct
// SQL and another host are outside that gate's trust boundary. A retry replays
// the same authenticated checkpoints rather than issuing new identities.
func importLocalHistoryIDsOffline(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, s *SQLStore, fenceRoot *os.Root, nodeVault *vault.Vault, nodeID string) (HistoricalMediaIDScope, error) {
	var result HistoricalMediaIDScope
	if ctx == nil || gate == nil || s == nil || fenceRoot == nil || nodeVault == nil || !s.valid() || !lowerHex(nodeID, 32) {
		return result, ErrInvalid
	}
	err := gate.InspectSQLite(ctx, dataRoot, databasePath, func(held context.Context, check func() error) error {
		s.fenceMu.RLock()
		fence := s.fence
		s.fenceMu.RUnlock()
		if fence == nil || fence.store != s || recoveryFenceLocation(dataRoot, fenceRoot, fence.directory) != nil {
			return ErrFenceRequired
		}
		want, e := fenceRoot.Stat(".")
		if e != nil {
			return ErrFenceRequired
		}
		got, e := fence.root.Stat(".")
		if e != nil || !os.SameFile(want, got) {
			return ErrFenceRequired
		}
		lease, e := fence.acquire(held, true)
		if e != nil {
			return e
		}
		defer lease.Release()
		guard := func(tx *sql.Tx) error {
			if check() != nil || held.Err() != nil || fence.checkFile(lease.file) != nil || s.verifyRoot(held, tx) != nil {
				return ErrFenceRequired
			}
			var mainPath string
			if tx.QueryRowContext(held, `SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&mainPath) != nil {
				return ErrFenceRequired
			}
			actual, e1 := filepath.Abs(mainPath)
			expected, e2 := filepath.Abs(databasePath)
			if e1 != nil || e2 != nil || filepath.Clean(actual) != filepath.Clean(expected) {
				return ErrFenceRequired
			}
			a, e1 := os.Stat(actual)
			b, e2 := os.Lstat(expected)
			if e1 != nil || e2 != nil || !b.Mode().IsRegular() || b.Mode()&os.ModeSymlink != 0 || !os.SameFile(a, b) {
				return ErrFenceRequired
			}
			var tag string
			if tx.QueryRowContext(held, `SELECT fence_tag FROM sealed_tree_fence WHERE singleton=1`).Scan(&tag) != nil || !hmac.Equal([]byte(tag), []byte(fence.tag())) {
				return ErrFenceChanged
			}
			_, e = recoveryMasterBinding(held, tx, s, fenceRoot, nodeVault, nodeID)
			return e
		}
		// A full, bounded-memory scan gives this exact local snapshot a stable
		// scope. The final batch repeats it before completion in its transaction.
		scan := func(tx *sql.Tx) (string, uint64, error) {
			rows, e := tx.QueryContext(held, `SELECT file_id FROM media_encryption ORDER BY file_id`)
			if e != nil {
				return "", 0, e
			}
			defer rows.Close()
			h := sha256.New()
			_, _ = fmt.Fprint(h, "frontiercloud:local-history-ids:v1\x00", nodeID, "\x00", s.rootID, "\x00")
			var n uint64
			previous := ""
			for rows.Next() {
				var id string
				if rows.Scan(&id) != nil || !lowerHex(id, 32) || id <= previous {
					return "", 0, ErrInvalid
				}
				_, _ = fmt.Fprint(h, id)
				previous = id
				n++
			}
			if e = rows.Err(); e != nil {
				return "", 0, e
			}
			return hex.EncodeToString(h.Sum(nil)), n, nil
		}
		tx, e := s.db.BeginTx(held, nil)
		if e != nil {
			return e
		}
		if e = guard(tx); e != nil {
			tx.Rollback()
			return e
		}
		manifest, count, e := scan(tx)
		if e == nil {
			e = guard(tx)
		}
		if closeErr := tx.Rollback(); e == nil && closeErr != nil {
			e = closeErr
		}
		if e != nil {
			return e
		}
		var batch uint64
		after := ""
		for {
			tx, e = s.db.BeginTx(held, nil)
			if e != nil {
				return e
			}
			commit := func() error {
				if e := s.lockIndexedWriter(held, tx); e != nil {
					return e
				}
				if e := guard(tx); e != nil {
					return e
				}
				rows, e := tx.QueryContext(held, `SELECT file_id FROM media_encryption WHERE file_id>? ORDER BY file_id LIMIT 257`, after)
				if e != nil {
					return e
				}
				ids := make([]string, 0, 257)
				for rows.Next() {
					var id string
					if rows.Scan(&id) != nil || !lowerHex(id, 32) || id <= after || len(ids) > 0 && id <= ids[len(ids)-1] {
						rows.Close()
						return ErrInvalid
					}
					ids = append(ids, id)
				}
				if e = rows.Err(); e != nil {
					rows.Close()
					return e
				}
				if e = rows.Close(); e != nil {
					return e
				}
				final := len(ids) <= 256
				if !final {
					ids = ids[:256]
				}
				h := sha256.New()
				_, _ = fmt.Fprintf(h, "frontiercloud:local-history-batch:v1\x00%s\x00%d\x00%t\x00", manifest, batch, final)
				for _, id := range ids {
					_, _ = fmt.Fprint(h, id)
				}
				digest := hex.EncodeToString(h.Sum(nil))
				if len(ids) == 0 {
					if batch != 0 || !final || count != 0 {
						return ErrConflict
					}
					e = s.completeEmptyHistoricalMediaTx(held, tx, manifest, digest)
				} else {
					e = s.reserveHistoricalMediaBatchTx(held, tx, manifest, batch, final, digest, ids)
				}
				if e != nil {
					return e
				}
				if final {
					current, total, e := scan(tx)
					if e != nil || current != manifest || total != count {
						return ErrConflict
					}
					batches := batch + 1
					empty := len(ids) == 0
					if empty {
						batches = 0
					}
					if e = s.markHistoricalSourceCompleteTx(held, tx, manifest, batches, empty, digest); e != nil {
						return e
					}
					result = HistoricalMediaIDScope{Manifest: manifest, Batches: batches, Empty: empty, FinalDigest: digest}
				} else {
					after = ids[len(ids)-1]
					batch++
				}
				if e = guard(tx); e != nil {
					return e
				}
				return tx.Commit()
			}()
			if commit != nil {
				tx.Rollback()
				return commit
			}
			if result.Manifest != "" {
				return nil
			}
		}
	})
	if err != nil {
		return HistoricalMediaIDScope{}, err
	}
	return result, nil
}
