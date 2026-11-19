package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// NativeDirectoryRenameResult contains names only for the authenticated caller.
type NativeDirectoryRenameResult struct {
	Status string `json:"status"`
	Old    string `json:"old_path"`
	New    string `json:"new_path"`
}

// RenameNativeDirectory resolves and renames within the same fenced transaction.
// The caller must already hold the authenticated Admin, Owner and ingress gates.
func (s *SQLStore) RenameNativeDirectory(ctx context.Context, old, newName string, audit store.AdminAudit) (NativeDirectoryRenameResult, error) {
	var result NativeDirectoryRenameResult
	if !s.valid() || ctx == nil || ctx.Err() != nil {
		return result, ErrInvalid
	}
	old = strings.TrimSpace(strings.ReplaceAll(old, "\\", "/"))
	newName = strings.TrimSpace(newName)
	target := path.Dir(old) + "/" + newName
	if old == target {
		// The shared validator excludes unchanged paths. Validate the same
		// source against an unused syntactically valid sibling instead.
		candidate := "fc-rename-validation"
		if newName == candidate {
			candidate = "fc-rename-validation-2"
		}
		if !store.ValidDirectoryRename(old, path.Dir(old)+"/"+candidate) {
			return result, ErrInvalid
		}
	} else if !store.ValidDirectoryRename(old, target) {
		return result, ErrInvalid
	}
	err := s.withPriorityTx(ctx, func(tx *sql.Tx) error {
		entry, _, err := s.pathEntryTx(ctx, tx, old)
		if err != nil {
			return err
		}
		if entry.Kind != "directory" {
			return ErrInvalid
		}
		result = NativeDirectoryRenameResult{Status: "unchanged", Old: old, New: target}
		if old == target {
			return nil
		}
		// Until subtree-aware reservation fencing exists, do not rename while
		// any authenticated file preparation is in flight. This existence
		// check is indexed and shares the exact transaction with the move.
		var pending int
		if err = tx.QueryRowContext(ctx, `SELECT 1 FROM sealed_tree_pending_files LIMIT 1`).Scan(&pending); err == nil {
			return ErrConflict
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if len(newName) > len(entry.Name) || utf8.RuneCountInString(newName) > utf8.RuneCountInString(entry.Name) {
			if err = s.checkRenameDescendantBounds(ctx, tx, entry.ObjectID, target); err != nil {
				return err
			}
		}
		record, _, err := s.recordByID(ctx, tx, entry.ObjectID)
		if err != nil {
			return err
		}
		if record.Revision <= 0 || record.Revision == math.MaxInt64 {
			return ErrInvalid
		}
		if _, err = s.moveTx(ctx, tx, entry.ObjectID, entry.ParentID, newName, record.Revision); err != nil {
			return err
		}
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
		if handled, e := s.archiveAudit(ctx, tx, map[string]any{"action": "directory_rename", "target_count": 1, "audit": audit, "at": now}); handled {
			if e != nil {
				return e
			}
			result.Status = "renamed"
			return nil
		}
		// Logical names and source summaries must never enter the plaintext
		// audit table. Keep the action and request attribution atomically.
		_, err = tx.ExecContext(ctx, `INSERT INTO admin_audit_log (session_id_hash,action,target_count,source_summary,result,detail,client_ip,user_agent,request_id,trace_id,created_at) VALUES (?, 'directory_rename', 1, NULL, 'success', NULL, ?, ?, ?, ?, ?)`,
			truncateAudit(audit.SessionHash, 64), truncateAudit(audit.ClientIP, 45), truncateAudit(audit.UserAgent, 512), truncateAudit(audit.RequestID, 128), truncateAudit(audit.TraceID, 32), now)
		if err != nil {
			return err
		}
		result.Status = "renamed"
		return nil
	})
	if err != nil {
		return NativeDirectoryRenameResult{}, err
	}
	return result, nil
}

// A growing component may push an existing descendant past the resolver's
// byte/rune bounds. Verify authenticated visible and hidden listings before
// moving; internal placeholders and oversized subtrees fail closed.
func (s *SQLStore) checkRenameDescendantBounds(ctx context.Context, tx treeQuery, directoryID, newPath string) error {
	type scope struct {
		id           string
		bytes, runes int
	}
	queue := []scope{{directoryID, len(newPath), utf8.RuneCountInString(newPath)}}
	const maxEntries = 4096
	scanned := 0
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := queue[0]
		queue = queue[1:]
		internal, _, err := s.listingSummary(ctx, tx, s.listingClassGroup(current.id, listingInternal))
		if err != nil {
			return err
		}
		if internal != 0 {
			return ErrConflict
		}
		cursor := ""
		for {
			if err = ctx.Err(); err != nil {
				return err
			}
			items, next, err := s.listCatalogPageTx(ctx, tx, current.id, cursor, 128, true)
			if err != nil {
				return err
			}
			scanned += len(items)
			if scanned > maxEntries || scanned == maxEntries && next != "" {
				return ErrConflict
			}
			for _, item := range items {
				child := item.Entry
				bytes := current.bytes + 1 + len(child.Name)
				runes := current.runes + 1 + utf8.RuneCountInString(child.Name)
				if bytes > 4096 || runes > 1024 {
					return ErrInvalid
				}
				if child.Kind == "directory" {
					queue = append(queue, scope{child.ObjectID, bytes, runes})
				}
			}
			if next == "" {
				break
			}
			if next == cursor {
				return ErrInvalid
			}
			cursor = next
		}
	}
	return nil
}
