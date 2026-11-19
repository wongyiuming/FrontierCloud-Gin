package sealedtree

import (
	"context"
	"database/sql"
	"math"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const (
	maxVisibilityPaths   = 200
	maxVisibilityEntries = 4096
)

// SetNativeDirectoryVisibility changes only existing directory visibility,
// its authenticated index, and the redacted Admin audit in one transaction.
// The caller must separately authenticate Admin and fence public capability
// admission. Bearer grants already sent to a browser retain their fixed expiry.
func (s *SQLStore) SetNativeDirectoryVisibility(ctx context.Context, paths []string, hidden bool, audit store.AdminAudit) (int, error) {
	if !s.valid() || ctx == nil || ctx.Err() != nil || len(paths) == 0 || len(paths) > maxVisibilityPaths {
		return 0, ErrInvalid
	}
	changed := 0
	err := s.withPriorityTx(ctx, func(tx *sql.Tx) error {
		directories, err := s.nativeVisibilityDirectories(ctx, tx, paths, hidden)
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
		for _, entry := range directories {
			updated, err := s.setDirectoryVisibilityTx(ctx, tx, entry, hidden, now)
			if err != nil {
				return err
			}
			if updated {
				changed++
			}
		}
		if changed == 0 {
			return nil
		}
		action := "unhide"
		if hidden {
			action = "hide"
		}
		if handled, e := s.archiveAudit(ctx, tx, map[string]any{"action": action, "target_count": changed, "audit": audit, "at": now}); handled {
			return e
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO admin_audit_log (session_id_hash,action,target_count,source_summary,result,detail,client_ip,user_agent,request_id,trace_id,created_at) VALUES (?,?,?,NULL,'success',NULL,?,?,?,?,?)`,
			truncateAudit(audit.SessionHash, 64), action, changed, truncateAudit(audit.ClientIP, 45),
			truncateAudit(audit.UserAgent, 512), truncateAudit(audit.RequestID, 128), truncateAudit(audit.TraceID, 32), now)
		return err
	})
	if err != nil {
		return 0, err
	}
	return changed, nil
}

func (s *SQLStore) nativeVisibilityDirectories(ctx context.Context, tx treeQuery, paths []string, hidden bool) ([]Entry, error) {
	depths := make(map[string]int, len(paths))
	var directories []Entry
	add := func(entry Entry, depth int) {
		if depths[entry.ObjectID] == 0 {
			directories = append(directories, entry)
			depths[entry.ObjectID] = depth
		}
	}
	for _, path := range paths {
		parts := strings.Split(path, "/")
		if len(parts) > 3 || (parts[0] != "music" && parts[0] != "vido") {
			return nil, ErrInvalid
		}
		entry, _, err := s.pathEntryTx(ctx, tx, path)
		if err != nil {
			return nil, err
		}
		if entry.Kind != "directory" {
			return nil, ErrInvalid
		}
		add(entry, len(parts))
	}
	if hidden {
		return directories, nil
	}
	// Legacy restore clears explicit descendant directory rules in the same
	// scope. Collect them before changing listing revisions; unrelated rules,
	// internal placeholders and any file revocation are outside the operation.
	scanned := 0
	for i := 0; i < len(directories); i++ {
		parent := directories[i].ObjectID
		depth := depths[parent]
		if depth == 3 {
			continue
		}
		cursor := ""
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			page, next, err := s.listCatalogPageTx(ctx, tx, parent, cursor, 128, true)
			if err != nil {
				return nil, err
			}
			scanned += len(page)
			if scanned > maxVisibilityEntries || (scanned == maxVisibilityEntries && next != "") {
				return nil, ErrConflict
			}
			for _, item := range page {
				if item.Entry.Kind == "directory" {
					add(item.Entry, depth+1)
				}
			}
			if next == "" {
				break
			}
			if next == cursor {
				return nil, ErrConflict
			}
			cursor = next
		}
	}
	return directories, nil
}

func (s *SQLStore) setDirectoryVisibilityTx(ctx context.Context, tx treeQuery, entry Entry, hidden bool, now string) (bool, error) {
	record, current, err := s.recordByID(ctx, tx, entry.ObjectID)
	if err != nil {
		return false, err
	}
	if current != entry {
		return false, ErrConflict
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return false, err
	}
	if facts.InternalPlaceholder || facts.Revocation != nil || facts.DirectoryDeletion != nil || facts.HiddenProof != nil || revision < 1 || revision == math.MaxInt64 {
		return false, ErrConflict
	}
	if hidden == (facts.Visibility != nil && facts.Visibility.Hidden == 1) {
		return false, nil
	}
	oldClass := listingClass(&facts)
	facts.Visibility = nil
	if hidden {
		facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: now}
	}
	sealed, err := s.tree.SealFacts(facts, revision+1)
	if err != nil {
		return false, err
	}
	id, err := FactsEncryptionID(sealed)
	if err != nil {
		return false, err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return false, err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, id, sealed.Sealed, sealed.ObjectIndex, revision)
	if err != nil {
		return false, err
	}
	if n, err := updated.RowsAffected(); err != nil || n != 1 {
		return false, ErrConflict
	}
	if err = s.listingRemove(ctx, tx, entry, record, oldClass); err != nil {
		return false, err
	}
	if err = s.listingAdd(ctx, tx, entry, record, listingClass(&facts)); err != nil {
		return false, err
	}
	return true, nil
}
