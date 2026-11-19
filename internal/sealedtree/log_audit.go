package sealedtree

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
)

func (s *SQLStore) ConfigureLogArchive(c *logarchive.Catalog) { s.logArchive.Store(c) }
func (s *SQLStore) archiveAudit(ctx context.Context, tx treeQuery, fields any) (bool, error) {
	if c := s.logArchive.Load(); c != nil {
		return c.AppendTransaction(ctx, tx, logarchive.Audit, fields)
	}
	return false, nil
}

func (s *SQLStore) archiveLyricAudit(ctx context.Context, tx treeQuery, operation string, p lyricAuditPayload) (bool, error) {
	handled, e := s.archiveAudit(ctx, tx, map[string]any{"action": "lyric_relations", "operation": operation, "origin": p.Origin, "relations": p.Relations, "target_count": len(p.Targets), "changes_count": len(p.Changes), "at": p.At, "audit": p.Audit})
	if !handled || e != nil {
		return handled, e
	}
	for i := 0; i < len(p.Targets); i += 8 {
		end := min(i+8, len(p.Targets))
		if _, e = s.archiveAudit(ctx, tx, map[string]any{"action": "lyric_relations_targets", "operation": operation, "targets": p.Targets[i:end]}); e != nil {
			return true, e
		}
	}
	for i := 0; i < len(p.Changes); i += 8 {
		end := min(i+8, len(p.Changes))
		if _, e = s.archiveAudit(ctx, tx, map[string]any{"action": "lyric_relations_changes", "operation": operation, "changes": p.Changes[i:end]}); e != nil {
			return true, e
		}
	}
	return true, nil
}
