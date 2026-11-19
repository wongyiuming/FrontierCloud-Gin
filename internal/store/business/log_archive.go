package business

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
)

// Installed once by the encrypted-tree Master runtime. Resource nodes and
// non-activated installations retain their current audit behavior.
func (r *Repository) ConfigureLogArchive(c *logarchive.Catalog)   { r.logArchive.Store(c) }
func (r *Repository) ConfigureLogProducer(p *logarchive.Producer) { r.logProducer.Store(p) }

func archiveCatalog(q queryer) *logarchive.Catalog {
	switch q := q.(type) {
	case *catalogWrite:
		return q.logs
	case *legacyCheckedQuery:
		return nil
	}
	return nil
}
func archiveEvent(ctx context.Context, q queryer, k logarchive.Kind, fields any) (bool, error) {
	if c := archiveCatalog(q); c != nil {
		return c.AppendTransaction(ctx, q, k, fields)
	}
	if tx, ok := q.(*catalogWrite); ok && tx.producer != nil {
		return tx.producer.AppendTransaction(ctx, q, k, fields)
	}
	return false, nil
}

func securityWindowQuery(q queryer, ip, cutoff string, limit int) (string, []any) {
	if c := archiveCatalog(q); c != nil {
		// Existing unexpired security-window facts remain valid across activation.
		// New entries keep only a keyed index, never a plaintext diagnostic body.
		return "SELECT id,created_at FROM (SELECT id,created_at FROM ip_security_audit_log WHERE ip_address=? AND action='invalid_api' AND created_at>? UNION ALL SELECT id,created_at FROM log_security_windows WHERE ip_tag=? AND action='invalid_api' AND created_at>?) ORDER BY created_at DESC,id DESC LIMIT ?", []any{ip, cutoff, c.SecurityWindowTag(ip), cutoff, limit}
	}
	return "SELECT id,created_at FROM ip_security_audit_log WHERE ip_address=? AND action='invalid_api' AND created_at>? ORDER BY created_at DESC,id DESC LIMIT ?", []any{ip, cutoff, limit}
}
