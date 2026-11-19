package logarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const captureBlockWindow = 5 * time.Minute

// PendingForMaster is read-only and used only by the local Master terminal.
// Browser access uses PublishCapture and exact-block grants instead.
func (c *Catalog) PendingForMaster(ctx context.Context, kind Kind) ([]json.RawMessage, error) {
	if !validKind(kind) {
		return nil, ErrPolicy
	}
	var sealed string
	e := c.db.QueryRowContext(ctx, "SELECT sealed FROM log_pending WHERE kind=?", kind).Scan(&sealed)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	p, e := c.vault.Unseal(sealed)
	if e != nil {
		return nil, e
	}
	var values []json.RawMessage
	if json.Unmarshal([]byte(p), &values) != nil {
		return nil, ErrBlock
	}
	return values, nil
}

// Pending batches are sealed before SQL/WAL I/O. Coalescing them keeps quiet
// access streams from creating one immutable manifest per second for 35 days.
// Pending data never leaves Master; only immutable published blocks get grants.
func (c *Catalog) QueueCapture(ctx context.Context, kind Kind, start, end time.Time, raw []byte) error {
	if !validKind(kind) || len(raw) > MaxPlainBytes || !start.Before(end) {
		return ErrPolicy
	}
	if e := c.admitDisk(); e != nil {
		return e
	}
	var added []json.RawMessage
	if json.Unmarshal(raw, &added) != nil {
		return ErrPolicy
	}
	tx, e := c.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var cfgRaw string
	if e = tx.QueryRowContext(ctx, "SELECT sealed FROM log_settings WHERE id=1").Scan(&cfgRaw); e != nil {
		return e
	}
	p, e := c.vault.Unseal(cfgRaw)
	var cfg Configuration
	if e != nil || json.Unmarshal([]byte(p), &cfg) != nil || !cfg.Enabled {
		return ErrPolicy
	}
	var old string
	var oldStart, oldEnd int64
	var oldCost int
	e = tx.QueryRowContext(ctx, "SELECT started,ended,sealed,cost FROM log_pending WHERE kind=?", kind).Scan(&oldStart, &oldEnd, &old, &oldCost)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	values := []json.RawMessage{}
	oldPlain := ""
	if e == nil {
		oldPlain, e = c.vault.Unseal(old)
		if e != nil || json.Unmarshal([]byte(oldPlain), &values) != nil {
			return ErrBlock
		}
	}
	if old != "" && (len(oldPlain)+len(raw) > MaxPlainBytes-1024 || end.Sub(time.UnixMilli(oldStart)) >= captureBlockWindow) {
		if e = c.publishPending(ctx, tx, kind, oldStart, oldEnd, oldPlain, oldCost); e != nil {
			return e
		}
		oldCost = 0
		old = ""
		values = nil
	}
	values = append(values, added...)
	combined, e := json.Marshal(values)
	if e != nil || len(combined) > MaxPlainBytes {
		return ErrPolicy
	}
	sealed, e := c.vault.Seal(string(combined))
	clear(combined)
	if e != nil {
		return e
	}
	cost := len(sealed) + 256
	result, e := tx.ExecContext(ctx, "UPDATE log_budget SET used_bytes=used_bytes+? WHERE id=1 AND used_bytes+?<=134217728", cost-oldCost, cost-oldCost)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrPolicy
	}
	first := start.UnixMilli()
	if old != "" && oldStart < first {
		first = oldStart
	}
	last := end.UnixMilli()
	if oldEnd > last && old != "" {
		last = oldEnd
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO log_pending(kind,started,ended,sealed,cost) VALUES(?,?,?,?,?) ON CONFLICT(kind) DO UPDATE SET started=excluded.started,ended=excluded.ended,sealed=excluded.sealed,cost=excluded.cost", kind, first, last, sealed, cost)
	if e != nil {
		return e
	}
	return tx.Commit()
}

func (c *Catalog) publishPending(ctx context.Context, q Transaction, kind Kind, start, end int64, plain string, oldCost int) error {
	record, p, e := Seal(c.vault, c.master, kind, time.UnixMilli(start), time.UnixMilli(end), []byte(plain))
	if e != nil {
		return e
	}
	manifest, e := SealRecord(c.vault, record)
	if e != nil {
		return e
	}
	cost := len(manifest) + len(p) + 512
	result, e := q.ExecContext(ctx, "UPDATE log_budget SET used_bytes=used_bytes+? WHERE id=1 AND used_bytes+?<=134217728", cost-oldCost, cost-oldCost)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrPolicy
	}
	if _, e = q.ExecContext(ctx, "INSERT INTO log_entries(id,kind,started,ended,manifest,cipher,cost) VALUES(?,?,?,?,?,?,?)", record.Header.ID, kind, start, end, manifest, p, cost); e != nil {
		return e
	}
	_, e = q.ExecContext(ctx, "DELETE FROM log_pending WHERE kind=?", kind)
	return e
}

// PublishCapture seals at most the ten known pending kinds. Queries request
// only their selected kind; the idle worker publishes mature rotation windows.
func (c *Catalog) PublishCapture(ctx context.Context, now time.Time, kind Kind, force bool) error {
	kinds := Kinds()
	if kind != "" {
		if !validKind(kind) {
			return ErrPolicy
		}
		kinds = []Kind{kind}
	}
	for _, k := range kinds {
		tx, e := c.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		var sealed string
		var start, end int64
		var cost int
		e = tx.QueryRowContext(ctx, "SELECT started,ended,sealed,cost FROM log_pending WHERE kind=?", k).Scan(&start, &end, &sealed, &cost)
		if errors.Is(e, sql.ErrNoRows) {
			tx.Rollback()
			continue
		}
		if e != nil {
			tx.Rollback()
			return e
		}
		if !force && now.Sub(time.UnixMilli(start)) < captureBlockWindow {
			tx.Rollback()
			continue
		}
		plain, e := c.vault.Unseal(sealed)
		if e == nil {
			e = c.publishPending(ctx, tx, k, start, end, plain, cost)
		}
		if e != nil {
			tx.Rollback()
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
	}
	return nil
}
