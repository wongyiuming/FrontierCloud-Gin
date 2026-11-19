package logarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Transaction is a borrowed business transaction. Audit and the business
// mutation must commit or roll back together; never open a second SQL writer.
type Transaction interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (c *Catalog) AppendTransaction(ctx context.Context, q Transaction, kind Kind, fields any) (bool, error) {
	var sealed string
	e := q.QueryRowContext(ctx, "SELECT sealed FROM log_settings WHERE id=1").Scan(&sealed)
	if errors.Is(e, sql.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return true, e
	}
	plain, e := c.vault.Unseal(sealed)
	var cfg Configuration
	if e != nil || json.Unmarshal([]byte(plain), &cfg) != nil {
		return true, ErrBlock
	}
	if !cfg.Enabled {
		return false, nil
	}
	raw, e := json.Marshal(fields)
	if e != nil {
		return true, e
	}
	var event map[string]any
	if json.Unmarshal(raw, &event) != nil {
		return true, ErrPolicy
	}
	now := time.Now().UTC()
	event["received_at_ms"] = now.UnixMilli()
	if batch, ok := event["events"].([]any); ok {
		if len(batch) > 128 {
			return true, ErrPolicy
		}
		for _, item := range batch {
			v, ok := item.(map[string]any)
			if !ok {
				return true, ErrPolicy
			}
			v["received_at_ms"] = now.UnixMilli()
			if source, ok := event["source_node"]; ok {
				v["source_node"] = source
			}
		}
		raw, e = json.Marshal(batch)
	} else {
		raw, e = json.Marshal(event)
	}
	if e != nil {
		return true, e
	}
	if e = c.admitDisk(); e != nil {
		return true, e
	}
	record, p, e := Seal(c.vault, c.master, kind, now, now.Add(time.Millisecond), raw)
	if e != nil {
		return true, e
	}
	manifest, e := SealRecord(c.vault, record)
	if e != nil {
		return true, e
	}
	cost := len(manifest) + len(p) + 512
	result, e := q.ExecContext(ctx, "UPDATE log_budget SET used_bytes=used_bytes+? WHERE id=1 AND used_bytes<=?", cost, (128<<20)-cost)
	if e != nil {
		return true, e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return true, ErrPolicy
	}
	_, e = q.ExecContext(ctx, "INSERT INTO log_entries(id,kind,started,ended,manifest,cipher,cost) VALUES(?,?,?,?,?,?,?)", record.Header.ID, string(kind), record.Header.StartMillis, record.Header.EndMillis, manifest, p, cost)
	return true, e
}

func (c *Catalog) SecurityWindowTag(ip string) string { return c.vault.LogSecurityIndex(ip) }
