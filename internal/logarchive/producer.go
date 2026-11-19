package logarchive

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// A resource node knows only Master's X25519 ingest PUBLIC key. Its persistent
// outbox cannot decrypt a log packet, including when this is the archive node.
type Producer struct {
	db      *sql.DB
	node    string
	cfg     atomic.Pointer[producerConfig]
	queue   chan event
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	dropped atomic.Int64
}
type producerConfig struct {
	Master  string `json:"master"`
	Public  []byte `json:"public"`
	Enabled bool   `json:"enabled"`
}

func OpenProducer(db *sql.DB, node string) (*Producer, error) {
	if db == nil || !identifier(node) {
		return nil, ErrPolicy
	}
	for _, s := range []string{`CREATE TABLE IF NOT EXISTS log_producer_config(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL)`, `CREATE TABLE IF NOT EXISTS log_producer_outbox(id TEXT PRIMARY KEY,master TEXT NOT NULL,packet BLOB NOT NULL,cost INTEGER NOT NULL)`, `CREATE TABLE IF NOT EXISTS log_producer_budget(id INTEGER PRIMARY KEY CHECK(id=1),used INTEGER NOT NULL)`, `INSERT INTO log_producer_budget VALUES(1,0) ON CONFLICT(id) DO NOTHING`} {
		if _, e := db.Exec(s); e != nil {
			return nil, e
		}
	}
	p := &Producer{db: db, node: node, queue: make(chan event, 128)}
	var raw string
	e := db.QueryRow("SELECT value FROM log_producer_config WHERE id=1").Scan(&raw)
	if e == nil {
		var c producerConfig
		if json.Unmarshal([]byte(raw), &c) != nil || !identifier(c.Master) || c.Enabled && len(c.Public) != 32 {
			return nil, ErrBlock
		}
		p.cfg.Store(&c)
	} else if !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	return p, nil
}
func (p *Producer) Enabled() bool         { c := p.cfg.Load(); return c != nil && c.Enabled }
func (p *Producer) FallbackAllowed() bool { c := p.cfg.Load(); return c != nil && !c.Enabled }
func (p *Producer) ObserveInactive(ctx context.Context, master string) {
	if !identifier(master) {
		return
	}
	c := &producerConfig{Master: master, Enabled: false}
	if !p.cfg.CompareAndSwap(nil, c) {
		return
	}
	raw, _ := json.Marshal(c)
	_, _ = p.db.ExecContext(ctx, "INSERT INTO log_producer_config VALUES(1,?) ON CONFLICT(id) DO NOTHING", string(raw))
}
func (p *Producer) Configure(ctx context.Context, master string, public []byte, enabled bool, receipts []string) error {
	if !identifier(master) || len(public) != 32 || len(receipts) > 16 {
		return ErrPolicy
	}
	c := producerConfig{master, public, enabled}
	// Authentication has already bound this public key to the current upstream.
	// Switch the RAM capture boundary immediately, even if this disk is slow.
	p.cfg.Store(&c)
	raw, _ := json.Marshal(c)
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, id := range receipts {
		if !identifier(id) {
			return ErrPolicy
		}
		var cost int
		e = tx.QueryRowContext(ctx, "SELECT cost FROM log_producer_outbox WHERE id=? AND master=?", id, master).Scan(&cost)
		if errors.Is(e, sql.ErrNoRows) {
			continue
		}
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM log_producer_outbox WHERE id=? AND master=?", id, master); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE log_producer_budget SET used=used-? WHERE id=1", cost); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO log_producer_config VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value", string(raw)); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	p.cfg.Store(&c)
	return nil
}
func (p *Producer) AppendTransaction(ctx context.Context, q Transaction, kind Kind, fields any) (bool, error) {
	c := p.cfg.Load()
	if c == nil || !c.Enabled {
		return false, nil
	}
	if !validKind(kind) {
		return true, ErrPolicy
	}
	raw, e := json.Marshal(map[string]any{"kind": kind, "fields": fields})
	if e != nil {
		return true, e
	}
	packet, e := sealIngest(c.Public, c.Master, p.node, raw)
	clear(raw)
	if e != nil {
		return true, e
	}
	raw, e = json.Marshal(packet)
	if e != nil {
		return true, e
	}
	cost := len(raw) + 128
	result, e := q.ExecContext(ctx, "UPDATE log_producer_budget SET used=used+? WHERE id=1 AND used+?<=16777216", cost, cost)
	if e != nil {
		return true, e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return true, ErrPolicy
	}
	_, e = q.ExecContext(ctx, "INSERT INTO log_producer_outbox(id,master,packet,cost) VALUES(?,?,?,?)", packet.ID, packet.Master, raw, cost)
	return true, e
}
func (p *Producer) Capture(kind Kind, fields map[string]any) {
	if !p.Enabled() {
		p.dropped.Add(1)
		return
	}
	raw, e := json.Marshal(fields)
	if e != nil || len(raw) > 8192 {
		p.dropped.Add(1)
		return
	}
	select {
	case p.queue <- event{kind, time.Now(), raw}:
	default:
		p.dropped.Add(1)
	}
}
func (p *Producer) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	p.cancel = cancel
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		batches := map[Kind][]map[string]any{}
		sizes := map[Kind]int{}
		flush := func(kind Kind) {
			values := batches[kind]
			if len(values) == 0 {
				return
			}
			deadline, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			tx, e := p.db.BeginTx(deadline, nil)
			if e == nil {
				_, e = p.AppendTransaction(deadline, tx, kind, map[string]any{"events": values})
				if e == nil {
					e = tx.Commit()
				} else {
					tx.Rollback()
				}
			}
			if e != nil {
				p.dropped.Add(int64(len(values)))
			}
			delete(batches, kind)
			delete(sizes, kind)
		}
		accept := func(v event) {
			var fields map[string]any
			if json.Unmarshal(v.raw, &fields) != nil {
				return
			}
			if sizes[v.kind]+len(v.raw)+96 > 12000 || len(batches[v.kind]) >= 64 {
				flush(v.kind)
			}
			fields["producer_at_ms"] = v.stamp.UnixMilli()
			batches[v.kind] = append(batches[v.kind], fields)
			sizes[v.kind] += len(v.raw) + 96
		}
		defer func() {
			for k := range batches {
				flush(k)
			}
		}()
		for {
			select {
			case v := <-p.queue:
				accept(v)
			case <-ticker.C:
				for k := range batches {
					flush(k)
				}
			case <-ctx.Done():
				for {
					select {
					case v := <-p.queue:
						accept(v)
					default:
						return
					}
				}
			}
		}
	}()
}
func (p *Producer) Close() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
}
func (p *Producer) Packets(ctx context.Context, master string) ([]IngestPacket, error) {
	rows, e := p.db.QueryContext(ctx, "SELECT packet FROM log_producer_outbox WHERE master=? ORDER BY id LIMIT 16", master)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []IngestPacket{}
	for rows.Next() {
		var raw []byte
		var v IngestPacket
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if json.Unmarshal(raw, &v) != nil {
			return nil, ErrBlock
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (p *Producer) PublicWire() map[string]any {
	c := p.cfg.Load()
	if c == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{"enabled": c.Enabled, "ready": CollectorReady(), "master": c.Master, "public_key": base64.RawStdEncoding.EncodeToString(c.Public), "dropped": p.dropped.Load()}
}
