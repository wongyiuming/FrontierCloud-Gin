package logarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	_ "modernc.org/sqlite"
)

// The archive namespace has its own schema, not a business-schema migration.
// Log bodies, keys, manifests and configuration are sealed before SQL/WAL I/O.
// Clear columns are bounded scheduling/index facts, never event attributes.
type Catalog struct {
	db       *sql.DB
	vault    *vault.Vault
	master   string
	ownsDB   bool
	dataRoot string
}

var catalogSchema = []string{
	`CREATE TABLE IF NOT EXISTS log_ingest_key(id INTEGER PRIMARY KEY CHECK(id=1),sealed TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS log_ingest_receipts(node_id TEXT NOT NULL,packet_id TEXT NOT NULL,received INTEGER NOT NULL,PRIMARY KEY(node_id,packet_id))`,
	`CREATE INDEX IF NOT EXISTS log_ingest_receipt_recent ON log_ingest_receipts(node_id,received)`,
	`CREATE TABLE IF NOT EXISTS log_pending(kind TEXT PRIMARY KEY,started INTEGER NOT NULL,ended INTEGER NOT NULL,sealed TEXT NOT NULL,cost INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS log_security_windows(id INTEGER PRIMARY KEY,ip_tag TEXT NOT NULL,action TEXT NOT NULL,created_at TEXT NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS log_security_window_lookup ON log_security_windows(ip_tag,action,created_at,id)`,
	`CREATE TABLE IF NOT EXISTS log_settings (id INTEGER PRIMARY KEY CHECK(id=1),sealed TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS log_entries (id TEXT PRIMARY KEY,kind TEXT NOT NULL,started INTEGER NOT NULL,ended INTEGER NOT NULL,manifest TEXT NOT NULL,cipher BLOB,remote TEXT NOT NULL DEFAULT '',remote_member TEXT NOT NULL DEFAULT '',cleanup TEXT NOT NULL DEFAULT '',cleanup_member TEXT NOT NULL DEFAULT '',remote_generation INTEGER NOT NULL DEFAULT 0,retry_at INTEGER NOT NULL DEFAULT 0,error_code TEXT NOT NULL DEFAULT '',cost INTEGER NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS log_query ON log_entries(kind,started,id)`,
	`CREATE INDEX IF NOT EXISTS log_jobs ON log_entries(remote_generation,retry_at,id)`,
	`CREATE TABLE IF NOT EXISTS log_budget (id INTEGER PRIMARY KEY CHECK(id=1),used_bytes INTEGER NOT NULL CHECK(used_bytes>=0))`,
	`INSERT INTO log_budget(id,used_bytes) VALUES(1,0) ON CONFLICT(id) DO NOTHING`,
}

// SharedCatalog keeps the encrypted manifest and durable queue inside the
// existing Master SQLite snapshot. It never changes database-wide limits or
// closes the borrowed business database. The log namespace has its own byte cap.
func SharedCatalog(db *sql.DB, master *vault.Vault, masterID string) (*Catalog, error) {
	if db == nil || master == nil || !identifier(masterID) {
		return nil, ErrPolicy
	}
	for _, q := range catalogSchema {
		if _, e := db.Exec(q); e != nil {
			return nil, e
		}
	}
	return &Catalog{db: db, vault: master, master: masterID}, nil
}

// ExistingCatalog is the non-initializing operator reader. It never creates
// tables, changes settings, renews grants on a node, or advances queue state.
func ExistingCatalog(db *sql.DB, master *vault.Vault, masterID string) (*Catalog, error) {
	if db == nil || master == nil || !identifier(masterID) {
		return nil, ErrPolicy
	}
	var used int64
	if e := db.QueryRow("SELECT used_bytes FROM log_budget WHERE id=1").Scan(&used); e != nil {
		return nil, e
	}
	return &Catalog{db: db, vault: master, master: masterID}, nil
}

// Reserve business headroom rather than consuming the final free disk bytes.
func (c *Catalog) ConfigureDiskAdmission(root string) { c.dataRoot = root }
func (c *Catalog) admitDisk() error {
	if c.dataRoot == "" {
		return nil
	}
	root, e := os.OpenRoot(c.dataRoot)
	if e != nil {
		return e
	}
	defer root.Close()
	_, free, e := fsutil.DiskUsage(root)
	if e != nil {
		return e
	}
	if free < (1<<30)+(4*MaxPlainBytes) {
		return ErrPolicy
	}
	return nil
}

type Target struct {
	MemberID       string `json:"member_id"`
	RelationshipID string `json:"relationship_id"`
	Origin         string `json:"origin"`
}
type Configuration struct {
	Enabled    bool   `json:"enabled"`
	Generation int64  `json:"generation"`
	Target     Target `json:"target"`
}
type Entry struct {
	Record           Record
	Ciphertext       []byte
	Remote           Target
	RemoteGeneration int64
	Cleanup          Target
}

func OpenCatalog(dataRoot string, master *vault.Vault, masterID string) (*Catalog, error) {
	if master == nil || !identifier(masterID) {
		return nil, ErrPolicy
	}
	dir := filepath.Join(dataRoot, ".log-archive")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if i, e := os.Lstat(dir); e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return nil, ErrPolicy
	}
	file := filepath.Join(dir, "catalog.sqlite")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if i, e := os.Lstat(file + suffix); e == nil && (!i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0) {
			return nil, ErrPolicy
		} else if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	db, e := sql.Open("sqlite", file)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*Catalog, error) { db.Close(); return nil, e }
	for _, q := range []string{"PRAGMA busy_timeout=100", "PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA wal_autocheckpoint=128", "PRAGMA max_page_count=32768"} {
		if _, e = db.Exec(q); e != nil {
			return fail(e)
		}
	}
	if e = os.Chmod(file, 0600); e != nil {
		return fail(e)
	}
	c, e := SharedCatalog(db, master, masterID)
	if e != nil {
		return fail(e)
	}
	c.ownsDB = true
	return c, nil
}
func (c *Catalog) Close() error {
	if c.ownsDB {
		return c.db.Close()
	}
	return nil
}
func (c *Catalog) ReadKey(record Record) ([32]byte, error) {
	if record.Header.MasterID != c.master {
		return [32]byte{}, ErrPolicy
	}
	return UnwrapForMaster(c.vault, record)
}
func (c *Catalog) Configuration(ctx context.Context) (Configuration, error) {
	var value Configuration
	var raw string
	e := c.db.QueryRowContext(ctx, "SELECT sealed FROM log_settings WHERE id=1").Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return value, nil
	}
	if e != nil {
		return value, e
	}
	plain, e := c.vault.Unseal(raw)
	if e != nil || json.Unmarshal([]byte(plain), &value) != nil {
		return value, ErrBlock
	}
	return value, nil
}

// Configure is called only after the node service verifies Direct readiness.
// Generation compare-and-swap rejects two Admin tabs overwriting a move.
func (c *Catalog) Configure(ctx context.Context, target Target, generation int64) (Configuration, error) {
	if !identifier(target.MemberID) || !identifier(target.RelationshipID) || target.Origin == "" {
		return Configuration{}, ErrPolicy
	}
	tx, e := c.db.BeginTx(ctx, nil)
	if e != nil {
		return Configuration{}, e
	}
	defer tx.Rollback()
	var old Configuration
	var raw string
	e = tx.QueryRowContext(ctx, "SELECT sealed FROM log_settings WHERE id=1").Scan(&raw)
	if e == nil {
		p, x := c.vault.Unseal(raw)
		if x != nil || json.Unmarshal([]byte(p), &old) != nil {
			return old, ErrBlock
		}
	} else if !errors.Is(e, sql.ErrNoRows) {
		return old, e
	}
	if old.Generation != generation {
		return old, ErrPolicy
	}
	value := Configuration{Enabled: true, Generation: generation + 1, Target: target}
	p, _ := json.Marshal(value)
	sealed, e := c.vault.Seal(string(p))
	if e != nil {
		return old, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO log_settings(id,sealed) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET sealed=excluded.sealed", sealed); e != nil {
		return old, e
	}
	return value, tx.Commit()
}

func (c *Catalog) Append(ctx context.Context, kind Kind, stamp time.Time, raw []byte) error {
	return c.AppendBatch(ctx, kind, stamp, stamp.Add(time.Millisecond), raw)
}
func (c *Catalog) AppendBatch(ctx context.Context, kind Kind, start, end time.Time, raw []byte) error {
	if e := c.admitDisk(); e != nil {
		return e
	}
	cfg, e := c.Configuration(ctx)
	if e != nil {
		return e
	}
	if !cfg.Enabled {
		return ErrPolicy
	}
	if len(raw) > MaxPlainBytes || !json.Valid(raw) {
		return ErrPolicy
	}
	r, p, e := Seal(c.vault, c.master, kind, start, end, raw)
	if e != nil {
		return e
	}
	manifest, e := SealRecord(c.vault, r)
	if e != nil {
		return e
	}
	tx, e := c.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	cost := len(manifest) + len(p) + 512
	result, e := tx.ExecContext(ctx, "UPDATE log_budget SET used_bytes=used_bytes+? WHERE id=1 AND used_bytes<=?", cost, (128<<20)-cost)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrPolicy
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO log_entries(id,kind,started,ended,manifest,cipher,cost) VALUES(?,?,?,?,?,?,?)", r.Header.ID, string(kind), r.Header.StartMillis, r.Header.EndMillis, manifest, p, cost)
	if e != nil {
		return e
	}
	return tx.Commit()
}

func (c *Catalog) entry(ctx context.Context, id string) (Entry, error) {
	return c.readEntry(ctx, id, true)
}
func (c *Catalog) readEntry(ctx context.Context, id string, includeCipher bool) (Entry, error) {
	var result Entry
	var manifest, remote, cleanup string
	e := c.db.QueryRowContext(ctx, "SELECT manifest,CASE WHEN ? THEN cipher ELSE NULL END,remote,remote_generation,cleanup FROM log_entries WHERE id=?", includeCipher, id).Scan(&manifest, &result.Ciphertext, &remote, &result.RemoteGeneration, &cleanup)
	if e != nil {
		return result, e
	}
	result.Record, e = OpenRecord(c.vault, manifest)
	if e != nil || result.Record.Header.ID != id {
		return Entry{}, ErrBlock
	}
	if remote != "" {
		p, x := c.vault.Unseal(remote)
		if x != nil || json.Unmarshal([]byte(p), &result.Remote) != nil {
			return Entry{}, ErrBlock
		}
	}
	if cleanup != "" {
		p, x := c.vault.Unseal(cleanup)
		if x != nil || json.Unmarshal([]byte(p), &result.Cleanup) != nil {
			return Entry{}, ErrBlock
		}
	}
	return result, nil
}
func (c *Catalog) Entry(ctx context.Context, id string) (Entry, error) {
	if !identifier(id) {
		return Entry{}, ErrPolicy
	}
	return c.entry(ctx, id)
}

// Query returns only sealed-record metadata to trusted Master code. Pagination
// does not scan/decrypt event bodies, and never accepts a search string.
func (c *Catalog) Query(ctx context.Context, start, end, now time.Time, kind Kind, keyword bool, after string) ([]Entry, bool, error) {
	if ValidateQuery(start, end, now, kind, keyword) != nil || after != "" && !identifier(after) {
		return nil, false, ErrPolicy
	}
	rows, e := c.db.QueryContext(ctx, "SELECT id FROM log_entries WHERE kind=? AND ended>? AND started<? AND id>? ORDER BY id LIMIT 65", string(kind), start.UnixMilli(), end.UnixMilli(), after)
	if e != nil {
		return nil, false, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, false, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, false, e
	}
	more := len(ids) > 64
	if more {
		ids = ids[:64]
	}
	result := make([]Entry, 0, len(ids))
	for _, id := range ids {
		v, e := c.readEntry(ctx, id, false)
		if e != nil {
			return nil, false, e
		}
		result = append(result, v)
	}
	return result, more, nil
}

func (c *Catalog) Pending(ctx context.Context, generation int64, now time.Time) ([]Entry, error) {
	rows, e := c.db.QueryContext(ctx, "SELECT id FROM log_entries WHERE (remote_generation<>? OR cleanup<>'' OR (cipher IS NOT NULL AND ended<=?)) AND retry_at<=? ORDER BY id LIMIT 8", generation, now.Add(-LocalWindow).UnixMilli(), now.Unix())
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	items := []Entry{}
	for _, id := range ids {
		v, e := c.entry(ctx, id)
		if e != nil {
			return nil, e
		}
		items = append(items, v)
	}
	return items, nil
}
func (c *Catalog) Acknowledge(ctx context.Context, entry Entry, cfg Configuration) error {
	p, _ := json.Marshal(cfg.Target)
	sealed, e := c.vault.Seal(string(p))
	if e != nil {
		return e
	}
	cleanup := ""
	member := ""
	if entry.Remote.MemberID != "" && entry.Remote != cfg.Target {
		raw, _ := json.Marshal(entry.Remote)
		cleanup, e = c.vault.Seal(string(raw))
		if e != nil {
			return e
		}
		member = entry.Remote.MemberID
	}
	result, e := c.db.ExecContext(ctx, "UPDATE log_entries SET remote=?,remote_member=?,remote_generation=?,cleanup=?,cleanup_member=?,error_code='',retry_at=0 WHERE id=? AND cleanup=''", sealed, cfg.Target.MemberID, cfg.Generation, cleanup, member, entry.Record.Header.ID)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e == nil && n != 1 {
		return ErrPolicy
	}
	return e
}
func (c *Catalog) Cleaned(ctx context.Context, id string) error {
	_, e := c.db.ExecContext(ctx, "UPDATE log_entries SET cleanup='',cleanup_member='' WHERE id=?", id)
	return e
}
func (c *Catalog) UsesNode(ctx context.Context, member string) bool {
	cfg, e := c.Configuration(ctx)
	if e != nil {
		return true
	}
	if cfg.Enabled && cfg.Target.MemberID == member {
		return true
	}
	var n int
	e = c.db.QueryRowContext(ctx, "SELECT 1 FROM log_entries WHERE remote_member=? OR cleanup_member=? LIMIT 1", member, member).Scan(&n)
	return e == nil || !errors.Is(e, sql.ErrNoRows)
}
func (c *Catalog) QueueStatus(ctx context.Context, generation int64) (map[string]int64, error) {
	values := map[string]int64{}
	for key, q := range map[string]string{"records": "SELECT COUNT(*) FROM log_entries", "pending": "SELECT COUNT(*) FROM log_entries WHERE remote_generation<>? OR cleanup<>''", "failed": "SELECT COUNT(*) FROM log_entries WHERE error_code<>''", "durable_pending": "SELECT COUNT(*) FROM log_pending", "used_bytes": "SELECT used_bytes FROM log_budget WHERE id=1"} {
		var n int64
		var e error
		if key == "pending" {
			e = c.db.QueryRowContext(ctx, q, generation).Scan(&n)
		} else {
			e = c.db.QueryRowContext(ctx, q).Scan(&n)
		}
		if e != nil {
			return nil, e
		}
		values[key] = n
	}
	return values, nil
}
func (c *Catalog) Retry(ctx context.Context, id string, now time.Time) error {
	_, e := c.db.ExecContext(ctx, "UPDATE log_entries SET retry_at=?,error_code='transfer_failed' WHERE id=?", now.Add(time.Minute).Unix(), id)
	return e
}
func (c *Catalog) ReleaseLocal(ctx context.Context, id string, now time.Time) error {
	tx, e := c.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var size int
	e = tx.QueryRowContext(ctx, "SELECT COALESCE(LENGTH(cipher),0) FROM log_entries WHERE id=? AND remote_generation>0 AND ended<=?", id, now.Add(-LocalWindow).UnixMilli()).Scan(&size)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE log_entries SET cipher=NULL,cost=cost-? WHERE id=?", size, id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE log_budget SET used_bytes=used_bytes-? WHERE id=1", size); e != nil {
		return e
	}
	return tx.Commit()
}
func (c *Catalog) ExpiryPage(ctx context.Context, now time.Time) ([]Entry, error) {
	rows, e := c.db.QueryContext(ctx, "SELECT id FROM log_entries WHERE ended<=? ORDER BY id LIMIT 2", now.Add(-Retention).UnixMilli())
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	values := []Entry{}
	for _, id := range ids {
		v, e := c.entry(ctx, id)
		if e != nil {
			return nil, e
		}
		values = append(values, v)
	}
	return values, nil
}

// ForgetExpired is private to the lifecycle worker after remote expiry proof.
func (c *Catalog) ForgetExpired(ctx context.Context, id string, now time.Time) error {
	tx, e := c.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var cost int
	e = tx.QueryRowContext(ctx, "SELECT cost FROM log_entries WHERE id=? AND ended<=?", id, now.Add(-Retention).UnixMilli()).Scan(&cost)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM log_entries WHERE id=?", id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE log_budget SET used_bytes=used_bytes-? WHERE id=1", cost); e != nil {
		return e
	}
	return tx.Commit()
}
