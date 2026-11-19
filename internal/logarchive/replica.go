package logarchive

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"os"
	"path/filepath"
	"time"
)

// Reference is the complete archive-node contract. It deliberately has no
// wrapped key, event type, logical names or decrypt method.
type Reference struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

func (r Reference) Valid() bool {
	return identifier(r.ID) && validCiphertextReference(Record{CiphertextSHA256: r.SHA256, CiphertextBytes: r.Bytes})
}
func (r Record) Reference() Reference {
	return Reference{r.Header.ID, r.CiphertextSHA256, r.CiphertextBytes}
}

type Replica struct {
	db   *sql.DB
	root string
}

func OpenReplica(dataRoot string) (*Replica, error) {
	dir := filepath.Join(dataRoot, ".log-archive")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if i, e := os.Lstat(dir); e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return nil, ErrPolicy
	}
	file := filepath.Join(dir, "replicas.sqlite")
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
	for _, q := range []string{"PRAGMA busy_timeout=100", "PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA wal_autocheckpoint=128", "PRAGMA max_page_count=65536", `CREATE TABLE IF NOT EXISTS replicas(master TEXT NOT NULL,id TEXT NOT NULL,sha TEXT NOT NULL,payload BLOB NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(master,id))`, `CREATE INDEX IF NOT EXISTS replica_expiry ON replicas(expires,master,id)`} {
		if _, e = db.Exec(q); e != nil {
			db.Close()
			return nil, e
		}
	}
	if e = os.Chmod(file, 0600); e != nil {
		db.Close()
		return nil, e
	}
	return &Replica{db: db, root: dataRoot}, nil
}
func (r *Replica) Close() error { return r.db.Close() }
func (r *Replica) HasActive(ctx context.Context, master string) bool {
	query := "SELECT 1 FROM replicas WHERE expires>?"
	args := []any{time.Now().Unix()}
	if master != "" {
		query += " AND master=?"
		args = append(args, master)
	}
	var n int
	e := r.db.QueryRowContext(ctx, query+" LIMIT 1", args...).Scan(&n)
	return e == nil || !errors.Is(e, sql.ErrNoRows)
}
func (r *Replica) Expire(ctx context.Context, now time.Time) error {
	_, e := r.db.ExecContext(ctx, "DELETE FROM replicas WHERE (master,id) IN (SELECT master,id FROM replicas WHERE expires<=? ORDER BY expires LIMIT 8)", now.Unix())
	if e != nil {
		return e
	}
	_, e = r.db.ExecContext(ctx, "PRAGMA incremental_vacuum(128)")
	return e
}
func (r *Replica) Put(ctx context.Context, master string, ref Reference, payload []byte, expires int64, now time.Time) error {
	if !identifier(master) || !ref.Valid() || !bytes.HasPrefix(payload, []byte(magic)) || len(payload) != ref.Bytes || hash(payload) != ref.SHA256 || expires <= now.Unix() || expires > now.Add(Retention+time.Minute).Unix() {
		return ErrPolicy
	}
	root, e := os.OpenRoot(r.root)
	if e != nil {
		return e
	}
	defer root.Close()
	_, free, e := fsutil.DiskUsage(root)
	if e != nil {
		return e
	}
	if free < (256<<20)+int64(4*ref.Bytes) {
		return ErrPolicy
	}
	_, e = r.db.ExecContext(ctx, "INSERT INTO replicas(master,id,sha,payload,expires) VALUES(?,?,?,?,?) ON CONFLICT(master,id) DO NOTHING", master, ref.ID, ref.SHA256, payload, expires)
	if e != nil {
		return e
	}
	_, e = r.Read(ctx, master, ref, now)
	return e
}
func (r *Replica) Read(ctx context.Context, master string, ref Reference, now time.Time) ([]byte, error) {
	if !identifier(master) || !ref.Valid() {
		return nil, ErrPolicy
	}
	var sha string
	var p []byte
	var expires int64
	if e := r.db.QueryRowContext(ctx, "SELECT sha,payload,expires FROM replicas WHERE master=? AND id=?", master, ref.ID).Scan(&sha, &p, &expires); e != nil {
		return nil, e
	}
	if sha != ref.SHA256 || hash(p) != sha || len(p) != ref.Bytes || expires <= now.Unix() {
		return nil, ErrBlock
	}
	return p, nil
}

// Release removes only an exact owned copy after lifecycle expiry or a verified
// destination move. The caller must authenticate that reason and receipt.
func (r *Replica) Release(ctx context.Context, master string, ref Reference, expired bool, now time.Time) error {
	if !identifier(master) || !ref.Valid() {
		return ErrPolicy
	}
	q := "DELETE FROM replicas WHERE master=? AND id=? AND sha=?"
	args := []any{master, ref.ID, ref.SHA256}
	if expired {
		q += " AND expires<=?"
		args = append(args, now.Unix())
	}
	_, e := r.db.ExecContext(ctx, q, args...)
	if e != nil {
		return e
	}
	var count int
	if e = r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM replicas WHERE master=? AND id=?", master, ref.ID).Scan(&count); e != nil {
		return e
	}
	if count != 0 {
		return ErrPolicy
	}
	return nil
}
