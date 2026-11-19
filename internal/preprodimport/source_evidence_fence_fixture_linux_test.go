//go:build linux && owner_publish_fixture && ledger_fixture

package preprodimport

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// This fixture holds a real SQLite writer reservation, not a production
// cross-process source-vault fence. It protects only cooperating SQLite
// writers; pathname checks cannot prove which inode a SQLite connection holds.
type fixtureEvidenceFence struct {
	conn      *sql.Conn
	file      *os.File
	path      string
	info      os.FileInfo
	tag       string
	rowHash   [32]byte
	expiresAt int64
}

func fixtureEvidenceRowHash(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, tag string) ([32]byte, error) {
	var result [32]byte
	var n int64
	if err := q.QueryRowContext(ctx, `SELECT length(cipher) FROM preprod_source_evidence WHERE evidence_tag=?`, tag).Scan(&n); err != nil || n <= 0 || n > 4*1024*1024 {
		return result, errors.New("source fixture evidence size")
	}
	var salt, nonce, cipher []byte
	var challenge string
	if err := q.QueryRowContext(ctx, `SELECT salt,nonce,cipher,challenge_tag FROM preprod_source_evidence WHERE evidence_tag=?`, tag).Scan(&salt, &nonce, &cipher, &challenge); err != nil || int64(len(cipher)) != n || len(salt) > 64 || len(nonce) > 64 || len(challenge) > 128 {
		return result, errors.New("source fixture evidence row")
	}
	h := sha256.New()
	h.Write([]byte("frontiercloud:test-source-evidence-row:v1\x00"))
	for _, field := range [][]byte{[]byte(tag), salt, nonce, cipher, []byte(challenge)} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		h.Write(length[:])
		h.Write(field)
	}
	copy(result[:], h.Sum(nil))
	return result, nil
}

func fixtureAcquireEvidenceFence(ctx context.Context, db *sql.DB, path, tag string, expected [32]byte, expiresAt int64) (*fixtureEvidenceFence, error) {
	if ctx == nil || db == nil || !filepath.IsAbs(path) || expiresAt <= time.Now().Unix() {
		return nil, errors.New("source fixture fence input")
	}
	info, err := os.Lstat(path)
	if err != nil || !privateOwned(info, false) {
		return nil, errors.New("source fixture file")
	}
	if links, ok := stagePublishLinkCount(info); !ok || links != 1 {
		return nil, errors.New("source fixture links")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return nil, errors.New("source fixture replaced")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		file.Close()
		return nil, err
	}
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		conn.Close()
		file.Close()
		return nil, err
	}
	f := &fixtureEvidenceFence{conn: conn, file: file, path: path, info: info, tag: tag, rowHash: expected, expiresAt: expiresAt}
	if err = f.Check(ctx); err != nil {
		f.Release()
		return nil, err
	}
	return f, nil
}

func (f *fixtureEvidenceFence) Check(ctx context.Context) error {
	if f == nil || ctx == nil || ctx.Err() != nil || f.conn == nil || f.file == nil || time.Now().Unix() >= f.expiresAt {
		return errors.New("source fixture fence expired")
	}
	var name string
	if err := f.conn.QueryRowContext(ctx, `SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&name); err != nil || filepath.Clean(name) != filepath.Clean(f.path) {
		return errors.New("source fixture database changed")
	}
	current, err := os.Lstat(f.path)
	opened, e := f.file.Stat()
	if err != nil || e != nil || !privateOwned(current, false) || !os.SameFile(f.info, current) || !os.SameFile(f.info, opened) {
		return errors.New("source fixture inode changed")
	}
	if links, ok := stagePublishLinkCount(current); !ok || links != 1 {
		return errors.New("source fixture links changed")
	}
	actual, err := fixtureEvidenceRowHash(ctx, f.conn, f.tag)
	if err != nil || actual != f.rowHash || time.Now().Unix() >= f.expiresAt {
		return errors.New("source fixture evidence changed")
	}
	return nil
}

func (f *fixtureEvidenceFence) Release() {
	if f != nil && f.conn != nil {
		_, _ = f.conn.ExecContext(context.Background(), `ROLLBACK`)
		_ = f.conn.Close()
		f.conn = nil
	}
	if f != nil && f.file != nil {
		_ = f.file.Close()
		f.file = nil
	}
}
