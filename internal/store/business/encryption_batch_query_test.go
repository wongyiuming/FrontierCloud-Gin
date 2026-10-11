package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	_ "modernc.org/sqlite"
)

type encryptionQueryCounter struct {
	*sql.DB
	calls, largest int
}

func (q *encryptionQueryCounter) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	q.calls++
	q.largest = max(q.largest, len(args))
	return q.DB.QueryContext(ctx, query, args...)
}

func TestEncryptionBatchQueriesAreBoundedAndValidateRealSQLRows(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "batch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE media_encryption(object_kind TEXT,object_id TEXT,descriptor_json TEXT,PRIMARY KEY(object_kind,object_id))"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i+1)
	}
	expected := make(map[string]mediacrypto.Metadata)
	for _, i := range []int{0, 499, 1000} {
		metadata, _ := mediacrypto.NewMetadata(int64(i + 1))
		raw, _ := json.Marshal(metadata)
		if _, err := db.Exec("INSERT INTO media_encryption VALUES ('media',?,?)", ids[i], string(raw)); err != nil {
			t.Fatal(err)
		}
		expected[ids[i]] = metadata
	}
	if _, err := db.Exec("INSERT INTO media_encryption VALUES ('media',?,NULL)", ids[500]); err != nil {
		t.Fatal(err)
	}
	// A different identity namespace never decorates a media catalog, even when
	// that foreign SQL row has the same object_id.
	if _, err := db.Exec("INSERT INTO media_encryption VALUES ('recording_lyric',?,'invalid JSON')", ids[20]); err != nil {
		t.Fatal(err)
	}
	query := &encryptionQueryCounter{DB: db}
	actual, err := readEncryptions(ctx, query, append(ids, ids[0], ids[1000]))
	if err != nil || len(actual) != len(expected) {
		t.Fatal("batch changed missing/tombstone/namespace semantics", len(actual), err)
	}
	for id, metadata := range expected {
		if actual[id] == nil || *actual[id] != metadata {
			t.Fatal("descriptor mismatch", id)
		}
	}
	if query.calls != 3 || query.largest > 500 {
		t.Fatal("descriptor lookup grew per track", query.calls, query.largest)
	}
	if _, err := readEncryptions(ctx, query, nil); err != nil || query.calls != 3 {
		t.Fatal("empty catalog performed SQL", err, query.calls)
	}
	if _, err := readEncryptions(ctx, query, []string{"invalid"}); !errors.Is(err, mediacrypto.ErrMetadata) || query.calls != 3 {
		t.Fatal("invalid identity reached SQL", err, query.calls)
	}
	if _, err := db.Exec("UPDATE media_encryption SET descriptor_json='{}' WHERE object_kind='media' AND object_id=?", ids[1000]); err != nil {
		t.Fatal(err)
	}
	if rows, err := readEncryptions(ctx, query, ids); !errors.Is(err, mediacrypto.ErrMetadata) || rows != nil {
		t.Fatal("corrupt late batch returned partial metadata", rows, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := readEncryptions(cancelled, query, ids); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled query ignored", err)
	}
}
