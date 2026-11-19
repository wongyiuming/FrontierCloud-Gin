//go:build legacy_gate_fixture

package business_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

func TestMySQLLegacyTreeGateEmptyIndexBlocksRoot(t *testing.T) {
	// This fixture tests the server's configured isolation. Passing on the
	// isolated REPEATABLE READ server is not evidence for READ COMMITTED.
	db := database(t)
	if db.Backend() != "mysql" {
		t.Skip("MySQL InnoDB gap-lock fixture")
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	repo := business.New(raw, db.Backend())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	held, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- repo.FixtureHoldLegacyWrite(ctx, func() error {
			close(held)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-held:
	case err := <-finished:
		t.Fatal("gate acquisition", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	conn, err := raw.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var id int64
	if err = conn.QueryRowContext(ctx, `SELECT CONNECTION_ID()`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	inserted := make(chan error, 1)
	go func() {
		_, e := conn.ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1})
		inserted <- e
	}()
	for {
		var waiting int
		err = raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.threads t ON t.THREAD_ID=w.REQUESTING_THREAD_ID WHERE t.PROCESSLIST_ID=?`, id).Scan(&waiting)
		if err != nil {
			t.Fatal("cannot observe InnoDB lock wait", err)
		}
		if waiting > 0 {
			break
		}
		select {
		case err = <-inserted:
			t.Fatal("root insert did not wait", err)
		case <-ctx.Done():
			t.Fatal("root wait not observed", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err = repo.DeferExpiredUpload(ctx, strings.Repeat("1", 32)); err != nil {
		t.Fatal("concurrent legacy writer", err)
	}
	close(release)
	if err = <-finished; err != nil {
		t.Fatal("release writer", err)
	}
	if err = <-inserted; err != nil {
		t.Fatal("root insert after release", err)
	}
	if err = repo.DeferExpiredUpload(ctx, strings.Repeat("1", 32)); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("writer accepted published root", err)
	}
}
