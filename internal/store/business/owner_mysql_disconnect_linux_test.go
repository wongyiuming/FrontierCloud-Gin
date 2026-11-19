//go:build linux

package business_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	mysqlstore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/mysql"
)

// This closes only the dedicated fixture's connection pool; it does not stop
// a database server, test non-cooperating writers, or access production.
func TestOwnerControlFenceSurvivesMySQLPoolDisconnect(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_MYSQL_HOST") == "" {
		t.Skip("dedicated MySQL fixture not configured")
	}
	prefix := os.Getenv("FRONTIERCLOUD_TEST_MYSQL_DATABASE_PREFIX")
	if !strings.HasPrefix(prefix, "fc_test_") {
		t.Fatal("isolated MySQL fixture prefix required")
	}
	ctx := context.Background()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	var name string
	if err := raw.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&name); err != nil || !strings.HasPrefix(name, prefix) {
		t.Fatal("database is not isolated", err)
	}
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("1", 32), Role: "Standalone", PrivateKey: "fixture", CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := ownerfence.Create(root, dir, ownerFixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	setup := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	acquire := func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}
	if err = setup.ConfigureOwnerControlFence(acquire); err != nil {
		t.Fatal(err)
	}
	if err = setup.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	lease, err := setup.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err = raw.Close(); err != nil {
		t.Fatal("close fixture pool", err)
	}
	if err = lease.Check(ctx); err != nil {
		t.Fatal("SQL pool disconnect released local lease", err)
	}
	port := 3306
	if v := os.Getenv("FRONTIERCLOUD_TEST_MYSQL_PORT"); v != "" {
		port, err = strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
	}
	other, err := mysqlstore.Open(mysqlstore.Config{Host: os.Getenv("FRONTIERCLOUD_TEST_MYSQL_HOST"), Port: port, Database: name, User: os.Getenv("FRONTIERCLOUD_TEST_MYSQL_USER"), PasswordFile: os.Getenv("FRONTIERCLOUD_TEST_MYSQL_PASSWORD_FILE")})
	if err != nil {
		t.Fatal("fixture reconnect", err)
	}
	defer other.Close()
	otherSetup := other.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
	})
	if err = otherSetup.ConfigureOwnerControlFence(acquire); err != nil {
		t.Fatal(err)
	}
	blocked, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, err = other.Nodes().InitializeIdentity(blocked, store.NodeIdentity{})
	expired := errors.Is(blocked.Err(), context.DeadlineExceeded)
	cancel()
	if !expired || !errors.Is(err, store.ErrNodeState) {
		t.Fatal("writer bypassed held lease after reconnect", err)
	}
	lease.Release()
	if _, err = other.Nodes().InitializeIdentity(ctx, store.NodeIdentity{}); err != nil {
		t.Fatal("writer failed after lease release", err)
	}
}
