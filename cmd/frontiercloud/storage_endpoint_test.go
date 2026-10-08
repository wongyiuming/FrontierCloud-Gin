package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

func TestStorageHandoverRequiresClosedGateAndNeverBootstrapsMissingData(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "missing", "native.db")
	t.Setenv("DATA_ROOT", root)
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("SQLITE_PATH", database)
	t.Setenv("DEPLOYMENT_MODE", "only_stroge")
	t.Setenv("TLS_ENABLED", "true")
	t.Setenv("SERVER_NAME", "disk.test")
	t.Setenv("STORAGE_ENDPOINT", "https://disk.test:8443")
	t.Setenv("STORAGE_PORT", "8443")
	t.Setenv("HTTP_ADDR", ":8443")
	t.Setenv("NGINX_MEDIA_ACCEL", "false")
	args := []string{"--confirm-node-id", strings.Repeat("a", 32), "--previous-endpoint", "https://disk.test", "--endpoint", "https://disk.test:8443"}
	var output bytes.Buffer
	if err := storageEndpointCommand("storage-endpoint", args, &output); !errors.Is(err, maintenance.ErrState) {
		t.Fatal("open fence allowed handover", err)
	}
	gate, err := maintenance.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := gate.Enter(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := storageEndpointCommand("storage-endpoint", args, &output); err == nil {
		t.Fatal("missing store created")
	}
	if _, err := os.Stat(filepath.Dir(database)); !os.IsNotExist(err) {
		t.Fatal("database initialized", err)
	}
	if output.Len() != 0 {
		t.Fatal("failure emitted success")
	}
	if enabled, err := gate.Enabled(); err != nil || !enabled {
		t.Fatal("failure resumed runtime", err)
	}
}
