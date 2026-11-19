//go:build linux

package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

func TestTreeArchiveRefusesRetainedRecoveryHold(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	data := filepath.Join(base, "data")
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	db := filepath.Join(data, "database")
	if err = os.WriteFile(db, []byte("existing database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = gate.HoldTreeRecovery(ctx, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(base, "backup.tar")
	_, err = CreateTreeArchive(ctx, gate, data, db, archive, Manifest{Role: "Master", Database: "sqlite"}, nil,
		func(context.Context, func() error) (func(Manifest) (json.RawMessage, error), func() error, error) {
			t.Error("capture began during retained recovery")
			return nil, nil, ErrUnsafe
		})
	if !errors.Is(err, ErrUnsafe) {
		t.Fatalf("capture did not refuse retained recovery: %v", err)
	}
	if _, err = os.Lstat(archive); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("capture published an archive: %v", err)
	}
}
