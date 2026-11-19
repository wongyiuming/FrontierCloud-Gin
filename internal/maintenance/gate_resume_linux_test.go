//go:build linux

package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResumeExistingSQLiteKeepsFenceOnRefusedProof(t *testing.T) {
	gate, directory := fixture(t)
	ctx := context.Background()
	database := filepath.Join(directory, "database.sqlite")
	if err := os.WriteFile(database, []byte("fixture inode"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	refused := errors.New("fixture refused resume")
	if err := gate.ResumeExistingSQLite(ctx, directory, database, func(context.Context, func() error) error { return refused }); !errors.Is(err, refused) {
		t.Fatal(err)
	}
	if enabled, err := gate.Enabled(); err != nil || !enabled {
		t.Fatal("failed validation released native maintenance", err)
	}
	hold := filepath.Join(directory, OwnerImportHold)
	if err := gate.ResumeExistingSQLite(ctx, directory, database, func(context.Context, func() error) error {
		return os.WriteFile(hold, nil, 0600)
	}); !errors.Is(err, ErrState) {
		t.Fatal("new hold was not detected", err)
	}
	if err := os.Remove(hold); err != nil {
		t.Fatal(err)
	}
	if err := gate.ResumeExistingSQLite(ctx, directory, database, func(_ context.Context, check func() error) error { return check() }); err != nil {
		t.Fatal(err)
	}
	if enabled, err := gate.Enabled(); err != nil || enabled {
		t.Fatal("valid resume did not remove native maintenance", err)
	}
}
