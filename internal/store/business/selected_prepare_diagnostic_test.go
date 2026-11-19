package business

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlite3 "modernc.org/sqlite/lib"
)

func TestSelectedPrepareFailureClass(t *testing.T) {
	stages := []string{"readiness", "input", "path", "prepare_proof", "policy", "directory", "pending", "reservation", "scope", "capability"}
	for _, stage := range stages {
		err := &selectedPrepareFailure{stage: stage, err: fmt.Errorf("secret path: %w", sealedtree.ErrFenceChanged)}
		gotStage, gotCause := SelectedPrepareFailureClass(err)
		if gotStage != stage || gotCause != "fence_changed" || !errors.Is(err, sealedtree.ErrFenceChanged) || err.Error() != err.err.Error() {
			t.Fatalf("stage %q classification or error chain changed", stage)
		}
	}
	for _, tc := range []struct {
		err   error
		cause string
	}{{context.Canceled, "cancelled"}, {context.DeadlineExceeded, "deadline"}, {sealedtree.ErrConflict, "conflict"}, {sealedtree.ErrInvalid, "invalid"}, {store.ErrNodeState, "state"}, {store.ErrStorageCapacity, "capacity"}, {errors.New("secret"), "other"}} {
		stage, cause := SelectedPrepareFailureClass(tc.err)
		if stage != "other" || cause != tc.cause {
			t.Fatalf("unexpected classification %s/%s", stage, cause)
		}
	}
	if stage, _ := SelectedPrepareFailureClass(&selectedPrepareFailure{stage: "secret", err: store.ErrNodeState}); stage != "other" {
		t.Fatal("unrecognized stage was exposed")
	}
	for code, want := range map[int]string{sqlite3.SQLITE_BUSY: "sqlite_busy", sqlite3.SQLITE_BUSY | 2<<8: "sqlite_busy", sqlite3.SQLITE_LOCKED: "sqlite_locked", sqlite3.SQLITE_LOCKED | 1<<8: "sqlite_locked", 1: "other"} {
		if got := selectedSQLiteFailureClass(code); got != want {
			t.Fatalf("unexpected SQLite classification %s", got)
		}
	}
	var runtime *SelectedUploadRuntime
	_, err := runtime.PrepareAndIssue(context.Background(), "", SelectedPrepareRequest{})
	if stage, cause := SelectedPrepareFailureClass(err); stage != "readiness" || cause != "state" {
		t.Fatalf("actual readiness failure was %s/%s", stage, cause)
	}
}

func TestSelectedPrepareFailureClassSQLiteBusy(t *testing.T) {
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "busy.sqlite")) + "?_pragma=busy_timeout(0)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	if _, err = db.Exec("CREATE TABLE diagnostic (value INTEGER)"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec("INSERT INTO diagnostic VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO diagnostic VALUES (2)")
	if err == nil {
		t.Fatal("expected a real SQLite busy error")
	}
	stage, cause := SelectedPrepareFailureClass(&selectedPrepareFailure{stage: "reservation", err: fmt.Errorf("sensitive: %w", err)})
	if stage != "reservation" || cause != "sqlite_busy" {
		t.Fatalf("unexpected SQLite classification %s/%s", stage, cause)
	}
}
