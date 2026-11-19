package business

import (
	"context"
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// selectedPrepareFailure preserves the original error text and chain for
// callers while attaching a fixed, non-sensitive diagnostic stage.
type selectedPrepareFailure struct {
	stage string
	err   error
}

func (e *selectedPrepareFailure) Error() string { return e.err.Error() }
func (e *selectedPrepareFailure) Unwrap() error { return e.err }

// SelectedPrepareFailureClass exposes only fixed values suitable for logs.
func SelectedPrepareFailureClass(err error) (string, string) {
	stage := "other"
	var failure *selectedPrepareFailure
	if errors.As(err, &failure) {
		switch failure.stage {
		case "readiness", "input", "path", "prepare_proof", "policy", "directory", "pending", "reservation", "scope", "capability":
			stage = failure.stage
		}
	}
	cause := "other"
	var sqliteErr *sqlite.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		cause = "deadline"
	case errors.Is(err, context.Canceled):
		cause = "cancelled"
	case errors.Is(err, sealedtree.ErrFenceChanged):
		cause = "fence_changed"
	case errors.Is(err, sealedtree.ErrConflict):
		cause = "conflict"
	case errors.Is(err, sealedtree.ErrInvalid):
		cause = "invalid"
	case errors.As(err, &sqliteErr):
		cause = selectedSQLiteFailureClass(sqliteErr.Code())
	case errors.Is(err, store.ErrStorageCapacity):
		cause = "capacity"
	case errors.Is(err, store.ErrNodeState):
		cause = "state"
	}
	return stage, cause
}

func selectedSQLiteFailureClass(code int) string {
	switch code & 0xff {
	case sqlite3.SQLITE_BUSY:
		return "sqlite_busy"
	case sqlite3.SQLITE_LOCKED:
		return "sqlite_locked"
	default:
		return "other"
	}
}
