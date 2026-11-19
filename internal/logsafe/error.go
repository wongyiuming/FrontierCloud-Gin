// Package logsafe provides bounded error categories without recording paths,
// credential-bearing URLs or other text carried by an underlying error.
package logsafe

import (
	"context"
	"errors"
	"os"
)

func ErrorType(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, os.ErrNotExist):
		return "not_found"
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, os.ErrExist):
		return "already_exists"
	default:
		return "internal"
	}
}
