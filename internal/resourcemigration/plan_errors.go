package resourcemigration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Only stable categories and a strictly parsed HTTP status may leave this
// classifier. Do not log error.Error(), underlying causes, endpoints or bodies.
func planFailureDiagnostic(err error) (reason string, status int) {
	switch {
	case errors.Is(err, ErrPlanObservation):
		return "facts_mismatch", 0
	case errors.Is(err, store.ErrMigrationState):
		return "metadata_mismatch", 0
	case errors.Is(err, sql.ErrNoRows):
		return "metadata_missing", 0
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded", 0
	case errors.Is(err, context.Canceled):
		return "cancelled", 0
	case errors.Is(err, node.ErrAuthentication):
		return "peer_authentication", 0
	case errors.Is(err, store.ErrMigrationInventoryLimit):
		return "catalog_limit", 0
	}
	var syntax *json.SyntaxError
	var mismatch *json.UnmarshalTypeError
	if errors.As(err, &syntax) || errors.As(err, &mismatch) {
		return "peer_response_invalid", 0
	}
	return planTransportDiagnostic(err, 0)
}

func planTransportDiagnostic(err error, depth int) (string, int) {
	if err == nil || depth > 16 {
		return "unclassified", 0
	}
	// Current node transport intentionally emits sanitized literal errors.
	// Match whole literals only; unknown errors must never be echoed.
	message := err.Error()
	switch message {
	case "node control HTTPS request failed", "node control response interrupted":
		return "peer_transport_network", 0
	case "node control response too large", "invalid node control response", "invalid signed envelope":
		return "peer_response_invalid", 0
	case "relationship credential unavailable":
		return "peer_credential_unavailable", 0
	case "control message too large", "invalid control request", "only versioned control endpoints are permitted":
		return "peer_request_invalid", 0
	}
	const prefix = "node control HTTP "
	if len(message) == len(prefix)+3 && strings.HasPrefix(message, prefix) {
		raw := message[len(prefix):]
		if raw[0] >= '1' && raw[0] <= '5' && raw[1] >= '0' && raw[1] <= '9' && raw[2] >= '0' && raw[2] <= '9' {
			status, _ := strconv.Atoi(raw)
			return "peer_transport_http", status
		}
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if reason, status := planTransportDiagnostic(cause, depth+1); reason != "unclassified" {
				return reason, status
			}
		}
	} else if cause := errors.Unwrap(err); cause != nil {
		return planTransportDiagnostic(cause, depth+1)
	}
	return "unclassified", 0
}

func logPlanFailure(ctx context.Context, logger *slog.Logger, err error) {
	reason, status := planFailureDiagnostic(err)
	logger.WarnContext(ctx, "migration_plan_failed", "stage", planErrorStage(err), "reason", reason, "http_status", status)
}
