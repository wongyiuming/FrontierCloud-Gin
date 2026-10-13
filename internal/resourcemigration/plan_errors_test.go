package resourcemigration

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPlanFailureDiagnosticsUseOnlyAllowlistedCategories(t *testing.T) {
	private := "https://private.example/?credential=secret signed-body"
	for _, tc := range []struct {
		err    error
		reason string
		status int
	}{
		{fmt.Errorf("%s: %w", private, ErrPlanObservation), "facts_mismatch", 0},
		{fmt.Errorf("%s: %w", private, store.ErrMigrationState), "metadata_mismatch", 0},
		{sql.ErrNoRows, "metadata_missing", 0},
		{context.DeadlineExceeded, "deadline_exceeded", 0},
		{context.Canceled, "cancelled", 0},
		{node.ErrAuthentication, "peer_authentication", 0},
		{errors.New("node control HTTPS request failed"), "peer_transport_network", 0},
		{node.ErrRemoteConflict, "peer_transport_http", 409},
		{fmt.Errorf("%s: %w", private, errors.New("node control HTTP 503")), "peer_transport_http", 503},
		{errors.Join(errors.New(private), errors.New("node control response interrupted")), "peer_transport_network", 0},
		{errors.New("invalid node control response"), "peer_response_invalid", 0},
		{errors.New("relationship credential unavailable"), "peer_credential_unavailable", 0},
		{errors.New("node control HTTP 409 " + private), "unclassified", 0},
		{errors.New("node control HTTP 000"), "unclassified", 0},
		{errors.New("node control HTTP +50"), "unclassified", 0},
		{errors.New("node control HTTPS request failed " + private), "unclassified", 0},
		{errors.New(private), "unclassified", 0},
	} {
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))
		failure := &PlanObservationError{Stage: PlanStageSourceInventory, Cause: tc.err}
		reason, status := planFailureDiagnostic(failure)
		if reason != tc.reason || status != tc.status {
			t.Fatalf("controlled category = %s/%d; want %s/%d", reason, status, tc.reason, tc.status)
		}
		logPlanFailure(context.Background(), logger, failure)
		text := output.String()
		if !strings.Contains(text, `"stage":"source_inventory"`) || !strings.Contains(text, `"reason":"`+tc.reason+`"`) {
			t.Fatal("missing controlled diagnosis")
		}
		for _, forbidden := range []string{"private.example", "https://", "credential=", "signed-body", "secret"} {
			if strings.Contains(text, forbidden) {
				t.Fatal("private diagnostics escaped allowlist")
			}
		}
	}
}
