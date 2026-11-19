package httpapi

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestSelectedPrepareLogNeverIncludesErrorDetails(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	logSelectedPrepareFailure(errors.New("private-path private-session private-token"))
	got := output.String()
	if strings.Contains(got, "private-") || !strings.Contains(got, `"stage":"other"`) || !strings.Contains(got, `"cause":"other"`) {
		t.Fatalf("unsafe or incomplete log: %s", got)
	}
}
