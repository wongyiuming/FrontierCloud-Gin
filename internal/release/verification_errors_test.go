package release

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSafeVerificationFailureKeepsFactsWithoutRawDetail(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&apiFailure{kind: "rate_limited", retry: 90}, "retry_after_seconds=90"},
		{&apiFailure{kind: "http_status", status: 403}, "http_status=403"},
		{&apiFailure{kind: "network"}, "network request failed"},
		{&apiFailure{kind: "unexpected"}, "response is invalid"},
		{context.DeadlineExceeded, "deadline exceeded"},
		{context.Canceled, "canceled"},
		{errors.New("https://private.invalid/?token=must-not-escape"), "unavailable"},
	} {
		got := SafeVerificationFailure(fmt.Errorf("private must-not-escape: %w", tc.err)).Error()
		if !strings.Contains(got, tc.want) || strings.Contains(got, "must-not-escape") || strings.Contains(got, "https:") {
			t.Fatal(got)
		}
	}
}
