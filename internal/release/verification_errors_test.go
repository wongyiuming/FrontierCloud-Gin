package release

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
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

func TestVerificationHTTPPreservesInFlightCancellationAndTimeout(t *testing.T) {
	for _, kind := range []string{"cancel", "context-timeout", "client-timeout"} {
		t.Run(kind, func(t *testing.T) {
			started := make(chan struct{})
			v := verifierFixture(t, func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-r.Context().Done()
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			want, text := context.DeadlineExceeded, "deadline exceeded"
			if kind == "cancel" {
				want, text = context.Canceled, "canceled"
				go func() { <-started; cancel() }()
			} else if kind == "client-timeout" {
				v.client.Timeout = 100 * time.Millisecond
			} else {
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			_, err := v.get(ctx, "/fixture", &map[string]any{})
			if !errors.Is(err, want) || !strings.Contains(SafeVerificationFailure(err).Error(), text) {
				t.Fatal("HTTP cause lost", err, SafeVerificationFailure(err))
			}
		})
	}
}
