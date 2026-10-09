package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture() event {
	return event{Repository: "wongyiuming/FrontierCloud-Gin", Branch: "dev", Event: "push", Conclusion: "success", SHA: strings.Repeat("a", 40), RunID: 100, RunNumber: 10, RunAttempt: 1, Timestamp: 1000}
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	return &receiver{secret: bytes.Repeat([]byte("s"), 32), directory: t.TempDir(), now: func() time.Time { return time.Unix(1000, 0) }}
}

func send(s *receiver, value event, signed bool) *httptest.ResponseRecorder {
	body, _ := json.Marshal(value)
	r := httptest.NewRequest(http.MethodPost, "/staging-ci-success", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if signed {
		mac := hmac.New(sha256.New, s.secret)
		mac.Write(body)
		r.Header.Set("X-FrontierCloud-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestRejectsIneligibleEventsWithoutQueuing(t *testing.T) {
	cases := map[string]func(*event){
		"main":               func(e *event) { e.Branch = "main" },
		"foreign repository": func(e *event) { e.Repository = "other/repo" },
		"PR":                 func(e *event) { e.Event = "pull_request" },
		"failed":             func(e *event) { e.Conclusion = "failure" },
		"cancelled":          func(e *event) { e.Conclusion = "cancelled" },
		"invalid SHA":        func(e *event) { e.SHA = "dev" },
		"expired":            func(e *event) { e.Timestamp = 699 },
		"future":             func(e *event) { e.Timestamp = 1031 },
		"invalid run":        func(e *event) { e.RunID = 0 },
		"invalid number":     func(e *event) { e.RunNumber = 0 },
		"invalid attempt":    func(e *event) { e.RunAttempt = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := newReceiver(t)
			value := fixture()
			mutate(&value)
			if w := send(s, value, true); w.Code != http.StatusBadRequest {
				t.Fatalf("status %d", w.Code)
			}
			files, _ := os.ReadDir(s.directory)
			if len(files) != 0 {
				t.Fatal("ineligible event wrote state")
			}
		})
	}
}

func TestRequiresSignatureAndDetectsTampering(t *testing.T) {
	s := newReceiver(t)
	if w := send(s, fixture(), false); w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status %d", w.Code)
	}
	body, _ := json.Marshal(fixture())
	mac := hmac.New(sha256.New, []byte("wrong secret"))
	mac.Write(body)
	r := httptest.NewRequest(http.MethodPost, "/staging-ci-success", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-FrontierCloud-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("tampered status %d", w.Code)
	}
}

func TestPersistsOnceAndAllowsNewerRunOrRerun(t *testing.T) {
	s := newReceiver(t)
	value := fixture()
	if w := send(s, value, true); w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	pending := filepath.Join(s.directory, "pending.json")
	if _, err := os.Stat(pending); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	// Deduplication survives process restart, not just an in-memory map.
	restarted := &receiver{secret: s.secret, directory: s.directory, now: s.now}
	if w := send(restarted, value, true); w.Code != http.StatusAccepted {
		t.Fatal(w.Code)
	}
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Fatal("replay queued twice")
	}
	value.RunAttempt++
	if w := send(restarted, value, true); w.Code != http.StatusAccepted {
		t.Fatal(w.Code)
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatal("rerun was lost")
	}
	value.RunNumber++
	value.RunID++
	value.RunAttempt = 1
	if w := send(restarted, value, true); w.Code != http.StatusAccepted {
		t.Fatal(w.Code)
	}
	if w := send(restarted, fixture(), true); w.Code != http.StatusAccepted {
		t.Fatal(w.Code)
	}
	raw, err := os.ReadFile(pending)
	if err != nil {
		t.Fatal(err)
	}
	var queued event
	if json.Unmarshal(raw, &queued) != nil || queued.RunNumber != value.RunNumber {
		t.Fatal("old run overwrote newer wakeup")
	}
}

func TestPersistenceErrorsAreNotAcknowledged(t *testing.T) {
	s := newReceiver(t)
	s.directory = filepath.Join(s.directory, "missing")
	if w := send(s, fixture(), true); w.Code != http.StatusServiceUnavailable {
		t.Fatal(w.Code)
	}
}

func TestBoundsBodyAndRequestShape(t *testing.T) {
	s := newReceiver(t)
	for _, tc := range []struct {
		method, path, content, body string
		code                        int
	}{
		{"GET", "/staging-ci-success", "application/json", "", 405},
		{"POST", "/wrong", "application/json", "", 404},
		{"POST", "/staging-ci-success?token=x", "application/json", "", 404},
		{"POST", "/staging-ci-success", "text/plain", "", 415},
		{"POST", "/staging-ci-success", "application/json", strings.Repeat("x", 4097), 413},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.content)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s %s: %d", tc.method, tc.path, w.Code)
		}
	}
}
