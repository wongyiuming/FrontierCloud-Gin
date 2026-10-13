package operator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func TestReceiptBindsRedisLocationWithoutCredentialRotation(t *testing.T) {
	d, _, runner, _ := upgradeFixture(t)
	service := runner.config.Services["web"]
	service.Environment["REDIS_URL"] = "redis://old:private@cache:6379/2"
	runner.config.Services["web"] = service
	baseline := selectionHash(runner.config)
	for _, value := range []string{"redis://cache:6379/2", "redis://new:rotated@cache/2"} {
		service.Environment["REDIS_URL"] = value
		runner.config.Services["web"] = service
		if selectionHash(runner.config) != baseline {
			t.Fatal("credential rotation changed selection")
		}
	}
	_, receipt, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	receipt.SelectionHash = baseline
	for _, value := range []string{"redis://other:6379/2", "redis://cache:6379/3", "rediss://cache:6379/2"} {
		service.Environment["REDIS_URL"] = value
		runner.config.Services["web"] = service
		if _, e := d.ValidateReceipt(context.Background(), receipt); e == nil {
			t.Fatal("Redis location drift admitted", value)
		}
	}
	if redisLocation("") != redisLocation("redis://redis") {
		t.Fatal("default Redis normalization")
	}
}

type deadlineTransport func(*http.Request) (*http.Response, error)

func (f deadlineTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRetirementRequestsFollowCallerDeadlineAndCancellation(t *testing.T) {
	client, e := NewNodeClient("https://master.invalid")
	if e != nil {
		t.Fatal(e)
	}
	if client.client.Timeout != 0 {
		t.Fatal("shared timeout bounds large scans")
	}
	for _, path := range []string{"/nodes/id/retire/check", "/nodes/id/retire/apply", "/nodes"} {
		var observed context.Context
		client.client.Transport = deadlineTransport(func(r *http.Request) (*http.Response, error) {
			observed = r.Context()
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		})
		if _, e := client.request(context.Background(), "POST", path, "", "", &map[string]any{}); e != nil {
			t.Fatal(e)
		}
		_, bounded := observed.Deadline()
		if bounded == strings.Contains(path, "/retire/") {
			t.Fatal("incorrect request deadline", path, bounded)
		}
		parent, cancel := context.WithTimeout(context.Background(), time.Hour)
		want, _ := parent.Deadline()
		if _, e := client.request(parent, "POST", path, "", "", &map[string]any{}); e != nil {
			t.Fatal(e)
		}
		if strings.Contains(path, "/retire/") {
			got, ok := observed.Deadline()
			if !ok || got != want {
				t.Fatal("caller deadline not retained")
			}
		}
		cancel()
		if !errors.Is(observed.Err(), context.Canceled) {
			t.Fatal("caller cancellation not retained")
		}
	}
}

func TestPublishSetExclusiveCompleteManifestAndTemporaryCleanup(t *testing.T) {
	items, runners := recoverySetFixture(t)
	output := filepath.Join(t.TempDir(), "set")
	report, e := BackupSet(context.Background(), items, output, runners[0].node, true, false)
	if e != nil {
		t.Fatal(e)
	}
	filename := filepath.Join(output, recovery.SetFile)
	original, e := os.ReadFile(filename)
	if e != nil {
		t.Fatal(e)
	}
	var decoded recovery.SetManifest
	if e := json.Unmarshal(original, &decoded); e != nil {
		t.Fatal(e)
	}
	if _, e := recovery.PublishSet(context.Background(), output, report.Manifest); e == nil {
		t.Fatal("replaced existing manifest")
	}
	current, e := os.ReadFile(filename)
	if e != nil || string(current) != string(original) {
		t.Fatal("existing manifest changed", e)
	}
	if e := os.Remove(filename); e != nil {
		t.Fatal(e)
	}
	interrupted := filename + ".next-interrupted"
	if e := os.WriteFile(interrupted, []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	republished, e := recovery.PublishSet(context.Background(), output, report.Manifest)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := recovery.CheckSet(context.Background(), output, republished.SHA256); e != nil {
		t.Fatal(e)
	}
	siblings, e := filepath.Glob(filename + ".next-*")
	if e != nil || len(siblings) != 1 || siblings[0] != interrupted {
		t.Fatal("generated temporary inode leaked", siblings, e)
	}
}
