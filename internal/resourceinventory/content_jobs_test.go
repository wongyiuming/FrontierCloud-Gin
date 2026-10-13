package resourceinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func contentRequestFixture() ContentRequest {
	return ContentRequest{ID: strings.Repeat("1", 32), Binding: Binding{MemberID: strings.Repeat("2", 32), MasterID: strings.Repeat("3", 32), RelationshipID: strings.Repeat("4", 32), Scope: "data"}, Resource: "media", ObjectID: strings.Repeat("5", 64), MetadataSHA: strings.Repeat("6", 64), Bytes: 7}
}
func awaitContentJob(t *testing.T, jobs *ContentJobs, job ContentJob, state string) ContentJob {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		value, e := jobs.Status(job.Request.ID, job.Incarnation, job.Request.Binding)
		if e != nil {
			t.Fatal(e)
		}
		if value.State == state {
			return value
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("content job did not reach", state)
	return ContentJob{}
}
func TestContentJobsActualBytesBindingReplayAndClose(t *testing.T) {
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if e = root.WriteFile("file.bin", []byte("payload"), 0600); e != nil {
		t.Fatal(e)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	observe := func(ctx context.Context, request ContentRequest) (ContentObservation, error) {
		calls.Add(1)
		close(started)
		select {
		case <-ctx.Done():
			return ContentObservation{}, ctx.Err()
		case <-release:
		}
		if request.MetadataSHA != strings.Repeat("6", 64) {
			return ContentObservation{}, errors.New("metadata version changed")
		}
		return ContentAt(ctx, root, "file.bin", request.Bytes)
	}
	jobs, e := NewContentJobs(context.Background(), observe, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer jobs.Close()
	request := contentRequestFixture()
	job, e := jobs.Start(request)
	if e != nil {
		t.Fatal(e)
	}
	<-started
	repeat, e := jobs.Start(request)
	if e != nil || repeat.Incarnation != job.Incarnation || repeat.ExpiresAt != job.ExpiresAt {
		t.Fatal("replay extended or duplicated observation", repeat, e)
	}
	wrong := request
	wrong.MetadataSHA = strings.Repeat("7", 64)
	if _, e = jobs.Start(wrong); e == nil {
		t.Fatal("same ID changed binding")
	}
	other := request
	other.ID = strings.Repeat("a", 32)
	if _, e = jobs.Start(other); !errors.Is(e, ErrBusy) {
		t.Fatal("parallel observation", e)
	}
	binding := request.Binding
	binding.MasterID = strings.Repeat("f", 32)
	if _, e = jobs.Status(job.Request.ID, job.Incarnation, binding); e == nil {
		t.Fatal("foreign result access")
	}
	close(release)
	done := awaitContentJob(t, jobs, job, "observed")
	sha := sha256.Sum256([]byte("payload"))
	if calls.Load() != 1 || done.Observation.SHA256 != hex.EncodeToString(sha[:]) {
		t.Fatal(done, calls.Load())
	}
	done.Observation.SHA256 = "tampered-client-copy"
	again, e := jobs.Status(job.Request.ID, job.Incarnation, job.Request.Binding)
	if e != nil || again.Observation.SHA256 == done.Observation.SHA256 {
		t.Fatal("mutable returned result", again, e)
	}
	// A new process has no inherited success, even for an identical request ID.
	restarted, e := NewContentJobs(context.Background(), func(ctx context.Context, r ContentRequest) (ContentObservation, error) {
		return ContentAt(ctx, root, "file.bin", r.Bytes)
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	fresh, e := restarted.Start(request)
	if e != nil || fresh.Incarnation == job.Incarnation {
		t.Fatal("restart reused incarnation", fresh, e)
	}
	if _, e = restarted.Status(request.ID, job.Incarnation, request.Binding); e == nil {
		t.Fatal("old result accepted after restart")
	}
	awaitContentJob(t, restarted, fresh, "observed")
	jobs.Close()
	if _, e = jobs.Start(other); e == nil {
		t.Fatal("closed worker accepted request")
	}
	if _, e = root.Stat("file.bin"); e != nil {
		t.Fatal("worker closed borrowed root", e)
	}
}
func TestContentJobsCancellationExpiryAndSanitizedFailure(t *testing.T) {
	var offset atomic.Int64
	epoch := time.Now()
	now := func() time.Time { return epoch.Add(time.Duration(offset.Load()) * time.Second) }
	started := make(chan struct{}, 2)
	jobs, e := NewContentJobs(context.Background(), func(ctx context.Context, r ContentRequest) (ContentObservation, error) {
		started <- struct{}{}
		<-ctx.Done()
		return ContentObservation{}, errors.New("private diagnostic must not reach caller")
	}, now)
	if e != nil {
		t.Fatal(e)
	}
	defer jobs.Close()
	request := contentRequestFixture()
	job, e := jobs.Start(request)
	if e != nil {
		t.Fatal(e)
	}
	<-started
	canceled, e := jobs.Cancel(request.ID, job.Incarnation, request.Binding)
	if e != nil || canceled.Observation != nil {
		t.Fatal(canceled, e)
	}
	awaitContentJob(t, jobs, job, "cancelled")
	request.ID = strings.Repeat("a", 32)
	job, e = jobs.Start(request)
	if e != nil {
		t.Fatal(e)
	}
	<-started
	offset.Store(int64(SessionTTL/time.Second) + 1)
	expired, e := jobs.Status(request.ID, job.Incarnation, request.Binding)
	if e != nil || expired.State != "expired" || expired.Observation != nil {
		t.Fatal(expired, e)
	}
	jobs.Close()
	failed, e := NewContentJobs(context.Background(), func(context.Context, ContentRequest) (ContentObservation, error) {
		return ContentObservation{}, errors.New("private diagnostic")
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer failed.Close()
	request = contentRequestFixture()
	job, e = failed.Start(request)
	if e != nil {
		t.Fatal(e)
	}
	value := awaitContentJob(t, failed, job, "failed")
	if value.ErrorCode != "content_observation_failed" || value.Observation != nil || strings.Contains(value.ErrorCode, "private") {
		t.Fatal("unsafe failure", value)
	}
	request.ID = strings.Repeat("b", 32)
	request.Resource = "backup"
	if _, e = failed.Start(request); e == nil {
		t.Fatal("unmanaged resource")
	}
}
