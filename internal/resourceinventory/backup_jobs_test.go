package resourceinventory

import (
	"context"
	"strings"
	"testing"
)

func TestBackupJobsGenerationAndResourceIsolation(t *testing.T) {
	request := contentRequestFixture()
	request.Resource = "backup"
	request.ObjectID = "100"
	jobs, e := NewBackupJobs(context.Background(), func(context.Context, ContentRequest) (ContentObservation, error) {
		return ContentObservation{Path: "backup/100", Bytes: 7, SHA256: strings.Repeat("a", 64)}, nil
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer jobs.Close()
	for _, id := range []string{"0", "-1", "01", "+1", "1.0", "1/../../key", "9223372036854775808", strings.Repeat("0", 64)} {
		bad := request
		bad.ObjectID = id
		if _, e = jobs.Start(bad); e == nil {
			t.Fatal("invalid generation", id)
		}
	}
	bad := request
	bad.Resource = "media"
	bad.ObjectID = strings.Repeat("a", 64)
	if _, e = jobs.Start(bad); e == nil {
		t.Fatal("media accepted by backup worker")
	}
	job, e := jobs.Start(request)
	if e != nil {
		t.Fatal(e)
	}
	job = awaitContentJob(t, jobs, job, "observed")
	if job.Observation == nil || job.Observation.Path != "backup/100" {
		t.Fatal(job)
	}
	media, e := NewContentJobs(context.Background(), func(context.Context, ContentRequest) (ContentObservation, error) {
		t.Fatal("backup admitted by media worker")
		return ContentObservation{}, nil
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer media.Close()
	if _, e = media.Start(request); e == nil {
		t.Fatal("backup accepted by media worker")
	}
}
