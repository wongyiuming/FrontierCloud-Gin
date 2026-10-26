package s3media

import (
	"context"
	"errors"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Every selected queue simulates a provider consuming its whole sweep context.
// The next sweep must still give each other journal a chance to make progress.
type exhaustedQueues struct {
	*serviceRepository
	cancel context.CancelFunc
	seen   []string
}

func (r *exhaustedQueues) exhaust(phase string, limit int) error {
	if limit != 8 {
		return ErrProof
	}
	r.seen = append(r.seen, phase)
	r.cancel()
	return context.DeadlineExceeded
}
func (r *exhaustedQueues) S3RecoveryUploads(_ context.Context, limit int) ([]store.S3Upload, error) {
	return nil, r.exhaust("uploads", limit)
}
func (r *exhaustedQueues) S3PendingDeletes(_ context.Context, limit int) ([]store.S3Object, error) {
	return nil, r.exhaust("deletes", limit)
}
func (r *exhaustedQueues) S3RecoveryProbes(_ context.Context, limit int) ([]store.S3Probe, error) {
	return nil, r.exhaust("probes", limit)
}

func TestExhaustedRecoveryBudgetCannotStarveOtherJournals(t *testing.T) {
	s, original, _, _, _ := serviceFixture(t)
	r := &exhaustedQueues{serviceRepository: original}
	s.repository = r
	for range 6 {
		ctx, cancel := context.WithCancel(context.Background())
		r.cancel = cancel
		err := s.Reconcile(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("exhausted sweep lost its bounded failure", err)
		}
	}
	want := []string{"uploads", "deletes", "probes", "uploads", "deletes", "probes"}
	if len(r.seen) != len(want) {
		t.Fatal("budget overrun or missing journal admission", r.seen)
	}
	for i := range want {
		if r.seen[i] != want[i] {
			t.Fatal("one unreachable journal permanently starved another", r.seen)
		}
	}
}

func TestProbeRecoveryFailureRetainsIdentityAndRecordsAttempt(t *testing.T) {
	s, r, _, _, _ := serviceFixture(t)
	r.member.SealedCredentials = ""
	intent := store.S3Probe{ID: "probe1", MemberID: "member1", Revision: 7, Key: "probes/member1/probe1", ProviderUploadID: "known-upload", ETag: `"known-etag"`, VersionID: "known-version"}
	if err := s.recoverProbe(context.Background(), intent); err == nil {
		t.Fatal("unusable credentials unexpectedly cleaned provider state")
	}
	if r.probeResult.Key != intent.Key || r.probeResult.ProviderUploadID != intent.ProviderUploadID || r.probeResult.ETag != intent.ETag || r.probeResult.VersionID != intent.VersionID || r.probeResult.ErrorCode == "" || r.probeResult.CleanupSettled || r.probeResult.ChecksPassed {
		t.Fatal("failed recovery lost identity or pretended cleanup", r.probeResult)
	}
}
