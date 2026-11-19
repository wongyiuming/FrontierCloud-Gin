package s3media

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type selectedProbeRepository struct {
	store.S3Repository
	pending []store.S3Probe
}

func (r *selectedProbeRepository) S3PendingMemberProbes(_ context.Context, id string) ([]store.S3Probe, error) {
	if id != "member1" {
		return nil, ErrUnavailable
	}
	return r.pending, nil
}

func (r *selectedProbeRepository) S3FinishProbe(ctx context.Context, id string, revision int64, result store.S3ProbeResult, audit store.NodeAudit) (store.S3Member, error) {
	if result.CleanupSettled && result.ErrorCode == "probe_recovered" {
		r.pending = nil
	}
	return r.S3Repository.S3FinishProbe(ctx, id, revision, result, audit)
}

type selectedProbeFixture struct {
	*serviceProvider
	repo   *serviceRepository
	failed bool
	aborts int
}

func (p *selectedProbeFixture) Abort(_ context.Context, key, id string) error {
	if key != "probes/member1/old" || id != "old-upload" {
		return ErrProof
	}
	p.aborts++
	return nil
}

func (p *selectedProbeFixture) TestKeyWithCheckpointOrigins(_ context.Context, origins []string, key string, checkpoint func(string) error) (s3store.TestReport, error) {
	if !p.repo.probeStarted || len(origins) != 2 || origins[0] != "https://admin.example" || origins[1] != "https://public.example" || key != "probes/member1/probe1" {
		return s3store.TestReport{}, ErrProof
	}
	report := s3store.TestReport{ProbeKey: key, UploadID: "provider-upload", Cleanup: true}
	if err := checkpoint(report.UploadID); err != nil {
		return report, err
	}
	if p.failed {
		return report, s3store.ErrCORS
	}
	report.Read, report.Head, report.Write, report.Delete, report.Multipart, report.Range, report.CORS = true, true, true, true, true, true, true
	return report, nil
}

func TestSelectedProbeJournalsBothOriginsBeforeReadiness(t *testing.T) {
	for _, failed := range []bool{false, true} {
		s, repo, provider, _, _ := serviceFixture(t)
		s.repository = &selectedProbeRepository{S3Repository: repo}
		fixture := &selectedProbeFixture{serviceProvider: provider, repo: repo, failed: failed}
		s.factory = func(s3store.Config, s3store.Credentials) (s3store.Provider, func(), error) {
			return fixture, func() {}, nil
		}
		_, err := s.ProbeSelected(context.Background(), "member1", 1, "https://admin.example", "https://public.example", store.NodeAudit{})
		if failed {
			if !errors.Is(err, s3store.ErrCORS) || repo.probeResult.ChecksPassed {
				t.Fatal("one denied origin marked ready", err)
			}
		} else if err != nil || !repo.probeResult.ChecksPassed || !repo.probeResult.CleanupSettled || len(repo.probeCheckpoints) != 1 {
			t.Fatal("two origin proof not journaled", err)
		}
	}
}

func TestSelectedProbeWillNotRepeatUnsettledCreate(t *testing.T) {
	s, repo, provider, _, _ := serviceFixture(t)
	wrapped := &selectedProbeRepository{S3Repository: repo, pending: []store.S3Probe{{MemberID: "member1", GrantUntil: time.Now().Add(time.Minute).Unix()}}}
	s.repository = wrapped
	fixture := &selectedProbeFixture{serviceProvider: provider, repo: repo}
	s.factory = func(s3store.Config, s3store.Credentials) (s3store.Provider, func(), error) {
		return fixture, func() {}, nil
	}
	if _, err := s.ProbeSelected(context.Background(), "member1", 1, "https://admin.example", "https://public.example", store.NodeAudit{}); !errors.Is(err, ErrPending) || repo.probeStarted {
		t.Fatal("live old probe allowed another create", err)
	}
	wrapped.pending = []store.S3Probe{{MemberID: "other", GrantUntil: time.Now().Add(time.Minute).Unix()}}
	if _, err := s.ProbeSelected(context.Background(), "member1", 1, "https://admin.example", "https://public.example", store.NodeAudit{}); err == nil || repo.probeStarted {
		t.Fatal("another member's probe accepted", err)
	}
}

func TestSelectedProbeRecoversExactOwnedJournal(t *testing.T) {
	s, repo, provider, _, _ := serviceFixture(t)
	wrapped := &selectedProbeRepository{S3Repository: repo, pending: []store.S3Probe{{ID: "old", MemberID: "member1", Revision: 1, Key: "probes/member1/old", ProviderUploadID: "old-upload", GrantUntil: time.Now().Add(-time.Second).Unix()}}}
	s.repository = wrapped
	provider.list = func(context.Context, string, string) ([]s3store.Part, error) { return nil, s3store.ErrNotFound }
	provider.head = func(context.Context, string, string) (s3store.Proof, error) {
		return s3store.Proof{}, s3store.ErrNotFound
	}
	fixture := &selectedProbeFixture{serviceProvider: provider, repo: repo}
	s.factory = func(s3store.Config, s3store.Credentials) (s3store.Provider, func(), error) {
		return fixture, func() {}, nil
	}
	if _, err := s.ProbeSelected(context.Background(), "member1", 1, "https://admin.example", "https://public.example", store.NodeAudit{}); err != nil || fixture.aborts != 1 || len(wrapped.pending) != 0 || !repo.probeStarted {
		t.Fatal("exact journal recovery", err)
	}
}
