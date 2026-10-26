package business_test

import (
	"errors"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestS3SQLProbeNoMutationClearsOnlyUnusedGrant(t *testing.T) {
	f := newS3SQL(t, true)
	member := f.add(t, "probe-known-rejection", false)
	finishDenied := func() {
		t.Helper()
		probe, err := f.repo.S3StartProbe(f.ctx, member.ID, member.Revision, store.NodeAudit{})
		if err != nil {
			t.Fatal(err)
		}
		if probe.GrantUntil <= time.Now().Unix() {
			t.Fatal("fixture lacks a live initial horizon")
		}
		member, err = f.repo.S3FinishProbe(f.ctx, probe.ID, probe.Revision, store.S3ProbeResult{Key: probe.Key, NoMutation: true, CleanupSettled: true, ErrorCode: "s3_denied"}, store.NodeAudit{})
		if err != nil {
			t.Fatal(err)
		}
		var state, uid, version, etag string
		var until int64
		if err = f.raw.QueryRow("SELECT state,provider_upload_id,version_id,etag,grant_until FROM s3_probe_journal WHERE probe_id=?", probe.ID).Scan(&state, &uid, &version, &etag, &until); err != nil {
			t.Fatal(err)
		}
		if state != "settled" || uid != "" || version != "" || etag != "" || until != 0 || member.ProbeState != "failed" || member.ProbeRevision != 0 {
			t.Fatal("known rejection retained a fictitious bearer or probe confidence", state, uid, version, etag, until, member)
		}
	}
	finishDenied()
	var err error
	member, err = f.repo.S3RecoveryCredentials(f.ctx, member.ID, member.Revision, "recovery-sealed", 0, store.NodeAudit{})
	if err != nil || !member.CleanupOnly {
		t.Fatal("known rejection unnecessarily blocked recovery credentials", member, err)
	}
	cfg := s3SQLConfig("probe-known-rejection")
	sealed := "corrected-sealed"
	cfg.SealedCredentials = &sealed
	member, err = f.repo.S3ConfigureMember(f.ctx, member.ID, member.Revision, cfg, store.NodeAudit{})
	if err != nil || member.SealedCredentials != sealed || member.Enabled != 0 || member.CleanupOnly || member.ProbeState != "unchecked" {
		t.Fatal("known rejection unnecessarily blocked a corrected key", member, err)
	}
	finishDenied()
	if err = f.repo.S3RemoveMember(f.ctx, member.ID, member.Revision, store.NodeAudit{}); err != nil {
		t.Fatal("known rejection unnecessarily delayed removal", err)
	}
}

func TestS3SQLProbeNoMutationRetainsUncertainOrExistingGrant(t *testing.T) {
	cases := []struct {
		name    string
		initial *store.S3ProbeResult
		result  store.S3ProbeResult
	}{
		{name: "unknown_create", result: store.S3ProbeResult{ErrorCode: "s3_network"}},
		{name: "cleanup_not_settled", result: store.S3ProbeResult{NoMutation: true, ErrorCode: "s3_denied"}},
		{name: "result_upload_id", result: store.S3ProbeResult{NoMutation: true, CleanupSettled: true, ProviderUploadID: "provider-upload", ErrorCode: "s3_denied"}},
		{name: "result_version", result: store.S3ProbeResult{NoMutation: true, CleanupSettled: true, VersionID: "provider-version", ErrorCode: "s3_denied"}},
		{name: "result_etag", result: store.S3ProbeResult{NoMutation: true, CleanupSettled: true, ETag: "provider-etag", ErrorCode: "s3_denied"}},
		{name: "persisted_provider_identity", initial: &store.S3ProbeResult{ProviderUploadID: "persisted-upload", VersionID: "persisted-version", ETag: "persisted-etag", ErrorCode: "probe_cleanup_pending"}, result: store.S3ProbeResult{NoMutation: true, CleanupSettled: true, ErrorCode: "s3_denied"}},
		{name: "successful_probe", result: store.S3ProbeResult{ChecksPassed: true, CleanupSettled: true, ProviderUploadID: "successful-upload"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newS3SQL(t, true)
			member := f.add(t, "probe-retained-horizon", false)
			probe, err := f.repo.S3StartProbe(f.ctx, member.ID, member.Revision, store.NodeAudit{})
			if err != nil {
				t.Fatal(err)
			}
			if test.initial != nil {
				proof := *test.initial
				proof.Key = probe.Key
				if _, err = f.repo.S3FinishProbe(f.ctx, probe.ID, probe.Revision, proof, store.NodeAudit{}); err != nil {
					t.Fatal(err)
				}
			}
			proof := test.result
			proof.Key = probe.Key
			member, err = f.repo.S3FinishProbe(f.ctx, probe.ID, probe.Revision, proof, store.NodeAudit{})
			if err != nil {
				t.Fatal(err)
			}
			var until int64
			if err = f.raw.QueryRow("SELECT grant_until FROM s3_probe_journal WHERE probe_id=?", probe.ID).Scan(&until); err != nil {
				t.Fatal(err)
			}
			if until != probe.GrantUntil || until <= time.Now().Unix() {
				t.Fatal("uncertain or known authorization lost its real horizon", until, probe.GrantUntil)
			}
			if _, err = f.repo.S3RecoveryCredentials(f.ctx, member.ID, member.Revision, "replacement-sealed", 0, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
				t.Fatal("live authorization allowed credential replacement", err)
			}
			if err = f.repo.S3RemoveMember(f.ctx, member.ID, member.Revision, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
				t.Fatal("live authorization allowed member removal", err)
			}
		})
	}
}

func TestS3SQLProbeNoMutationCannotRewriteSettledHistory(t *testing.T) {
	f := newS3SQL(t, true)
	member := f.add(t, "probe-settled-history", false)
	probe, err := f.repo.S3StartProbe(f.ctx, member.ID, member.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	// Model a settled all-empty record written by the preceding runtime. Only
	// its state/code are seeded; the genuine StartProbe deadline is untouched.
	if _, err = f.raw.Exec("UPDATE s3_probe_journal SET state='settled',error_code='s3_denied' WHERE probe_id=?", probe.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3FinishProbe(f.ctx, probe.ID, probe.Revision, store.S3ProbeResult{Key: probe.Key, NoMutation: true, CleanupSettled: true, ErrorCode: "s3_denied"}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	var until int64
	if err = f.raw.QueryRow("SELECT grant_until FROM s3_probe_journal WHERE probe_id=?", probe.ID).Scan(&until); err != nil {
		t.Fatal(err)
	}
	if until != probe.GrantUntil || until <= time.Now().Unix() {
		t.Fatal("late replay rewrote settled authorization history", until, probe.GrantUntil)
	}
}
