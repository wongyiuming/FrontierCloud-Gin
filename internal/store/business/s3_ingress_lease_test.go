package business_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Configuration and probe state are control-plane writes; provider network
// operations and high-frequency object accounting are not run under this gate.
func TestS3ControlWritesWaitForIngressAdmission(t *testing.T) {
	for _, operation := range []string{"add", "configure", "recovery", "remove", "start-probe", "finish-probe", "fail-probe"} {
		t.Run(operation, func(t *testing.T) {
			f := newS3SQL(t, true)
			member := f.add(t, "existing", false)
			var probe store.S3Probe
			if operation == "finish-probe" {
				var err error
				probe, err = f.repo.S3StartProbe(f.ctx, member.ID, member.Revision, store.NodeAudit{})
				if err != nil {
					t.Fatal(err)
				}
			}
			routing := f.db.Nodes().(store.PublicRoutingRepository)
			if err := routing.ConfigurePublicOrigin("https://master.test"); err != nil {
				t.Fatal(err)
			}
			_, lease, err := routing.AcquireCurrentIngress(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			before, err := f.repo.S3Member(f.ctx, member.ID)
			if err != nil {
				t.Fatal(err)
			}
			attempt := func(ctx context.Context) error {
				switch operation {
				case "add":
					_, err := f.repo.S3AddMember(ctx, s3SQLConfig("another"), store.NodeAudit{})
					return err
				case "configure":
					c := s3SQLConfig("existing")
					c.SealedCredentials = nil
					c.Name = "new name"
					_, err := f.repo.S3ConfigureMember(ctx, member.ID, member.Revision, c, store.NodeAudit{})
					return err
				case "recovery":
					_, err := f.repo.S3RecoveryCredentials(ctx, member.ID, member.Revision, "replacement", 0, store.NodeAudit{})
					return err
				case "remove":
					return f.repo.S3RemoveMember(ctx, member.ID, member.Revision, store.NodeAudit{})
				case "start-probe":
					_, err := f.repo.S3StartProbe(ctx, member.ID, member.Revision, store.NodeAudit{})
					return err
				case "finish-probe":
					_, err := f.repo.S3FinishProbe(ctx, probe.ID, probe.Revision, store.S3ProbeResult{Key: probe.Key, ProviderUploadID: "probe-upload", VersionID: "probe-version", ETag: "probe-etag", ChecksPassed: true, CleanupSettled: true}, store.NodeAudit{})
					return err
				case "fail-probe":
					_, err := f.repo.S3ProbeMember(ctx, member.ID, member.Revision, "failed", store.NodeAudit{})
					return err
				}
				panic("unknown operation")
			}
			blocked, cancel := context.WithTimeout(f.ctx, 200*time.Millisecond)
			err = attempt(blocked)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("control write bypassed held ingress lease: %v", err)
			}
			after, err := f.repo.S3Member(f.ctx, member.ID)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatalf("member changed while lease held: before=%+v after=%+v err=%v", before, after, err)
			}
			if err = lease.Commit(); err != nil {
				t.Fatal(err)
			}
			if err = attempt(f.ctx); err != nil {
				t.Fatalf("control write did not proceed after release: %v", err)
			}
		})
	}
}
