package business_test

import (
	"context"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSelectedS3PendingProbesAreMemberScoped(t *testing.T) {
	f := newS3SQL(t, true)
	a, b := f.add(t, "selected-a", false), f.add(t, "selected-b", false)
	pa, err := f.repo.S3StartProbe(f.ctx, a.ID, a.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3StartProbe(f.ctx, b.ID, b.Revision, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	reader := f.db.Pool().(interface {
		S3PendingMemberProbes(context.Context, string) ([]store.S3Probe, error)
	})
	probes, err := reader.S3PendingMemberProbes(f.ctx, a.ID)
	if err != nil || len(probes) != 1 || probes[0].ID != pa.ID {
		t.Fatal("member-scoped lookup", probes, err)
	}
	if _, err = reader.S3PendingMemberProbes(f.ctx, "invalid"); err == nil {
		t.Fatal("accepted invalid member")
	}
	if _, err = f.repo.S3FinishProbe(f.ctx, pa.ID, pa.Revision, store.S3ProbeResult{Key: pa.Key, NoMutation: true, CleanupSettled: true, ErrorCode: "s3_denied"}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	probes, err = reader.S3PendingMemberProbes(f.ctx, a.ID)
	if err != nil || len(probes) != 0 {
		t.Fatal("settled probe remained pending", probes, err)
	}
}
