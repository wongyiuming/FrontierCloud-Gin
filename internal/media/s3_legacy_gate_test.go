package media

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type trackedLegacyS3 struct {
	s3Control
	calls int
}

func (c *trackedLegacyS3) Begin(context.Context, string) (store.S3Upload, error) {
	c.calls++
	return store.S3Upload{}, nil
}
func (c *trackedLegacyS3) PartGrant(context.Context, string, int, int64, string) (s3store.Grant, error) {
	c.calls++
	return s3store.Grant{}, nil
}
func (c *trackedLegacyS3) ConfirmPart(context.Context, string, int) (store.S3Upload, error) {
	c.calls++
	return store.S3Upload{}, nil
}
func (c *trackedLegacyS3) Complete(context.Context, string, store.AdminAudit) (store.GlobalMedia, error) {
	c.calls++
	return store.GlobalMedia{}, nil
}
func (c *trackedLegacyS3) Cancel(context.Context, string, store.AdminAudit) (store.S3Upload, error) {
	c.calls++
	return store.S3Upload{}, nil
}
func (c *trackedLegacyS3) Reconcile(context.Context) error { c.calls++; return nil }
func (c *trackedLegacyS3) ReadSource(context.Context, string, string) (s3media.SourceGrant, error) {
	c.calls++
	return s3media.SourceGrant{}, nil
}
func (c *trackedLegacyS3) Generation() uint64 { return 0 }

func TestS3LegacyPathsRejectPersistedTreeBeforeProvider(t *testing.T) {
	_, db, service, _ := s3CatalogFixture(t)
	ctx := context.Background()
	row := publishS3CatalogObject(t, db, "music/S3Fence/song.mp3", nil)
	control := &trackedLegacyS3{}
	service.s3 = control
	if _, err := service.S3BeginUpload(ctx, "legacy"); err != nil || control.calls != 1 {
		t.Fatal("legacy S3 path changed", err)
	}
	if _, err := service.ReadSource(ctx, row.Path, row.ObjectID, true); err != nil || control.calls != 2 {
		t.Fatal("legacy S3 grant changed", err)
	}
	if _, err := db.Database().ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1}); err != nil {
		t.Fatal(err)
	}
	checks := []func() error{
		func() error { _, err := service.S3BeginUpload(ctx, "legacy"); return err },
		func() error { _, err := service.S3PartGrant(ctx, "legacy", 1, 10, "checksum"); return err },
		func() error { _, err := service.S3ConfirmPart(ctx, "legacy", 1); return err },
		func() error { _, err := service.S3CompleteUpload(ctx, "legacy", store.AdminAudit{}); return err },
		func() error { _, err := service.S3CancelUpload(ctx, "legacy", store.AdminAudit{}); return err },
		func() error { return service.ReconcileS3(ctx) },
		func() error { _, err := service.ReadSource(ctx, row.Path, row.ObjectID, true); return err },
		func() error { _, err := service.DeleteGlobal(ctx, []string{row.Path}, store.AdminAudit{}); return err },
		func() error { return service.CancelMasterUpload(ctx, "legacy", store.AdminAudit{}) },
		func() error { return service.RetryGlobalDeletes(ctx) },
		func() error {
			_, err := service.RenameGlobal(ctx, "music/S3Fence", "music/other", store.AdminAudit{})
			return err
		},
		func() error { return service.RetryGlobalRenames(ctx) },
	}
	for i, check := range checks {
		if err := check(); !errors.Is(err, store.ErrNodeState) {
			t.Fatalf("legacy S3 operation %d accepted: %v", i, err)
		}
	}
	if control.calls != 2 {
		t.Fatal("provider reached after tree marker", control.calls)
	}
	got, err := db.Pool().Resource(ctx, row.ID)
	if err != nil || got.State != row.State || got.Path != row.Path {
		t.Fatal("existing S3 object changed", got, err)
	}
}
