package media

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type mediaS3Control struct {
	s3Control
	generation atomic.Uint64
	reads      atomic.Int64
	deletes    atomic.Int64
	read       func(context.Context, string, string) (s3media.SourceGrant, error)
	remove     func(context.Context, string, store.AdminAudit) error
	complete   func(context.Context, string, store.AdminAudit) (store.GlobalMedia, error)
	cancel     func(context.Context, string, store.AdminAudit) (store.S3Upload, error)
	reconcile  func(context.Context) error
}

func (c *mediaS3Control) Generation() uint64 { return c.generation.Load() }
func (c *mediaS3Control) ReadSource(ctx context.Context, id, name string) (s3media.SourceGrant, error) {
	c.reads.Add(1)
	if c.read != nil {
		return c.read(ctx, id, name)
	}
	return s3media.SourceGrant{ObjectID: id, SizeBytes: 128, GET: s3store.Grant{URL: "https://object-store.example.test/get", Headers: map[string]string{"If-Match": `"owned-etag"`}, ExpiresAt: time.Now().Unix() + 299}, HEAD: s3store.Grant{URL: "https://object-store.example.test/head", Headers: map[string]string{"If-Match": `"owned-etag"`}, ExpiresAt: time.Now().Unix() + 298}}, nil
}
func (c *mediaS3Control) Delete(ctx context.Context, id string, a store.AdminAudit) error {
	c.deletes.Add(1)
	if c.remove != nil {
		return c.remove(ctx, id, a)
	}
	return s3media.ErrPending
}
func (c *mediaS3Control) Complete(ctx context.Context, id string, a store.AdminAudit) (store.GlobalMedia, error) {
	if c.complete != nil {
		return c.complete(ctx, id, a)
	}
	return store.GlobalMedia{}, store.ErrNodeState
}
func (c *mediaS3Control) Cancel(ctx context.Context, id string, a store.AdminAudit) (store.S3Upload, error) {
	if c.cancel != nil {
		return c.cancel(ctx, id, a)
	}
	return store.S3Upload{}, store.ErrNodeState
}
func (c *mediaS3Control) Reconcile(ctx context.Context) error {
	if c.reconcile != nil {
		return c.reconcile(ctx)
	}
	return nil
}

type forbiddenS3Reader struct{ calls int }

func (r *forbiddenS3Reader) Read([]byte) (int, error) {
	r.calls++
	return 0, errors.New("Master must never consume S3 payload")
}

func TestS3MediaTicketAndNativePayloadPathsStaySeparate(t *testing.T) {
	root, db, service, _ := s3CatalogFixture(t)
	ctx := context.Background()
	control := &mediaS3Control{}
	service.s3 = control
	ticket, err := service.ReserveMasterUpload(ctx, "a.mp3", "music/S3Ticket", "", "s3", 128, 255, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Transport != "S3" || ticket.Site != "s3" || ticket.MemberID != "" || ticket.URL != "/api/v1/media/admin/upload/s3/"+ticket.ID {
		t.Fatal("native ticket leaked into S3", ticket)
	}
	reader := &forbiddenS3Reader{}
	if _, err = service.UploadMasterBytes(ctx, ticket.ID, reader, store.AdminAudit{}); !errors.Is(err, ErrBrowserSource) || reader.calls != 0 {
		t.Fatal("S3 bytes read by Master", reader.calls, err)
	}
	if _, err = os.Stat(filepath.Join(root, ticket.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("S3 reservation created local media", err)
	}
	calledComplete, calledCancel := false, false
	control.complete = func(_ context.Context, id string, _ store.AdminAudit) (store.GlobalMedia, error) {
		calledComplete = id == ticket.ID
		return store.GlobalMedia{ID: ticket.MediaID, Path: ticket.Path}, nil
	}
	if result, err := service.FinalizeMasterUpload(ctx, ticket.ID, store.AdminAudit{}); err != nil || !calledComplete || result.MediaID != ticket.MediaID {
		t.Fatal("S3 finalize entered native peer", result, err)
	}
	control.cancel = func(ctx context.Context, id string, a store.AdminAudit) (store.S3Upload, error) {
		calledCancel = id == ticket.ID
		u, err := db.Pool().(store.S3Repository).S3RequestAbort(ctx, id, a)
		if err != nil {
			return u, err
		}
		return u, s3media.ErrPending
	}
	if err = service.CancelMasterUpload(ctx, ticket.ID, store.AdminAudit{}); !errors.Is(err, s3media.ErrPending) || !calledCancel {
		t.Fatal("S3 cancel entered native peer", err)
	}
	u, err := db.Pool().(store.S3Repository).S3Upload(ctx, ticket.ID)
	if err != nil || u.State != "aborting" || u.Reservation.State != "reserved" {
		t.Fatal("pending cleanup was discarded", u, err)
	}
	service.ConfigureS3(nil)
	if _, err = service.ReserveMasterUpload(ctx, "b.mp3", "music/S3Ticket", "", "s3", 128, 255, store.AdminAudit{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unconfigured provider accepted reservation", err)
	}
}

func TestS3SourceAuthorizationBindsVisibilityPathObjectAndEncryption(t *testing.T) {
	_, db, service, _ := s3CatalogFixture(t)
	ctx := context.Background()
	row := publishS3CatalogObject(t, db, "music/S3Source/plain.mp3", nil)
	control := &mediaS3Control{}
	service.s3 = control
	if _, err := service.PlaintextSource(ctx, row.Path, "", false); !errors.Is(err, ErrPath) {
		t.Fatal("missing immutable ID signed", err)
	}
	if _, err := service.PlaintextSource(ctx, row.Path, strings.Repeat("f", 64), false); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong immutable ID signed", err)
	}
	if control.reads.Load() != 0 {
		t.Fatal("provider reached before authorization")
	}
	grant, err := service.PlaintextSource(ctx, row.Path, row.ObjectID, false)
	if err != nil || grant.ObjectID != row.ID || grant.GET.Headers["If-Match"] != `"owned-etag"` || grant.HEAD.URL == grant.GET.URL {
		t.Fatal("lost source identity/headers", grant, err)
	}
	if err = service.Hide(ctx, []string{row.Path}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	before := control.reads.Load()
	if _, err = service.ReadSource(ctx, row.Path, row.ObjectID, false); !errors.Is(err, os.ErrNotExist) || control.reads.Load() != before {
		t.Fatal("hidden S3 source signed", err)
	}
	if _, err = service.ReadSource(ctx, row.Path, row.ObjectID, true); err != nil {
		t.Fatal("Admin source authorization lost", err)
	}
	meta, err := mediacrypto.NewMetadata(128)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := publishS3CatalogObject(t, db, "music/S3EncryptedSource/secure.mp3", &meta)
	before = control.reads.Load()
	if _, err = service.PlaintextSource(ctx, encrypted.Path, encrypted.ObjectID, true); !errors.Is(err, ErrPath) || control.reads.Load() != before {
		t.Fatal("ciphertext exposed by plaintext grant", err)
	}
	if _, err = service.ReadSource(ctx, encrypted.Path, encrypted.ObjectID, true); err != nil {
		t.Fatal("encrypted source grant unavailable", err)
	}
	object, err := service.CryptoObject(ctx, "music/artist/song.mp3", "", true)
	if err != nil {
		t.Fatal(err)
	}
	before = control.reads.Load()
	if grant, err = service.ReadSource(ctx, object.Path, object.ID, true); err != nil || grant.ObjectID != "" || control.reads.Load() != before {
		t.Fatal("native source required S3", grant, err)
	}
	if _, err = service.PlaintextSource(ctx, object.Path, object.ID, true); !errors.Is(err, ErrPath) {
		t.Fatal("native object accepted S3-only source", err)
	}
}

func TestS3DownloadPlanCarriesBrowserIdentityAndCannotRelayPayload(t *testing.T) {
	root, db, service, _ := s3CatalogFixture(t)
	ctx := context.Background()
	row := publishS3CatalogObject(t, db, "music/S3Download/one.mp3", nil)
	publishS3CatalogObject(t, db, "music/S3Download/two.mp3", nil)
	// An unrelated local shadow can never become an S3 payload fallback.
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, row.Path)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, row.Path), bytes.Repeat([]byte("x"), 128), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Delivery(ctx, row.Path, row.ID, "", "", false); !errors.Is(err, ErrBrowserSource) {
		t.Fatal("S3 stream fell back to local or redirect", err)
	}
	download, err := service.Download(ctx, []string{row.Path})
	if err != nil {
		t.Fatal(err)
	}
	defer download.Close()
	if !download.RequiresBrowserSource() {
		t.Fatal("S3 pre-audit browser requirement missing")
	}
	native, err := service.Download(ctx, []string{"music/artist/song.mp3"})
	if err != nil {
		t.Fatal(err)
	}
	if native.RequiresBrowserSource() {
		native.Close()
		t.Fatal("native download required browser source")
	}
	native.Close()
	entries, err := download.BrowserPlan(1)
	if err != nil || len(entries) != 1 || entries[0].Transport != "S3" || entries[0].ObjectID != row.ObjectID || entries[0].Bytes != 128 || entries[0].URL != "" {
		t.Fatal("browser plan lost S3 snapshot", entries, err)
	}
	if _, err = download.PlanDelivery(row.ID, entries[0].Snapshot, "", "", false); !errors.Is(err, ErrBrowserSource) {
		t.Fatal("plan bytes exposed URL-only/native payload", err)
	}
	if _, _, err = download.Open(row.Path); !errors.Is(err, ErrBrowserSource) {
		t.Fatal("local shadow substituted S3 payload", err)
	}
	var payload bytes.Buffer
	if err = download.ZIP(&payload); !errors.Is(err, ErrBrowserSource) || payload.Len() != 0 {
		t.Fatal("Master began S3 ZIP relay", payload.Len(), err)
	}
	if _, err = download.globalSource(row); !errors.Is(err, ErrBrowserSource) {
		t.Fatal("Master opened S3 data plane", err)
	}
	download.Close()
	directory, err := service.Download(ctx, []string{"music/S3Download"})
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if entries, err := directory.BrowserPlan(1); !errors.Is(err, ErrUploadSize) || len(entries) != 0 {
		t.Fatal("oversize S3 plan fell back to server ZIP", entries, err)
	}
}

func TestS3MutationFenceKeepsSourceStableAndRenameMetadataOnly(t *testing.T) {
	root, db, service, _ := s3CatalogFixture(t)
	ctx := context.Background()
	row := publishS3CatalogObject(t, db, "music/S3Fence/one.mp3", nil)
	original, err := db.Pool().(store.S3Repository).S3Object(ctx, row.ID)
	if err != nil {
		t.Fatal(err)
	}
	started, finish := make(chan struct{}), make(chan struct{})
	control := &mediaS3Control{read: func(ctx context.Context, id, name string) (s3media.SourceGrant, error) {
		close(started)
		select {
		case <-finish:
			return s3media.SourceGrant{ObjectID: id}, nil
		case <-ctx.Done():
			return s3media.SourceGrant{}, ctx.Err()
		}
	}}
	service.s3 = control
	done := make(chan error, 1)
	go func() { _, err := service.PlaintextSource(ctx, row.Path, row.ID, false); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("source did not enter provider")
	}
	defer func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, 75*time.Millisecond)
	_, err = service.RenameGlobal(bounded, "music/S3Fence", "music/S3Renamed", store.AdminAudit{})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("rename crossed an active source lease", err)
	}
	close(finish)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, err = service.RenameGlobal(ctx, "music/S3Fence", "music/S3Renamed", store.AdminAudit{}); err != nil {
		t.Fatal("S3 rename contacted missing native peer", err)
	}
	current, err := db.Pool().(store.S3Repository).S3Object(ctx, row.ID)
	if err != nil || current.Proof != original.Proof || current.Media.Path != "music/S3Renamed/one.mp3" {
		t.Fatal("metadata rename changed provider key", current, err)
	}
	if _, err = os.Stat(filepath.Join(root, "music/S3Renamed")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("S3 rename created local directory", err)
	}
	before := control.reads.Load()
	if _, err = service.ReadSource(ctx, row.Path, row.ID, false); !errors.Is(err, os.ErrNotExist) || control.reads.Load() != before {
		t.Fatal("old path remained authorized", err)
	}
}

func TestS3PoolLogicalCapacityAndDeletePendingNeverUseNativePeer(t *testing.T) {
	_, db, service, member := s3CatalogFixture(t)
	ctx := context.Background()
	row := publishS3CatalogObject(t, db, "music/S3Delete/one.mp3", nil)
	control := &mediaS3Control{}
	service.s3 = control
	pool, err := service.StoragePool(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pool["physical_capacity_known"] != false || pool["physical_total_bytes"] != nil || pool["physical_free_bytes"] != nil {
		t.Fatal("unobserved provider physical capacity reported as zero", pool)
	}
	found := false
	for _, value := range pool["members"].([]store.StorageMember) {
		if value.ID == member.ID {
			found = true
			if value.Available != member.Allocation-128 || value.Available <= 0 {
				t.Fatal("physical zero disabled S3 logical capacity", value)
			}
		}
	}
	if !found {
		t.Fatal("missing S3 member")
	}
	result, err := service.DeleteGlobal(ctx, []string{row.Path}, store.AdminAudit{})
	if err != nil || result.Deleted != 0 || len(result.Pending) != 1 || control.deletes.Load() != 1 {
		t.Fatal("S3 delete did not retain pending provider cleanup", result, err)
	}
	placement, err := db.Pool().GlobalPlacement(ctx, row.ID)
	if err != nil || placement == nil || placement.State != "pending_delete" {
		t.Fatal("S3 delete discarded SQL ownership", placement, err)
	}
	member, err = db.Pool().(store.S3Repository).S3Member(ctx, member.ID)
	if err != nil || member.Used != 128 {
		t.Fatal("pending deletion refunded quota", member, err)
	}
	if err = service.RetryGlobalDeletes(ctx); err != nil || control.deletes.Load() != 1 {
		t.Fatal("native retry loop claimed S3", err)
	}
}

func TestS3RecoveryNoopKeepsWarmCatalogAndChangesInvalidate(t *testing.T) {
	_, db, service, _ := s3CatalogFixture(t)
	ctx := context.Background()
	publishS3CatalogObject(t, db, "music/S3Warm/one.mp3", nil)
	service.ConfigureCatalogCache(time.Minute)
	control := &mediaS3Control{}
	service.s3 = control
	if _, err := service.Catalog(ctx, "music", "music/S3Warm", "", false); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		service.catalog.mu.Lock()
		defer service.catalog.mu.Unlock()
		return len(service.catalog.entries)
	}
	if count() == 0 {
		t.Fatal("fixture did not fill catalog")
	}
	if err := service.ReconcileS3(ctx); err != nil || count() == 0 {
		t.Fatal("noop S3 recovery invalidated warm catalog", err)
	}
	control.reconcile = func(context.Context) error { control.generation.Add(1); return nil }
	if err := service.ReconcileS3(ctx); err != nil || count() != 0 {
		t.Fatal("visible S3 recovery retained stale catalog", err)
	}
	service.ConfigureS3(nil)
	if _, err := service.S3Members(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil control did not fail closed", err)
	}
}

var _ io.Reader = (*forbiddenS3Reader)(nil)
