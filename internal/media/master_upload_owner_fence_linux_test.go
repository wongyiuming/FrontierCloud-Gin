//go:build linux

package media

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type stagedBarrierReader struct {
	source                    io.Reader
	entered, resume, consumed chan struct{}
	once, done                sync.Once
}

func (r *stagedBarrierReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered); <-r.resume })
	n, err := r.source.Read(p)
	if n > 0 {
		r.done.Do(func() { close(r.consumed) })
	}
	return n, err
}

// Isolated legacy writer: actual SQLite, node vault and owner flock. It does
// not authorize the plaintext-path writer when an encrypted tree is active.
func TestMasterLocalUploadOwnerFenceStagesBeforeShortPublication(t *testing.T) {
	ctx := context.Background()
	root, db, svc := masterFixture(t)
	ticket, err := svc.ReserveMasterUpload(ctx, "guarded.mp3", "music/Guarded", "", "primary", 10, 255, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	fence, err := ownerfence.Create(dir, root, svc.identity)
	if err != nil {
		t.Fatal(err)
	}
	config := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if err := config.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err := config.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	reader := &stagedBarrierReader{source: strings.NewReader("ID3payload"), entered: make(chan struct{}), resume: make(chan struct{}), consumed: make(chan struct{})}
	result := make(chan error, 1)
	go func() { _, e := svc.UploadMasterBytes(ctx, ticket.ID, reader, store.AdminAudit{}); result <- e }()
	select {
	case <-reader.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("stage did not start")
	}
	shared, err := config.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal("owner held while reading upload", err)
	}
	close(reader.resume)
	select {
	case <-reader.consumed:
	case <-time.After(5 * time.Second):
		t.Fatal("stage did not consume body")
	}
	select {
	case e := <-result:
		t.Fatal("publication bypassed owner reader", e)
	case <-time.After(150 * time.Millisecond):
	}
	if !svc.mutation.TryRLock() {
		t.Fatal("writer held volume while waiting for owner")
	}
	svc.mutation.RUnlock()
	shared.Release()
	select {
	case e := <-result:
		if e != nil {
			t.Fatal("publication failed", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication deadlocked")
	}
	row, err := db.Pool().Resource(ctx, ticket.MediaID)
	if err != nil || row.Path != ticket.Path || row.Bytes != 10 {
		t.Fatal("publication not committed", err)
	}
	failed, err := svc.ReserveMasterUpload(ctx, "failed.mp3", "music/Guarded", "", "primary", 10, 255, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().Exec(`CREATE TRIGGER fixture_upload_rollback BEFORE INSERT ON global_media_objects BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	_, err = svc.UploadMasterBytes(ctx, failed.ID, strings.NewReader("ID3payload"), store.AdminAudit{})
	if !errors.Is(err, ErrRecovery) {
		t.Fatal("failed transaction did not preserve recovery", err)
	}
	var count int
	if e := db.Database().QueryRow("SELECT COUNT(*) FROM media_objects WHERE media_id=?", failed.MediaID).Scan(&count); e != nil || count != 0 {
		t.Fatal("SQL publication did not roll back", e)
	}
	masterFunds(t, db, 10, 10)
	entries, e := os.ReadDir(root)
	if e != nil {
		t.Fatal(e)
	}
	foundJournal := false
	for _, entry := range entries {
		foundJournal = foundJournal || uploadJournalName.MatchString(entry.Name())
	}
	if !foundJournal {
		t.Fatal("failed publication lost durable recovery journal")
	}
	if _, e := os.Stat(filepath.Join(root, filepath.FromSlash(failed.Path))); e != nil {
		t.Fatal("unknown publication bytes were removed", e)
	}
}
