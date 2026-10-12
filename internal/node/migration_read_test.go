package node

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type failingReadLease struct {
	store.NodeRepository
	closed   atomic.Int64
	renewals atomic.Int64
}

func (r *failingReadLease) AcquireMigrationRead(context.Context, string, string, string, string) (string, error) {
	return "lease", nil
}
func (r *failingReadLease) RenewMigrationRead(context.Context, string, string) error {
	r.renewals.Add(1)
	return errors.New("database unavailable")
}
func (r *failingReadLease) ReleaseMigrationRead(context.Context, string) error {
	r.closed.Add(1)
	return nil
}

func TestOwnedReadRenewalFailureClosesStreamAndJoinsBeforeRelease(t *testing.T) {
	repo := &failingReadLease{}
	s := &Service{repo: repo}
	fileClosed := make(chan struct{})
	ctx, release, e := s.protectOwnedRead(context.Background(), "relation", "logical", "physical", "media", func() { close(fileClosed) }, time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	select {
	case <-fileClosed:
	case <-time.After(time.Second):
		t.Fatal("renewal failure did not close pinned stream")
	}
	if ctx.Err() == nil {
		t.Fatal("failed read context still active")
	}
	release()
	release()
	if repo.renewals.Load() != 1 || repo.closed.Load() != 1 {
		t.Fatal("renewal worker or repeated release leaked", repo.renewals.Load(), repo.closed.Load())
	}
}

func TestOwnedReadCloseJoinsWorkerBeforeRemovingDependency(t *testing.T) {
	repo := &failingReadLease{}
	s := &Service{repo: repo}
	ctx, release, e := s.protectOwnedRead(context.Background(), "relation", "logical", "physical", "recording", func() { t.Error("normal close treated as renewal failure") }, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	release()
	if ctx.Err() == nil || repo.renewals.Load() != 0 || repo.closed.Load() != 1 {
		t.Fatal("normal stream close did not release durable dependency")
	}
}
