package certmanager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

type pausedStorage struct {
	certmagic.Storage
	started, proceed chan struct{}
}

func (s *pausedStorage) Store(ctx context.Context, key string, value []byte) error {
	close(s.started)
	<-s.proceed
	return s.Storage.Store(ctx, key, value)
}

func TestStorageCloseWaitsForWritesAndRejectsLateTasks(t *testing.T) {
	root := t.TempDir()
	backend := &pausedStorage{Storage: &certmagic.FileStorage{Path: root}, started: make(chan struct{}), proceed: make(chan struct{})}
	s := &controlledStorage{backend: backend}
	done := make(chan error, 1)
	go func() { done <- s.Store(context.Background(), "account/key", []byte("fixture")) }()
	<-backend.started
	closed := make(chan struct{})
	go func() { s.close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("shutdown released storage while a write was pending")
	case <-time.After(30 * time.Millisecond):
	}
	close(backend.proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("storage shutdown stalled")
	}
	if !errors.Is(s.Store(context.Background(), "late/key", []byte("late")), context.Canceled) {
		t.Fatal("late task wrote after shutdown")
	}
	if _, err := os.Stat(filepath.Join(root, "late")); !os.IsNotExist(err) {
		t.Fatal("late task recreated cache directories", err)
	}
}

func TestStorageCloseJoinsOwnedLocksAndPreservesTryLock(t *testing.T) {
	s := &controlledStorage{backend: &certmagic.FileStorage{Path: t.TempDir()}}
	if ok, err := s.TryLock(context.Background(), "renewal"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	closed := make(chan struct{})
	go func() { s.close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("node lease released before library lock")
	case <-time.After(30 * time.Millisecond):
	}
	if err := s.Unlock(context.Background(), "renewal"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("owned lock failed to close")
	}
	if _, err := s.TryLock(context.Background(), "late"); !errors.Is(err, context.Canceled) {
		t.Fatal("late lock accepted", err)
	}
}
