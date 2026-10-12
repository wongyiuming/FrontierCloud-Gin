package media

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// MigrationCleanup uses the ordinary durable quarantine/recovery transaction.
// It hashes a pinned source file outside the global mutation lease, then checks
// the exact inode again under a short exclusive lease before preparing deletion.
// No HTTP endpoint invokes this until its read/inventory eligibility is proved.
func (s *Service) MigrationCleanup(ctx context.Context, relationship string, l store.MigrationLease, g store.MigrationCleanupGrant, repo store.MigrationPeerRepository, a store.NodeAudit) error {
	if s.owned == nil || repo == nil || g.Object.Resource != "media" {
		return ErrUnavailable
	}
	if e := repo.PreparePeerMigrationCleanup(ctx, relationship, l, g, a); e != nil {
		return e
	}
	v, e := repo.AuthorizePeerMigration(ctx, relationship, l, g.Object.ID, "cleanup")
	if e != nil {
		return e
	}
	if v.State == "deleted" {
		return s.finishMigrationCleanup(ctx, l.TaskID, g.Object.ID)
	}
	release, e := s.acquire(ctx, false)
	if e != nil {
		return e
	}
	if e = s.ready(); e != nil {
		release()
		return e
	}
	info, e := s.safeInfo(v.Object.Path)
	if e != nil {
		release()
		return e
	}
	if !info.Mode().IsRegular() || info.Size() != v.Object.Bytes {
		release()
		return store.ErrMigrationState
	}
	f, e := s.root.Open(v.Object.Path)
	release()
	if e != nil {
		return e
	}
	defer f.Close()
	pinned, e := f.Stat()
	if e != nil || !os.SameFile(info, pinned) {
		return ErrRecovery
	}
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var size int64
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		n, err := f.Read(buffer)
		if n > 0 {
			size += int64(n)
			if size > v.Object.Bytes {
				return store.ErrMigrationState
			}
			_, _ = h.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	after, e := f.Stat()
	if e != nil || size != v.Object.Bytes || hex.EncodeToString(h.Sum(nil)) != v.Proof.SHA256 || !os.SameFile(pinned, after) || pinned.Size() != after.Size() || !pinned.ModTime().Equal(after.ModTime()) {
		return store.ErrMigrationState
	}
	release, e = s.acquire(ctx, true)
	if e != nil {
		return e
	}
	defer release()
	if e = s.ready(); e != nil {
		return e
	}
	v, e = repo.AuthorizePeerMigration(ctx, relationship, l, g.Object.ID, "cleanup")
	if e != nil {
		return e
	}
	if v.State == "deleted" {
		return s.finishMigrationCleanupLocked(ctx, l.TaskID, g.Object.ID)
	}
	current, e := s.safeInfo(v.Object.Path)
	if e != nil {
		return e
	}
	if !os.SameFile(pinned, current) || current.Size() != pinned.Size() || !current.ModTime().Equal(pinned.ModTime()) {
		return store.ErrMigrationState
	}
	raw := make([]byte, 16)
	if _, e = rand.Read(raw); e != nil {
		return e
	}
	op := store.DeleteOperation{ID: hex.EncodeToString(raw), State: "pending", Items: []store.DeleteItem{{Path: v.Object.Path, Slot: "0", OwnedID: v.Object.ObjectID, Bytes: v.Object.Bytes, MigrationTask: l.TaskID, MigrationLogical: v.Object.ID}}}
	if e = repo.PreparePeerMediaDelete(ctx, relationship, l, op, a); e != nil {
		if _, err := s.reconcileDelete(op.ID); err != nil {
			return err
		}
		return e
	}
	e = s.stageDelete(ctx, op, func() error {
		_, free, err := fsutil.DiskUsage(s.root)
		if err != nil {
			return err
		}
		return s.owned.CommitOwnedDelete(ctx, op.ID, free, a)
	})
	finished, err := s.reconcileDelete(op.ID)
	if err != nil {
		return err
	}
	if finished == nil {
		s.markRecovery()
		return ErrRecovery
	}
	if e != nil && finished.State != "committed" {
		return e
	}
	remaining, err := s.repository.DeleteOperation(ctx, op.ID)
	if err != nil {
		return err
	}
	if remaining != nil {
		return ErrRecovery
	}
	return nil
}

// A committed SQL receipt does not prove that its private quarantine was
// removed. Replays finish only this task/object's retained committed journal.
func (s *Service) finishMigrationCleanup(ctx context.Context, task, id string) error {
	release, e := s.acquire(ctx, true)
	if e != nil {
		return e
	}
	defer release()
	return s.finishMigrationCleanupLocked(ctx, task, id)
}
func (s *Service) finishMigrationCleanupLocked(ctx context.Context, task, id string) error {
	ops, e := s.repository.DeleteOperations(ctx)
	if e != nil {
		return e
	}
	for _, op := range ops {
		for _, item := range op.Items {
			if item.MigrationTask != task || item.MigrationLogical != id {
				continue
			}
			if op.State != "committed" {
				return ErrRecovery
			}
			if e = s.finishDelete(ctx, op); e != nil {
				return e
			}
		}
	}
	return nil
}
