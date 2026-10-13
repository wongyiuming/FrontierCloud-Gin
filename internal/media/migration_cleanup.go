package media

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// MigrationCleanup uses the ordinary durable quarantine/recovery transaction.
// It hashes a pinned source file outside the global mutation lease, then checks
// the exact inode again under a short exclusive lease before preparing deletion.
// The authenticated native-only worker uses the persisted-grant entry below.
func (s *Service) MigrationCleanup(ctx context.Context, relationship string, l store.MigrationLease, g store.MigrationCleanupGrant, repo store.MigrationPeerRepository, a store.NodeAudit) error {
	if s.owned == nil || repo == nil || g.Object.Resource != "media" {
		return ErrUnavailable
	}
	if e := repo.PreparePeerMigrationCleanup(ctx, relationship, l, g, a); e != nil {
		return e
	}
	return s.MigrationCleanupAuthorized(ctx, relationship, l, g.Object.ID, repo, a)
}

// MigrationCleanupAuthorized consumes only the already-persisted source grant.
func (s *Service) MigrationCleanupAuthorized(ctx context.Context, relationship string, l store.MigrationLease, id string, repo store.MigrationPeerRepository, a store.NodeAudit) error {
	return s.migrationDeleteAuthorized(ctx, relationship, l, id, repo, a, "cleanup")
}
func (s *Service) MigrationShadowCleanup(ctx context.Context, relationship string, l store.MigrationLease, g store.MigrationShadowGrant, repo store.MigrationPeerRepository, a store.NodeAudit) error {
	if s.owned == nil || repo == nil || g.Object.Resource != "media" {
		return ErrUnavailable
	}
	if e := repo.PreparePeerMigrationShadowDeletion(ctx, relationship, l, g, a); e != nil {
		return e
	}
	return s.MigrationShadowCleanupAuthorized(ctx, relationship, l, g.Object.ID, repo, a)
}
func (s *Service) MigrationShadowCleanupAuthorized(ctx context.Context, relationship string, l store.MigrationLease, id string, repo store.MigrationPeerRepository, a store.NodeAudit) error {
	return s.migrationDeleteAuthorized(ctx, relationship, l, id, repo, a, "shadow")
}

// Both paths use the same pinned inode, full SHA, quarantine and SQL recovery.
func (s *Service) migrationDeleteAuthorized(ctx context.Context, relationship string, l store.MigrationLease, id string, repo store.MigrationPeerRepository, a store.NodeAudit, operation string) error {
	if s.owned == nil || repo == nil {
		return ErrUnavailable
	}
	v, e := repo.AuthorizePeerMigration(ctx, relationship, l, id, operation)
	if e != nil {
		return e
	}
	if v.State == "deleted" {
		if e = s.finishMigrationCleanup(ctx, l.TaskID, id); e != nil {
			return e
		}
		return s.finishMigrationHistory(ctx, relationship, l, v, repo, operation)
	}
	if v.State != "deleting" || v.Object.Resource != "media" {
		return store.ErrMigrationState
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
		if e = migrationdata.ScanAdmission(ctx); e != nil {
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
	held := true
	defer func() {
		if held {
			release()
		}
	}()
	if e = s.ready(); e != nil {
		return e
	}
	v, e = repo.AuthorizePeerMigration(ctx, relationship, l, id, operation)
	if e != nil {
		return e
	}
	if v.State == "deleted" {
		if e = s.finishMigrationCleanupLocked(ctx, l.TaskID, id); e != nil {
			return e
		}
		release()
		held = false
		return s.finishMigrationHistory(ctx, relationship, l, v, repo, operation)
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
	release()
	held = false
	return s.finishMigrationHistory(ctx, relationship, l, v, repo, operation)
}

// A cancelled target owns only its task-private publication anchor. Its
// business copy and managed quarantine must already have been removed.
func (s *Service) finishMigrationHistory(ctx context.Context, relationship string, l store.MigrationLease, v store.MigrationPeerObject, repo store.MigrationPeerRepository, operation string) error {
	if operation != "shadow" {
		return s.migrationHistory(ctx, relationship, l, v, repo)
	}
	r, e := migrationdata.New(s.root, v.Header.TargetID, "media")
	if e != nil {
		return e
	}
	o := v.Object
	spec := migrationdata.Spec{TaskID: l.TaskID, MasterID: v.Header.MasterID, SourceID: v.Header.SourceID, TargetID: v.Header.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: v.Proof.SHA256, Encryption: o.Encryption, Recording: o.Recording}
	return r.RetireDeletedAnchor(ctx, spec, func() error {
		current, e := repo.AuthorizePeerMigration(ctx, relationship, l, o.ID, "shadow")
		if e != nil {
			return e
		}
		if current.State != "deleted" {
			return store.ErrMigrationState
		}
		release, e := s.acquire(ctx, false)
		if e != nil {
			return e
		}
		defer release()
		if e = s.ready(); e != nil {
			return e
		}
		if _, e = s.safeInfo(o.TargetPath); !errors.Is(e, os.ErrNotExist) {
			if e != nil {
				return e
			}
			return store.ErrMigrationState
		}
		object, e := s.repository.ObjectByID(ctx, o.ObjectID)
		if e != nil {
			return e
		}
		if object != nil {
			return store.ErrMigrationState
		}
		return nil
	})
}

func (s *Service) migrationHistory(ctx context.Context, relationship string, l store.MigrationLease, v store.MigrationPeerObject, repo store.MigrationPeerRepository) error {
	r, e := migrationdata.New(s.root, v.Header.SourceID, "media")
	if e != nil {
		return e
	}
	return r.HistoricalAnchors(ctx, v.Header.MasterID, v.Object, v.Proof.SHA256, func() error {
		current, e := repo.AuthorizePeerMigration(ctx, relationship, l, v.Object.ID, "cleanup")
		if e != nil {
			return e
		}
		if current.State != "deleted" {
			return store.ErrMigrationState
		}
		return nil
	})
}

func (s *Service) MigrationHistoryFinished(ctx context.Context, v store.MigrationPeerObject) (bool, error) {
	r, e := migrationdata.New(s.root, v.Header.SourceID, "media")
	if e != nil {
		return false, e
	}
	return r.HistoricalAnchorsFinished(ctx, v.Header.MasterID, v.Object, v.Proof.SHA256)
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

// MigrationCleanupFinished distinguishes the SQL deleted phase from retained
// managed file journals. Historical publication anchors are a separate phase.
func (s *Service) MigrationCleanupFinished(ctx context.Context, task, id string) (bool, error) {
	release, e := s.acquire(ctx, false)
	if e != nil {
		return false, e
	}
	defer release()
	ops, e := s.repository.DeleteOperations(ctx)
	if e != nil {
		return false, e
	}
	for _, op := range ops {
		for _, item := range op.Items {
			if item.MigrationTask == task && item.MigrationLogical == id {
				return false, nil
			}
		}
	}
	return true, nil
}
