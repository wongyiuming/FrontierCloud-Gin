package media

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Timeout is eligibility to investigate, never physical deletion proof.
// A local OS lease and the storage appliance's own stage lease fence writers.
func (s *Service) reconcileExpiredUpload(ctx context.Context, id string) error {
	release, err := s.uploadSessionLease(id)
	if err != nil {
		return err
	}
	defer release()
	v, err := s.masterUpload(ctx, id)
	if err != nil {
		return err
	}
	if v.State != "reserved" || v.ExpiresAt > time.Now().Unix() {
		return nil
	}
	audit := store.AdminAudit{RequestID: "expired-upload-recovery", Action: "upload-recovered"}
	if v.Member.Kind == "MasterLocal" {
		volumeRelease, err := s.acquire(ctx, true)
		if err != nil {
			return err
		}
		defer volumeRelease()
		if err = s.ready(); err != nil {
			return err
		}
		object, err := s.repository.ObjectByID(ctx, v.MediaID)
		if err != nil {
			return err
		}
		if object != nil {
			return store.ErrNodeState
		}
		if _, err = s.safeInfo(v.Path); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return os.ErrExist
			}
			return err
		}
		if err = s.syncDirectory("."); err != nil {
			return err
		}
	} else {
		if s.control == nil {
			return ErrUnavailable
		}
		value, err := s.control.StatStorage(ctx, v)
		if err == nil {
			receipt, err := checkReceipt(v, value)
			if err != nil {
				return err
			}
			_, err = s.pool.FinalizeRecoveredUpload(ctx, v.ID, receipt.ObjectID, receipt.Bytes, receipt.ETag, audit)
			return err
		}
		if !errors.Is(err, node.ErrRemoteNotFound) {
			return err
		}
		// Stat's 404 is not atomic absence proof. The non-destructive paired
		// operation refuses committed/unknown bytes and fences late writers.
		// Unsupported legacy storage must defer, never fall back to deletion.
		if err = s.control.AbortAbsentStorage(ctx, v); err != nil {
			return err
		}
	}
	return s.pool.ReleaseCleanedUpload(ctx, id, audit)
}

func (s *Service) RetryExpiredUploads(ctx context.Context) error {
	return s.retryExpiredUploads(ctx, uploadRecoveryBudget, 5*time.Second)
}

func uploadRecoveryBudget(v store.UploadReservation) time.Duration {
	// Hash verification happens on storage, not Master. Give large media
	// a bounded byte-dependent budget instead of timing out every retry.
	return min(180*time.Second, 10*time.Second+time.Duration(v.ExpectedBytes/(16*1024*1024))*time.Second)
}

// Keep a cleanup grace inside the sweep deadline: a maximum-size item must
// leave time to rotate its reservation before the sweep context expires.
// The budget function permits fast deadline tests without changing production
// limits. Both investigation and rotation still inherit caller cancellation.
func (s *Service) retryExpiredUploads(ctx context.Context, itemBudget func(store.UploadReservation) time.Duration, cleanupGrace time.Duration) error {
	if s.pool == nil || s.nodes == nil {
		return nil
	}
	role, err := s.role(ctx)
	if err != nil {
		return err
	}
	if role == "Follower" {
		// Reconcile dead appliance stages during normal service, not just startup.
		release, err := s.acquire(ctx, true)
		if err != nil {
			return err
		}
		defer release()
		if err = s.ready(); err != nil {
			return err
		}
		return s.recoverOwnedReservations(ctx)
	}
	if role != "Master" {
		return nil
	}
	rows, err := s.pool.ExpiredUploads(ctx, 50)
	if err != nil {
		return err
	}
	for _, v := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		budget := itemBudget(v)
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline) - cleanupGrace
			if remaining <= 0 {
				return context.DeadlineExceeded
			}
			budget = min(budget, remaining)
		}
		bounded, cancel := context.WithTimeout(ctx, budget)
		err := s.reconcileExpiredUpload(bounded, v.ID)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Rotation updates ordering only; it never renews expiry or releases
			// quota. Do not detach this SQL write from caller cancellation.
			rotation, rotationCancel := context.WithTimeout(ctx, cleanupGrace)
			rotationErr := s.pool.DeferExpiredUpload(rotation, v.ID)
			rotationCancel()
			if rotationErr != nil {
				if ctx.Err() == nil {
					slog.Warn("expired upload rotation failed", "upload_id", v.ID, "error", rotationErr)
				}
				return errors.Join(err, rotationErr)
			}
			if !errors.Is(err, store.ErrNodeState) && !errors.Is(err, os.ErrExist) && !errors.Is(err, ErrUnavailable) {
				slog.Warn("expired upload reconciliation deferred", "upload_id", v.ID, "error", err)
			}
		}
	}
	return ctx.Err()
}

func (s *Service) RunUploadRecovery(ctx context.Context) {
	runUploadRecovery(ctx, s.RetryExpiredUploads, func(delay time.Duration) uploadRecoveryTimer {
		return liveUploadRecoveryTimer{time.NewTimer(delay)}
	})
}

type uploadRecoveryTimer interface {
	channel() <-chan time.Time
	stop()
}

type liveUploadRecoveryTimer struct{ timer *time.Timer }

func (t liveUploadRecoveryTimer) channel() <-chan time.Time { return t.timer.C }
func (t liveUploadRecoveryTimer) stop()                     { t.timer.Stop() }

// Start immediately, then cool down for a full interval after each sweep.
// A fixed ticker would accumulate a tick during slow work and immediately
// restart expensive storage/hash investigations when that work finishes.
func runUploadRecovery(ctx context.Context, sweep func(context.Context) error, newTimer func(time.Duration) uploadRecoveryTimer) {
	for {
		if ctx.Err() != nil {
			return
		}
		bounded, cancel := context.WithTimeout(ctx, 180*time.Second)
		if err := sweep(bounded); err != nil && ctx.Err() == nil && !errors.Is(err, context.DeadlineExceeded) {
			slog.Warn("upload reconciliation sweep deferred", "error", err)
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		cooldown := newTimer(30 * time.Second)
		select {
		case <-ctx.Done():
			cooldown.stop()
			return
		case <-cooldown.channel():
			cooldown.stop()
		}
	}
}
