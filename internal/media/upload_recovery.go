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
		// A paired storage deletion/absence receipt refuses live partial stages.
		// Never release quota on a timeout, auth/network error or unknown file.
		if err = s.control.DeleteStorage(ctx, v); err != nil {
			return err
		}
	}
	return s.pool.ReleaseCleanedUpload(ctx, id, audit)
}

func (s *Service) RetryExpiredUploads(ctx context.Context) error {
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
		// Hash verification happens on storage, not Master. Give large media
		// a bounded byte-dependent budget instead of timing out every retry.
		budget := min(180*time.Second, 10*time.Second+time.Duration(v.ExpectedBytes/(16*1024*1024))*time.Second)
		bounded, cancel := context.WithTimeout(ctx, budget)
		err := s.reconcileExpiredUpload(bounded, v.ID)
		cancel()
		if err != nil {
			_ = s.pool.DeferExpiredUpload(ctx, v.ID)
			if !errors.Is(err, store.ErrNodeState) && !errors.Is(err, os.ErrExist) && !errors.Is(err, ErrUnavailable) {
				slog.Warn("expired upload reconciliation deferred", "upload_id", v.ID, "error", err)
			}
		}
	}
	return ctx.Err()
}

func (s *Service) RunUploadRecovery(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		bounded, cancel := context.WithTimeout(ctx, 180*time.Second)
		if err := s.RetryExpiredUploads(bounded); err != nil && ctx.Err() == nil && !errors.Is(err, context.DeadlineExceeded) {
			slog.Warn("upload reconciliation sweep deferred", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
