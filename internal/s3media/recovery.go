package s3media

import (
	"context"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (s *Service) recoverCreate(ctx context.Context, id string) error {
	release, err := s.lease(ctx, "upload:"+id)
	if err != nil {
		return err
	}
	defer release()
	upload, err := s.repository.S3Upload(ctx, id)
	if err != nil {
		return err
	}
	if upload.State != "creating" && upload.State != "create_unknown" {
		return nil
	}
	provider, closeProvider, err := s.uploadProvider(ctx, upload)
	if err != nil {
		return err
	}
	defer closeProvider()
	providerID, err := discoverUpload(ctx, provider, upload.Key, upload.Reservation.CreatedAt)
	if err != nil {
		return err
	}
	_, err = s.repository.S3FinishCreate(ctx, id, upload.Revision, providerID, "created", "")
	return err
}

func (s *Service) recoverProbe(ctx context.Context, intent store.S3Probe) (resultErr error) {
	release, err := s.lease(ctx, "member:"+intent.MemberID)
	if err != nil {
		return err
	}
	defer release()
	if intent.GrantUntil > time.Now().Unix() {
		return ErrPending
	}
	defer func() {
		if resultErr == nil {
			return
		}
		// Refresh failed attempts so a permanently unreachable oldest member
		// cannot occupy every slot of the next bounded probe queue.
		finish, cancel := finishContext(ctx)
		defer cancel()
		_, _ = s.repository.S3FinishProbe(finish, intent.ID, intent.Revision, store.S3ProbeResult{
			Key: intent.Key, ProviderUploadID: intent.ProviderUploadID,
			VersionID: intent.VersionID, ETag: intent.ETag, ErrorCode: ErrorCode(resultErr),
		}, store.NodeAudit{Actor: "s3-recovery"})
	}()
	member, err := s.repository.S3Member(ctx, intent.MemberID)
	if err != nil {
		return err
	}
	provider, closeProvider, err := s.provider(member)
	if err != nil {
		return err
	}
	defer closeProvider()
	if intent.ProviderUploadID == "" {
		intent.ProviderUploadID, err = discoverUpload(ctx, provider, intent.Key, intent.CreatedAt)
		if err != nil {
			return err
		}
		// Persist the discovered exact upload before its first cleanup mutation.
		_, err = s.repository.S3FinishProbe(ctx, intent.ID, intent.Revision, store.S3ProbeResult{Key: intent.Key, ProviderUploadID: intent.ProviderUploadID, ErrorCode: "probe_cleanup_pending"}, store.NodeAudit{Actor: "s3-recovery"})
		if err != nil {
			return err
		}
	}
	if err = abortKnown(ctx, provider, intent.Key, intent.ProviderUploadID); err != nil {
		return err
	}
	version, etag, err := deleteOwned(ctx, provider, intent.Key, map[string]string{"fc-probe": intent.Key}, intent.VersionID, intent.ETag)
	if err != nil {
		return err
	}
	finish, cancel := finishContext(ctx)
	defer cancel()
	_, err = s.repository.S3FinishProbe(finish, intent.ID, intent.Revision, store.S3ProbeResult{Key: intent.Key, ProviderUploadID: intent.ProviderUploadID, VersionID: version, ETag: etag, CleanupSettled: true, ErrorCode: "probe_recovered"}, store.NodeAudit{Actor: "s3-recovery"})
	return err
}

// Reconcile is a bounded control sweep, never a bucket scan or payload replay.
// The caller joins the media mutation fence and supplies a service-lifetime
// context. Pending grants/unknown creation are retained without quota refunds.
func (s *Service) Reconcile(ctx context.Context) error {
	if err := s.master(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var failures []error
	appendFailure := func(err error) {
		if err != nil && !errors.Is(err, ErrPending) {
			failures = append(failures, err)
		}
	}
	// Rotate admission between independent journals. An unreachable upload can
	// consume this sweep's whole time budget without starving every delete and
	// probe forever. Each journal retains its own persisted oldest-attempt order.
	start := int((s.sweeps.Add(1) - 1) % 3)
	phases := []func(context.Context, func(error)) error{s.reconcileUploads, s.reconcileDeletes, s.reconcileProbes}
	for offset := range phases {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if err := phases[(start+offset)%len(phases)](ctx, appendFailure); err != nil {
			return errors.Join(append(failures, err)...)
		}
	}
	return errors.Join(failures...)
}

func (s *Service) reconcileUploads(ctx context.Context, appendFailure func(error)) error {
	uploads, err := s.repository.S3RecoveryUploads(ctx, 8)
	if err != nil {
		return err
	}
	for _, upload := range uploads {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := upload.Reservation.ID
		expired := upload.Reservation.ExpiresAt <= time.Now().Unix() || upload.AbsoluteExpiresAt <= time.Now().Unix()
		if upload.State == "aborting" || expired {
			_, err = s.Cancel(ctx, id, store.AdminAudit{Action: "s3-upload-recovered"})
		} else if upload.State == "completing" {
			_, err = s.Complete(ctx, id, store.AdminAudit{Action: "s3-upload-recovered"})
		} else {
			err = s.recoverCreate(ctx, id)
		}
		appendFailure(err)
		if err != nil {
			// A failing oldest provider must not starve unrelated durable work
			// in the next bounded sweep. The CAS also preserves a safe short code.
			finish, stop := finishContext(ctx)
			latest, readErr := s.repository.S3Upload(finish, id)
			if readErr == nil && latest.State != "published" && latest.State != "aborted" {
				_ = s.repository.S3RecordUploadError(finish, id, latest.Revision, ErrorCode(err))
			}
			stop()
		}
	}
	return nil
}

func (s *Service) reconcileDeletes(ctx context.Context, appendFailure func(error)) error {
	objects, err := s.repository.S3PendingDeletes(ctx, 8)
	if err != nil {
		return err
	}
	for _, object := range objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		appendFailure(s.Delete(ctx, object.Media.ID, store.AdminAudit{Action: "s3-delete-recovered"}))
	}
	return nil
}

func (s *Service) reconcileProbes(ctx context.Context, appendFailure func(error)) error {
	probes, err := s.repository.S3RecoveryProbes(ctx, 8)
	if err != nil {
		return err
	}
	for _, probe := range probes {
		if err := ctx.Err(); err != nil {
			return err
		}
		appendFailure(s.recoverProbe(ctx, probe))
	}
	return nil
}
