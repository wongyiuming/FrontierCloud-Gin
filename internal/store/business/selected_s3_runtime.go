package business

import (
	"context"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// SelectedS3Provider is the Master-held provider adapter. It must reopen and
// compare the exact member configuration before invoking the callback; the
// callback is never called while a database transaction is held.
type SelectedS3Provider interface {
	WithSelectedProvider(context.Context, store.S3Member, func(context.Context, s3store.Provider) error) error
}

// RecoverCreate only accepts one exact-key provider upload with a matching
// creation window. An empty/incomplete listing never proves absence; it is
// retained for explicit reconciliation rather than issuing a second create.
func (s *SelectedS3Coordinator) RecoverCreate(ctx context.Context, sessionHash, uploadID string) (string, error) {
	u, ready, err := s.lease(ctx, sessionHash, uploadID)
	if err != nil {
		return "", err
	}
	defer u.Release()
	defer ready.Release()
	var intent selectedS3Intent
	var member store.S3Member
	err = s.withPending(ctx, uploadID, u, ready, func(_ context.Context, _ queryer, current selectedS3Intent, snapshot store.S3Member) error {
		if current.Phase != "creating" && current.Phase != "create_unknown" && current.Phase != "uploading" {
			return store.ErrNodeState
		}
		intent, member = current, snapshot
		return nil
	})
	if err != nil {
		return "", err
	}
	if intent.Phase == "uploading" {
		return "uploading", nil
	}
	var providerID string
	err = s.provider.WithSelectedProvider(ctx, member, func(c context.Context, provider s3store.Provider) error {
		var e error
		providerID, e = s3media.DiscoverSelectedUpload(c, provider, intent.Key, intent.CreatedAt)
		return e
	})
	if err != nil {
		return "", err
	}
	err = s.withPending(ctx, uploadID, u, ready, func(c context.Context, q queryer, current selectedS3Intent, _ store.S3Member) error {
		if current.Phase == "uploading" && current.ProviderUploadID == providerID {
			return nil
		}
		if current != intent {
			return store.ErrNodeState
		}
		next := current
		next.Phase, next.ProviderUploadID = "uploading", providerID
		next.Revision++
		return s.upload.repo.writeSelectedS3IntentTx(c, q, s.upload.key, next, func(_ context.Context, _ queryer, old selectedS3Intent, found bool) error {
			if !found || old != current {
				return store.ErrNodeState
			}
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	return "uploading", nil
}

// SelectedS3Readiness must be supplied by the actual startup/recovery and S3
// configuration coordinator. Its lease excludes maintenance, bucket changes
// and unresolved startup reconciliation through each operation, and holds a
// cross-process exclusive lock for the already-authenticated upload throughout
// network work. Implementations must not create persistent locks for untrusted
// unknown IDs. Configuration changes must also respect part grant deadlines.
type SelectedS3Readiness interface {
	AcquireSelectedS3(context.Context, *sealedtree.SQLStore, string) (SelectedUploadRuntimeLease, error)
	// Admission protects recovery/configuration while creating or retrying the
	// SQL reservation; it must not create persistent lock files for unknown IDs.
	AcquireSelectedS3Admission(context.Context, *sealedtree.SQLStore, string) (SelectedUploadRuntimeLease, error)
	CheckSelectedS3Member(context.Context, *sealedtree.SQLStore, store.S3Member) error
	CheckSelectedS3PublicOrigin(context.Context, *sealedtree.SQLStore, store.S3Member, string) error
}

// checkSelectedS3CurrentOriginTx is called only under the selected mutation's
// ingress fence, so an ingress switch cannot race this proof check and commit.
func (s *SelectedS3Coordinator) checkSelectedS3CurrentOriginTx(ctx context.Context, q queryer, member store.S3Member) error {
	var origin string
	if s == nil || q.QueryRowContext(ctx, "SELECT public_origin FROM public_ingress_config WHERE singleton=1").Scan(&origin) != nil ||
		!validPublicOrigin(origin) || s.ready.CheckSelectedS3PublicOrigin(ctx, s.upload.tree, member, origin) != nil {
		return store.ErrNodeState
	}
	return nil
}

type SelectedS3Coordinator struct {
	upload   *SelectedUploadRuntime
	provider SelectedS3Provider
	ready    SelectedS3Readiness
}

type SelectedS3PartView struct {
	Number    int    `json:"number"`
	Bytes     int64  `json:"size_bytes"`
	SHA256    string `json:"checksum_sha256"`
	Confirmed bool   `json:"confirmed"`
}
type SelectedS3Status struct {
	State       string `json:"state"`
	Reservation struct {
		ExpectedBytes int64 `json:"expected_bytes"`
	} `json:"reservation"`
	Parts []SelectedS3PartView `json:"parts"`
}

// Status is a bounded authenticated snapshot. It never exposes a provider key,
// upload ID, credential, signed URL, or storage-internal locator.
func (s *SelectedS3Coordinator) Status(ctx context.Context, sessionHash, uploadID string) (SelectedS3Status, error) {
	var result SelectedS3Status
	u, ready, err := s.lease(ctx, sessionHash, uploadID)
	if err != nil {
		return result, err
	}
	defer u.Release()
	readyHeld := true
	defer func() {
		if readyHeld {
			ready.Release()
		}
	}()
	if !nodeIDPattern.MatchString(uploadID) {
		return result, store.ErrNodeState
	}
	r := s.upload.repo
	err = r.withSelectedMutation(ctx, s.upload.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if u.Check(c) != nil || ready.Check(c) != nil {
			return store.ErrNodeState
		}
		selected, _, found, err := r.selectedIntentAnyTx(c, q, s.upload.key, uploadID)
		if err != nil || !found || selected.Policy != "S3" {
			return store.ErrNodeState
		}
		identity, err := readNode(c, q, r.lock())
		if err != nil || identity.Role != "Master" || identity.ID != selected.Capacity.MasterID || capacityMasterBinding(identity) != selected.MasterBinding {
			return store.ErrNodeState
		}
		if selected.State == "pending" && r.selectedFinalizePolicyTx(c, q, s.upload.key, selected) != nil {
			return store.ErrNodeState
		}
		intent, found, err := r.readSelectedS3IntentTx(c, q, s.upload.key, selected.Capacity.OperationID)
		if err != nil || !found || intent.UploadID != uploadID || intent.MemberID != selected.Capacity.MemberID || intent.BlobID != selected.Capacity.BlobID || intent.Bytes != selected.Capacity.Bytes || intent.Digest != selected.Capacity.Digest || intent.LocationBinding != selected.RelationshipBinding {
			return store.ErrNodeState
		}
		result.Reservation.ExpectedBytes = intent.Bytes
		result.Parts = []SelectedS3PartView{}
		if selected.State == "cancelled" {
			cancelled, e := m.IsSelectedCancelledTx(c, q, intent.OperationID)
			if e != nil || !cancelled || !selected.CancelRequested || intent.State != "cancelled" || intent.CancellationBinding != selected.CompletionBinding {
				return store.ErrNodeState
			}
			result.State = "cancelled"
		} else if selected.State == "completed" {
			if intent.State != "completed" || !intent.ProofRecorded {
				return store.ErrNodeState
			}
			var object, blob, mac string
			if q.QueryRowContext(c, `SELECT object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`, intent.OperationID).Scan(&object, &blob, &mac) != nil || opaqueledger.CompletionBinding(object, blob, mac) != selected.CompletionBinding {
				return store.ErrNodeState
			}
			deleted, e := m.S3PublicationDeletionRecordedTx(c, q, intent.ObjectID, intent.UploadID)
			if e != nil {
				return store.ErrNodeState
			}
			if deleted {
				result.State = "deleted"
			} else {
				placement, e := m.ReadSelectedS3CompletedTx(c, q, intent.OperationID, intent.ObjectID, intent.BlobID)
				if e != nil || placement.MemberID != intent.MemberID || placement.Proof != intent.ProviderProof || placement.Encryption == nil || *placement.Encryption != intent.Encryption {
					return store.ErrNodeState
				}
				result.State = "published"
			}
		} else {
			if selected.State != "pending" || intent.State != "pending" {
				return store.ErrNodeState
			}
			pending, e := m.ReadSelectedFileTx(c, q, intent.OperationID)
			if e != nil || verifySelectedPendingBinding(s.upload.key, selected, pending) != nil {
				return store.ErrNodeState
			}
			parts, e := r.listSelectedS3PartsTx(c, q, s.upload.key, intent, false)
			if e != nil {
				return e
			}
			for _, part := range parts {
				result.Parts = append(result.Parts, SelectedS3PartView{Number: part.Number, Bytes: part.Bytes, SHA256: part.SHA256, Confirmed: part.Confirmed})
			}
			result.State = intent.Phase
			if intent.Phase == "uploading" {
				result.State = "created"
			}
			if selected.CancelRequested {
				result.State = "aborting"
			}
		}
		if u.Check(c) != nil || ready.Check(c) != nil {
			return store.ErrNodeState
		}
		return nil
	})
	if err == nil && (result.State == "published" || result.State == "cancelled" || result.State == "deleted") {
		ready.Release()
		readyHeld = false
		if e := s.finishRecovery(ctx); e != nil {
			return SelectedS3Status{}, e
		}
	}
	return result, err
}

// finishRecovery keeps recovery closed if the full authenticated audit fails.
func (s *SelectedS3Coordinator) finishRecovery(ctx context.Context) error {
	if gate, ok := s.ready.(interface {
		FinishSelectedS3Recovery(context.Context, *sealedtree.SQLStore) error
	}); ok {
		err := gate.FinishSelectedS3Recovery(ctx, s.upload.tree)
		if err != nil && err != ErrSelectedS3RecoveryRequired {
			return err
		}
	}
	return nil
}

// NewSelectedS3Coordinator does not install a route or prove readiness. The
// actual runtime must supply its real recovery/configuration gate.
func NewSelectedS3Coordinator(upload *SelectedUploadRuntime, provider SelectedS3Provider, ready SelectedS3Readiness) (*SelectedS3Coordinator, error) {
	if upload == nil || selectedNil(provider) || selectedNil(ready) {
		return nil, store.ErrNodeState
	}
	return &SelectedS3Coordinator{upload: upload, provider: provider, ready: ready}, nil
}

func (s *SelectedS3Coordinator) lease(ctx context.Context, sessionHash, uploadID string) (SelectedUploadRuntimeLease, SelectedUploadRuntimeLease, error) {
	if s == nil || s.upload == nil || selectedNil(s.provider) || selectedNil(s.ready) {
		return nil, nil, store.ErrNodeState
	}
	upload, err := s.upload.lease(ctx, sessionHash)
	if err != nil {
		return nil, nil, err
	}
	if !nodeIDPattern.MatchString(uploadID) {
		upload.Release()
		return nil, nil, store.ErrNodeState
	}
	ready, err := s.ready.AcquireSelectedS3(ctx, s.upload.tree, uploadID)
	if err != nil || selectedNil(ready) {
		upload.Release()
		return nil, nil, store.ErrNodeState
	}
	if ready.Check(ctx) != nil {
		ready.Release()
		upload.Release()
		return nil, nil, store.ErrNodeState
	}
	return upload, ready, nil
}

// withPending binds every control step to the existing selected pending record,
// the same encrypted S3 journal and the currently authenticated bucket config.
// fn must not perform provider/network I/O or reenter the mutation handle.
func (s *SelectedS3Coordinator) withPending(ctx context.Context, uploadID string, u, ready SelectedUploadRuntimeLease, fn func(context.Context, queryer, selectedS3Intent, store.S3Member) error) error {
	return s.withPendingState(ctx, uploadID, u, ready, false, fn)
}

func (s *SelectedS3Coordinator) withPendingState(ctx context.Context, uploadID string, u, ready SelectedUploadRuntimeLease, cancelling bool, fn func(context.Context, queryer, selectedS3Intent, store.S3Member) error) error {
	if s == nil || !nodeIDPattern.MatchString(uploadID) || selectedNil(u) || selectedNil(ready) || fn == nil {
		return store.ErrNodeState
	}
	r := s.upload.repo
	return r.withSelectedMutation(ctx, s.upload.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if u.Check(c) != nil || ready.Check(c) != nil {
			return store.ErrNodeState
		}
		selected, _, found, err := r.selectedIntentAnyTx(c, q, s.upload.key, uploadID)
		if err != nil || !found || selected.State != "pending" || selected.CancelRequested != cancelling || selected.Policy != "S3" {
			return store.ErrNodeState
		}
		if err = r.selectedFinalizePolicyTx(c, q, s.upload.key, selected); err != nil {
			return err
		}
		pending, err := m.ReadSelectedFileTx(c, q, selected.Capacity.OperationID)
		if err != nil || verifySelectedPendingBinding(s.upload.key, selected, pending) != nil {
			return store.ErrNodeState
		}
		intent, err := r.ensureSelectedS3ReservationTx(c, q, s.upload.key, selected, pending, false)
		if err != nil {
			return err
		}
		member, err := r.s3Member(c, q, selected.Capacity.MemberID, r.lock())
		if err != nil {
			return err
		}
		if !cancelling && (s.ready.CheckSelectedS3Member(c, s.upload.tree, member) != nil || s.checkSelectedS3CurrentOriginTx(c, q, member) != nil) {
			return store.ErrNodeState
		}
		if err = fn(c, q, intent, member); err != nil {
			return err
		}
		if u.Check(c) != nil || ready.Check(c) != nil {
			return store.ErrNodeState
		}
		return nil
	})
}

// Begin writes creating before contacting S3. A failed or lost response remains
// recoverable as create_unknown; a second caller cannot issue another create.
// It returns no provider upload ID or object key to the browser.
func (s *SelectedS3Coordinator) Begin(ctx context.Context, sessionHash, uploadID string) (string, error) {
	u, ready, err := s.lease(ctx, sessionHash, uploadID)
	if err != nil {
		return "", err
	}
	defer u.Release()
	defer ready.Release()
	var intent selectedS3Intent
	var member store.S3Member
	err = s.withPending(ctx, uploadID, u, ready, func(c context.Context, q queryer, current selectedS3Intent, snapshot store.S3Member) error {
		if current.Phase == "uploading" {
			intent, member = current, snapshot
			return nil
		}
		if current.Phase != "reserved" {
			return store.ErrNodeState
		}
		next := current
		next.Phase = "creating"
		next.Revision++
		if err := s.upload.repo.writeSelectedS3IntentTx(c, q, s.upload.key, next, func(_ context.Context, _ queryer, old selectedS3Intent, found bool) error {
			if !found || old != current {
				return store.ErrNodeState
			}
			return nil
		}); err != nil {
			return err
		}
		intent, member = next, snapshot
		return nil
	})
	if err != nil {
		return "", err
	}
	if intent.Phase == "uploading" {
		return "uploading", nil
	}
	var providerID string
	err = s.provider.WithSelectedProvider(ctx, member, func(c context.Context, provider s3store.Provider) error {
		var callErr error
		providerID, callErr = provider.CreateMultipart(c, intent.Key, map[string]string{"fc-format": store.S3OpaqueMetadata, "fc-owner": intent.Owner})
		return callErr
	})
	phase := "uploading"
	if err != nil {
		phase = "create_unknown"
	}
	commitErr := s.withPending(ctx, uploadID, u, ready, func(c context.Context, q queryer, current selectedS3Intent, _ store.S3Member) error {
		if current != intent {
			return store.ErrNodeState
		}
		next := current
		next.Phase, next.ProviderUploadID = phase, providerID
		next.Revision++
		if phase == "create_unknown" {
			next.ProviderUploadID = ""
		}
		return s.upload.repo.writeSelectedS3IntentTx(c, q, s.upload.key, next, func(_ context.Context, _ queryer, old selectedS3Intent, found bool) error {
			if !found || old != current {
				return store.ErrNodeState
			}
			return nil
		})
	})
	if err != nil || commitErr != nil {
		return "", errors.Join(err, commitErr)
	}
	return "uploading", nil
}

// BeginOrRecover preserves the existing multipart begin contract without ever
// reissuing a create after the previous result became uncertain.
func (s *SelectedS3Coordinator) BeginOrRecover(ctx context.Context, sessionHash, uploadID string) (SelectedS3Status, error) {
	var zero SelectedS3Status
	status, err := s.Status(ctx, sessionHash, uploadID)
	if err != nil {
		return zero, err
	}
	switch status.State {
	case "reserved":
		_, err = s.Begin(ctx, sessionHash, uploadID)
	case "creating", "create_unknown":
		_, err = s.RecoverCreate(ctx, sessionHash, uploadID)
	case "created", "published", "deleted":
		return status, nil
	default:
		return zero, store.ErrNodeState
	}
	if err != nil {
		return zero, err
	}
	return s.Status(ctx, sessionHash, uploadID)
}

// PartGrant durably fixes the exact ciphertext hash/size and maximum expiry
// before the provider signs any URL. Replays may only repeat the same bytes.
func (s *SelectedS3Coordinator) PartGrant(ctx context.Context, sessionHash, uploadID string, number int, size int64, checksum string) (s3store.Grant, error) {
	var zero s3store.Grant
	u, ready, err := s.lease(ctx, sessionHash, uploadID)
	if err != nil {
		return zero, err
	}
	defer u.Release()
	defer ready.Release()
	var intent selectedS3Intent
	var member store.S3Member
	var part selectedS3Part
	err = s.withPending(ctx, uploadID, u, ready, func(c context.Context, q queryer, current selectedS3Intent, snapshot store.S3Member) error {
		if current.Phase != "uploading" {
			return store.ErrNodeState
		}
		until := time.Now().Unix() + store.S3GrantSeconds
		old, found, err := s.upload.repo.readSelectedS3PartTx(c, q, s.upload.key, current, number)
		if err != nil {
			return err
		}
		if !found || old.Confirmed || old.Bytes != size || old.SHA256 != checksum {
			return store.ErrNodeState
		}
		part = selectedS3Part{OperationID: current.OperationID, Number: number, Bytes: size, SHA256: checksum, GrantUntil: until, Revision: old.Revision + 1}
		if old.GrantUntil > until {
			part.GrantUntil = old.GrantUntil
		}
		if !validSelectedS3Part(part, current) {
			return store.ErrNodeState
		}
		if part.GrantUntil > current.GrantUntil {
			next := current
			next.Revision++
			next.GrantUntil = part.GrantUntil
			if err = s.upload.repo.writeSelectedS3IntentTx(c, q, s.upload.key, next, func(_ context.Context, _ queryer, old selectedS3Intent, exists bool) error {
				if !exists || old != current {
					return store.ErrNodeState
				}
				return nil
			}); err != nil {
				return err
			}
			current = next
		}
		if _, err = s.upload.repo.writeSelectedS3PartTx(c, q, s.upload.key, current, part, func(context.Context, queryer, selectedS3Part, bool) error { return nil }); err != nil {
			return err
		}
		intent, member = current, snapshot
		return nil
	})
	if err != nil {
		return zero, err
	}
	var grant s3store.Grant
	err = s.provider.WithSelectedProvider(ctx, member, func(c context.Context, provider s3store.Provider) error {
		duration := time.Until(time.Unix(part.GrantUntil, 0)).Truncate(time.Second)
		if duration <= 0 || duration > time.Duration(store.S3GrantSeconds)*time.Second {
			return store.ErrNodeState
		}
		var e error
		grant, e = provider.PresignPart(c, intent.Key, intent.ProviderUploadID, int32(number), size, checksum, duration)
		return e
	})
	if err != nil || grant.ExpiresAt <= time.Now().Unix() || grant.ExpiresAt > part.GrantUntil || u.Check(ctx) != nil || ready.Check(ctx) != nil {
		return zero, store.ErrNodeState
	}
	// Signing can take network time. Recheck the persisted part and current
	// ingress under the same fence before exposing this bearer URL.
	if err = s.withPending(ctx, uploadID, u, ready, func(c context.Context, q queryer, current selectedS3Intent, snapshot store.S3Member) error {
		if current != intent || snapshot.Revision != member.Revision {
			return store.ErrNodeState
		}
		stored, found, e := s.upload.repo.readSelectedS3PartTx(c, q, s.upload.key, current, number)
		if e != nil || !found || stored != part {
			return store.ErrNodeState
		}
		return nil
	}); err != nil {
		return zero, err
	}
	return grant, nil
}

// ConfirmPart accepts only a provider-observed part matching the already
// durable grant; a response from the browser cannot invent the ETag or hash.
func (s *SelectedS3Coordinator) ConfirmPart(ctx context.Context, sessionHash, uploadID string, number int) (store.S3Part, error) {
	var zero store.S3Part
	u, ready, err := s.lease(ctx, sessionHash, uploadID)
	if err != nil {
		return zero, err
	}
	defer u.Release()
	defer ready.Release()
	var intent selectedS3Intent
	var member store.S3Member
	var expected selectedS3Part
	err = s.withPending(ctx, uploadID, u, ready, func(c context.Context, q queryer, current selectedS3Intent, snapshot store.S3Member) error {
		if current.Phase != "uploading" {
			return store.ErrNodeState
		}
		part, found, err := s.upload.repo.readSelectedS3PartTx(c, q, s.upload.key, current, number)
		if err != nil || !found {
			return store.ErrNodeState
		}
		intent, member, expected = current, snapshot, part
		return nil
	})
	if err != nil {
		return zero, err
	}
	var observed s3store.Part
	err = s.provider.WithSelectedProvider(ctx, member, func(c context.Context, provider s3store.Provider) error {
		parts, e := provider.ListParts(c, intent.Key, intent.ProviderUploadID)
		if e != nil {
			return e
		}
		found := false
		for _, part := range parts {
			if int(part.Number) != number {
				continue
			}
			if found || part.Size != expected.Bytes || part.SHA256 != expected.SHA256 {
				return store.ErrNodeState
			}
			found, observed = true, part
		}
		if !found {
			return s3store.ErrIncomplete
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	var result selectedS3Part
	err = s.withPending(ctx, uploadID, u, ready, func(c context.Context, q queryer, current selectedS3Intent, _ store.S3Member) error {
		if current.Phase != "uploading" || current.OperationID != intent.OperationID || current.ProviderUploadID != intent.ProviderUploadID || current.LocationBinding != intent.LocationBinding {
			return store.ErrNodeState
		}
		part, found, err := s.upload.repo.readSelectedS3PartTx(c, q, s.upload.key, current, number)
		if err != nil || !found || part.Bytes != observed.Size || part.SHA256 != observed.SHA256 {
			return store.ErrNodeState
		}
		if part.Confirmed {
			if part.ETag != observed.ETag {
				return store.ErrNodeState
			}
			result = part
			return nil
		}
		part.Revision++
		part.Confirmed, part.ETag = true, observed.ETag
		if _, err = s.upload.repo.writeSelectedS3PartTx(c, q, s.upload.key, current, part, func(context.Context, queryer, selectedS3Part, bool) error { return nil }); err != nil {
			return err
		}
		result = part
		return nil
	})
	if err != nil {
		return zero, err
	}
	return store.S3Part{Number: result.Number, Bytes: result.Bytes, SHA256: result.SHA256, ETag: result.ETag, Confirmed: true, GrantUntil: result.GrantUntil}, nil
}

// Complete checkpoints the completing state before the provider operation. A
// lost response retries exact-key HEAD first; an ambiguous outcome never
// releases quota or invents a completion receipt.
func (s *SelectedS3Coordinator) Complete(ctx context.Context, sessionHash, uploadID string) (SelectedS3Status, error) {
	var zero SelectedS3Status
	status, err := s.Status(ctx, sessionHash, uploadID)
	if err != nil {
		return zero, err
	}
	if status.State == "published" || status.State == "deleted" {
		return status, nil
	}
	u, ready, err := s.lease(ctx, sessionHash, uploadID)
	if err != nil {
		return zero, err
	}
	defer u.Release()
	readyHeld := true
	defer func() {
		if readyHeld {
			ready.Release()
		}
	}()
	var intent selectedS3Intent
	var member store.S3Member
	var parts []store.S3Part
	err = s.withPending(ctx, uploadID, u, ready, func(c context.Context, q queryer, current selectedS3Intent, snapshot store.S3Member) error {
		if current.Phase == "uploading" {
			next := current
			next.Phase = "completing"
			next.Revision++
			if err := s.upload.repo.writeSelectedS3IntentTx(c, q, s.upload.key, next, func(_ context.Context, _ queryer, old selectedS3Intent, found bool) error {
				if !found || old != current {
					return store.ErrNodeState
				}
				return nil
			}); err != nil {
				return err
			}
			current = next
		} else if current.Phase != "completing" {
			return store.ErrNodeState
		}
		var err error
		parts, err = s.upload.repo.completeSelectedS3PartsTx(c, q, s.upload.key, current)
		if err != nil {
			return err
		}
		intent, member = current, snapshot
		return nil
	})
	if err != nil {
		return zero, err
	}
	var observed s3store.Proof
	err = s.provider.WithSelectedProvider(ctx, member, func(c context.Context, provider s3store.Provider) error {
		var e error
		observed, e = provider.Head(c, intent.Key, "")
		if !errors.Is(e, s3store.ErrNotFound) {
			return e
		}
		remote, e := provider.ListParts(c, intent.Key, intent.ProviderUploadID)
		if e != nil {
			return e
		}
		if len(remote) != len(parts) {
			return s3store.ErrIncomplete
		}
		for i, part := range remote {
			wanted := parts[i]
			if int(part.Number) != wanted.Number || part.Size != wanted.Bytes || part.SHA256 != wanted.SHA256 || part.ETag != wanted.ETag {
				return store.ErrNodeState
			}
		}
		observed, e = provider.Complete(c, intent.Key, intent.ProviderUploadID, remote)
		return e
	})
	if err != nil {
		return zero, err
	}
	_, err = s.upload.repo.finalizeSelectedS3(ctx, s.upload.tree, s.upload.key, uploadID, observed, func(c context.Context) error {
		if u.Check(c) != nil || ready.Check(c) != nil {
			return store.ErrNodeState
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	status.State, status.Reservation.ExpectedBytes, status.Parts = "published", intent.Bytes, []SelectedS3PartView{}
	ready.Release()
	readyHeld = false
	if err = s.finishRecovery(ctx); err != nil {
		return zero, err
	}
	return status, nil
}
