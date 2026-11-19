package business

import (
	"context"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// checkRecordingAudioAuthorityTx only performs local, bounded checks. It
// must be called while the caller holds the usual fenced SQL transaction.
// The Redis account-session revocation problem is deliberately not claimed by
// this check; runtime activation must provide that independent authority.
func (s *SelectedUploadRuntime) checkRecordingAudioAuthorityTx(c context.Context, q queryer, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID, member string) error {
	master, err := s.checkRecordingAudioSessionTx(c, q, expected, user, browser, sessionID)
	if err != nil {
		return err
	}
	if master.ID != member {
		return store.ErrNodeState
	}
	return nil
}

func (s *SelectedUploadRuntime) checkRecordingAudioSessionTx(c context.Context, q queryer, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID string) (store.NodeIdentity, error) {
	if c.Err() != nil || user.PasswordHash == "" || user.Status != "active" || user.CreatedAt <= 0 {
		return store.NodeIdentity{}, store.ErrRecordingState
	}
	actualBinding, actualID, actualExpiry, valid := mediacrypto.DirectSessionFromContext(c).Values()
	if !valid || actualBinding != browser || actualID != sessionID {
		return store.NodeIdentity{}, store.ErrRecordingState
	}
	verifiedCtx, e := s.crypto.WithDirectSession(c, browser, sessionID)
	if e != nil {
		return store.NodeIdentity{}, store.ErrRecordingState
	}
	verifiedBinding, verifiedID, verifiedExpiry, valid := mediacrypto.DirectSessionFromContext(verifiedCtx).Values()
	if !valid || verifiedBinding != actualBinding || verifiedID != actualID || verifiedExpiry != actualExpiry {
		return store.NodeIdentity{}, store.ErrRecordingState
	}
	current, e := scanUser(q.QueryRowContext(c, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+s.repo.lock(), user.ID))
	if e != nil || current.Status != "active" || current.PasswordHash != user.PasswordHash || current.CreatedAt != user.CreatedAt {
		return store.NodeIdentity{}, store.ErrRecordingState
	}
	return s.checkRecordingAudioIngressTx(c, q, expected)
}

func (s *SelectedUploadRuntime) checkRecordingAudioIngressTx(c context.Context, q queryer, expected store.PublicIngress) (store.NodeIdentity, error) {
	if expected.Generation < 1 || !nodeIDPattern.MatchString(expected.NodeID) || !validPublicOrigin(expected.PublicOrigin) {
		return store.NodeIdentity{}, store.ErrNodeState
	}
	var ingress store.PublicIngress
	if e := q.QueryRowContext(c, "SELECT node_id,public_origin,generation FROM public_ingress_config WHERE singleton=1"+s.repo.lock()).Scan(&ingress.NodeID, &ingress.PublicOrigin, &ingress.Generation); e != nil || ingress != expected {
		return store.NodeIdentity{}, store.ErrNodeState
	}
	master, e := readNode(c, q, s.repo.lock())
	if e != nil || master.Role != "Master" {
		return store.NodeIdentity{}, store.ErrNodeState
	}
	if ingress.NodeID == master.ID {
		if s.repo.configuredPublicOrigin() == "" || ingress.PublicOrigin != s.repo.configuredPublicOrigin() {
			return store.NodeIdentity{}, store.ErrNodeState
		}
	} else if !s.repo.peerIngressEnabled.Load() || validateActivePeerIngress(c, q, ingress.NodeID, ingress.PublicOrigin) != nil {
		return store.NodeIdentity{}, store.ErrNodeState
	}
	return master, c.Err()
}

// AdmitRecordingAudioTicket is a startup-injected, Master-side admission.
// The HTTP layer must authenticate the account and bind a live direct crypto
// session before calling it. This method rechecks their SQL and crypto state
// under the same fences and transaction as the reservation. It does not
// provide an upload route or establish account-session revocation authority.
// Until those authorities and recovery are wired, callers must keep the
// product route disabled.
func (s *SelectedUploadRuntime) AdmitRecordingAudioTicket(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser string, request store.RecordingAudioTicketRequest, audit store.KaraokeAudit) error {
	if s == nil || s.repo == nil || ctx == nil || tree == nil || tree != s.tree || s.crypto == nil || selectedNil(s.gate) || selectedNil(s.local) || !request.Valid() || user.PasswordHash == "" || user.Status != "active" || user.CreatedAt <= 0 {
		return store.ErrRecordingState
	}
	binding, err := store.RecordingAudioPreparationBinding(user.ID, browser, request.RecordingID)
	if err != nil {
		return store.ErrRecordingState
	}
	// Local is the sole Owner with a complete staged write/recovery primitive
	// here. Other modes must not acquire a reservation until wired end-to-end.
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || request.MemberID != identity.ID {
		return store.ErrNodeState
	}
	lease, err := s.gate.AcquireSelectedUpload(ctx, tree)
	if err != nil || selectedNil(lease) {
		return store.ErrNodeState
	}
	defer lease.Release()
	if lease.Check(ctx) != nil {
		return store.ErrNodeState
	}
	free, err := s.local.SelectedLocalFree(ctx)
	if err != nil || free < 0 {
		return store.ErrStorageCapacity
	}
	check := func(c context.Context, q queryer, in recordingAudioAdmission) error {
		if c.Err() != nil || lease.Check(c) != nil {
			return store.ErrRecordingState
		}
		if s.checkRecordingAudioAuthorityTx(c, q, expected, user, browser, request.SessionID, request.MemberID) != nil || s.crypto.VerifyTransientPreparation(binding, request.PreparationToken, in.Encryption) != nil {
			return store.ErrRecordingState
		}
		return c.Err()
	}
	in := recordingAudioAdmission{UserID: user.ID, RecordingID: request.RecordingID, MemberID: request.MemberID, Digest: request.CipherSHA256, Binding: binding, Title: request.Title, ContentType: request.ContentType, Encryption: request.Encryption}
	_, _, err = s.repo.reserveRecordingAudioCoordinated(ctx, tree, s.key, in, free, audit, check)
	return err
}

// UploadRecordingAudioLocal composes the existing encrypted Owner stage and
// signed settlement with account/session checks. It is not an HTTP endpoint;
// trusted startup must supply this runtime only after recovery readiness and
// real account-session revocation authority have been established.
func (s *SelectedUploadRuntime) UploadRecordingAudioLocal(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, recordingID, action string, contentLength int64, deadline selectedupload.ReadDeadline, body io.ReadCloser, audit store.KaraokeAudit, checkAccount func(context.Context) error) (bool, error) {
	if s == nil || s.repo == nil || ctx == nil || tree == nil || tree != s.tree || s.crypto == nil || selectedNil(s.gate) || selectedNil(s.local) || s.vault == nil || checkAccount == nil || (action != "upload" && action != "recover") || (action == "upload" && contentLength <= 0) || (action == "recover" && contentLength != 0) {
		return false, store.ErrRecordingState
	}
	actualBrowser, sessionID, _, valid := mediacrypto.DirectSessionFromContext(ctx).Values()
	if !valid || actualBrowser != browser || checkAccount(ctx) != nil {
		return false, store.ErrRecordingState
	}
	binding, err := store.RecordingAudioPreparationBinding(user.ID, browser, recordingID)
	if err != nil {
		return false, store.ErrRecordingState
	}
	if action == "recover" {
		lease, e := s.gate.AcquireSelectedUpload(ctx, tree)
		if e != nil || selectedNil(lease) {
			return false, store.ErrNodeState
		}
		if lease.Check(ctx) != nil {
			lease.Release()
			return false, store.ErrNodeState
		}
		ready, e := s.recordingAudioReady(ctx, expected, user, browser, sessionID, recordingID)
		if e == nil {
			e = lease.Check(ctx)
		}
		lease.Release()
		if e != nil {
			return false, e
		}
		if ready {
			if checkAccount(ctx) != nil {
				return false, store.ErrRecordingState
			}
			return true, nil
		}
	}
	return s.repo.uploadRecordingAudioLocalChecked(ctx, tree, s.key, s.vault, s.gate, s.local, user.ID, recordingID, action, contentLength, deadline, body, audit, func(c context.Context, q queryer, intent recordingAudioIntent) error {
		if intent.Binding != binding || intent.UserID != user.ID || intent.RecordingID != recordingID {
			return store.ErrRecordingState
		}
		return s.checkRecordingAudioAuthorityTx(c, q, expected, user, browser, sessionID, intent.MemberID)
	}, checkAccount)
}
