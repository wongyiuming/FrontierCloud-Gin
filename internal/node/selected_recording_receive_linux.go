//go:build linux

package node

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
)

// AllowsRecordingOrigin admits CORS preflight for the observed public ingress.
// The actual request also requires a signed recording grant for that ingress.
func (r *SelectedDirectReceiver) AllowsRecordingOrigin(ctx context.Context, origin string) bool {
	if !r.valid(ctx) || origin == "" {
		return false
	}
	ingress, _, err := r.service.ObservedPublicIngress(ctx)
	return err == nil && ingress.PublicOrigin == origin
}

func (r *SelectedDirectReceiver) ReceiveRecording(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration) (protocol.OpaqueCapacityReceipt, string, error) {
	return r.recordingDirect(ctx, token, origin, deadline, body, maximum, false, false)
}

func (r *SelectedDirectReceiver) RecoverRecording(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration) (protocol.OpaqueCapacityReceipt, string, error) {
	return r.recordingDirect(ctx, token, origin, deadline, body, maximum, true, false)
}

func (r *SelectedDirectReceiver) CleanupRecording(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration) (protocol.OpaqueCapacityReceipt, string, error) {
	return r.recordingDirect(ctx, token, origin, deadline, body, maximum, false, true)
}

func (r *SelectedDirectReceiver) recordingDirect(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration, recoverExisting, cleanup bool) (protocol.OpaqueCapacityReceipt, string, error) {
	var zero protocol.OpaqueCapacityReceipt
	if !r.valid(ctx) || origin == "" || deadline == nil || body == nil {
		return zero, "", ErrCapability
	}
	verify := protocol.VerifySelectedRecordingUpload
	if cleanup {
		verify = protocol.VerifySelectedRecordingCleanup
	}
	claim, lease, err := r.service.admitSelectedCapability(ctx, token, "Direct", "", verify)
	if err != nil {
		return zero, "", err
	}
	if !r.service.recordingOriginAuthorized(ctx, claim, origin) || claim.ExpiresAt <= time.Now().Unix() || lease.Check(ctx) != nil {
		lease.Release()
		return zero, "", ErrCapability
	}
	root := r.volume.(interface{ InventoryRoot() *os.Root }).InventoryRoot()
	if cleanup {
		return r.service.cleanupSelectedAdmitted(ctx, claim, lease, deadline, body, maximum, root)
	}
	return r.service.runSelectedAdmitted(ctx, claim, lease, deadline, body, maximum, root, recoverExisting)
}

func (s *Service) recordingOriginAuthorized(ctx context.Context, claim protocol.SelectedStorageUpload, origin string) bool {
	ingress, relation, err := s.ObservedPublicIngress(ctx)
	return err == nil && relation.ID == claim.Relationship && relation.PeerID == claim.Master &&
		ingress.NodeID == claim.RecordingIngressNode && ingress.Generation == claim.RecordingIngressGeneration &&
		ingress.PublicOrigin == claim.AdminOrigin && ingress.PublicOrigin == origin
}
