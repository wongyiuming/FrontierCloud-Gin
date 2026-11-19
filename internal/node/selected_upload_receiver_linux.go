//go:build linux

package node

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// SelectedDirectReceiver binds the actual service, Owner fence and media
// volume. It has no registered route; startup must additionally prove that
// legacy writers and unfinished Owner operations are drained/reconciled.
type SelectedDirectReceiver struct {
	service *Service
	fence   *ownerfence.Fence
	volume  any
}

// Relay requests authenticate the bounded ticket bytes with the paired Node
// credential. The ticket independently binds the streamed ciphertext digest.
func (r *SelectedDirectReceiver) Relay(ctx context.Context, headers http.Header, method, path, token string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration) (protocol.OpaqueCapacityReceipt, string, error) {
	var zero protocol.OpaqueCapacityReceipt
	if !r.valid(ctx) || token == "" || len(token) > 4096 || deadline == nil || body == nil {
		return zero, "", ErrCapability
	}
	const base = "/internal/v1/selected-upload/relay"
	cleanup, recoverExisting := false, false
	switch {
	case method == http.MethodPut && path == base:
	case method == http.MethodPost && path == base+"/recover":
		recoverExisting = true
	case method == http.MethodPost && path == base+"/cleanup":
		cleanup = true
	default:
		return zero, "", ErrCapability
	}
	relation, err := r.service.Authenticate(ctx, headers, method, path, []byte(token), false, false)
	if err != nil || relation.Direction != "upstream" || relation.State != "active" {
		return zero, "", ErrCapability
	}
	claim, lease, err := r.service.admitSelected(ctx, token, cleanup, "Relay", relation.ID)
	if err != nil {
		return zero, "", err
	}
	if claim.ExpiresAt <= time.Now().Unix() || lease.Check(ctx) != nil {
		lease.Release()
		return zero, "", ErrCapability
	}
	root := r.volume.(interface{ InventoryRoot() *os.Root }).InventoryRoot()
	if cleanup {
		return r.service.cleanupSelectedAdmitted(ctx, claim, lease, deadline, body, maximum, root)
	}
	return r.service.runSelectedAdmitted(ctx, claim, lease, deadline, body, maximum, root, recoverExisting)
}

func NewSelectedDirectReceiver(ctx context.Context, service *Service, fence *ownerfence.Fence) (*SelectedDirectReceiver, error) {
	if ctx == nil || service == nil || service.repo == nil || service.identity == nil || fence == nil || service.volume == nil {
		return nil, ErrCapability
	}
	r := &SelectedDirectReceiver{service: service, fence: fence, volume: service.volume}
	if !r.valid(ctx) {
		return nil, ErrCapability
	}
	return r, nil
}

func (r *SelectedDirectReceiver) valid(ctx context.Context) bool {
	if r == nil || ctx == nil || ctx.Err() != nil || r.service == nil || r.service.repo == nil || r.service.identity == nil || r.fence == nil || !sameLegacyVolume(r.service.volume, r.volume) {
		return false
	}
	v, ok := r.volume.(interface {
		VerifyLegacyOwnerVolume(context.Context, store.NodeRepository, *Identity, *ownerfence.Fence) error
		InventoryRoot() *os.Root
	})
	return ok && v.InventoryRoot() != nil && v.VerifyLegacyOwnerVolume(ctx, r.service.repo, r.service.identity, r.fence) == nil
}

func (r *SelectedDirectReceiver) ReadyFor(service *Service, volume any) bool {
	return r != nil && service != nil && r.service == service && sameLegacyVolume(r.volume, volume) && sameLegacyVolume(service.volume, volume)
}

func (r *SelectedDirectReceiver) Receive(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration) (protocol.OpaqueCapacityReceipt, string, error) {
	if !r.valid(ctx) {
		return protocol.OpaqueCapacityReceipt{}, "", ErrCapability
	}
	return r.service.receiveSelectedDirect(ctx, token, origin, deadline, body, maximum, r.volume.(interface{ InventoryRoot() *os.Root }).InventoryRoot())
}

func (r *SelectedDirectReceiver) Recover(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration) (protocol.OpaqueCapacityReceipt, string, error) {
	if !r.valid(ctx) {
		return protocol.OpaqueCapacityReceipt{}, "", ErrCapability
	}
	return r.service.recoverSelectedDirect(ctx, token, origin, deadline, body, maximum, r.volume.(interface{ InventoryRoot() *os.Root }).InventoryRoot())
}

func (r *SelectedDirectReceiver) Cleanup(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration) (protocol.OpaqueCapacityReceipt, string, error) {
	if !r.valid(ctx) {
		return protocol.OpaqueCapacityReceipt{}, "", ErrCapability
	}
	return r.service.cleanupSelectedDirect(ctx, token, origin, deadline, body, maximum, r.volume.(interface{ InventoryRoot() *os.Root }).InventoryRoot())
}

// AllowsBrowserOrigin performs a fresh Master challenge for preflight. Actual requests also
// require a signed operation capability bound to this exact observation.
func (r *SelectedDirectReceiver) AllowsBrowserOrigin(ctx context.Context, origin string) bool {
	if !r.valid(ctx) || origin == "" {
		return false
	}
	observed, err := r.service.FreshSelectedAdminOrigin(ctx, "")
	return err == nil && observed == origin
}
