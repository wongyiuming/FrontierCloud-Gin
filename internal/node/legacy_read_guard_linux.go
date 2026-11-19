//go:build linux

package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// LegacyReadGuard is an isolated adapter. It is not installed by startup;
// enrollment, every writer and reader, old-process drain and restore anchors
// must be proven before it can be used for activation.
type LegacyReadGuard struct {
	service *Service
	fence   *ownerfence.Fence
	volume  any
	control chan struct{}
	status  chan struct{}
}

func sameLegacyVolume(a, b any) bool {
	x, y := reflect.ValueOf(a), reflect.ValueOf(b)
	return x.IsValid() && y.IsValid() && x.Kind() == reflect.Pointer && y.Kind() == reflect.Pointer && !x.IsNil() && !y.IsNil() && x.Type() == y.Type() && x.Pointer() == y.Pointer()
}

func (g *LegacyReadGuard) validVolume(ctx context.Context) bool {
	if g == nil || g.service == nil || g.service.repo == nil || g.service.identity == nil || g.fence == nil || !sameLegacyVolume(g.service.volume, g.volume) {
		return false
	}
	volume, ok := g.service.volume.(interface {
		VerifyLegacyOwnerVolume(context.Context, store.NodeRepository, *Identity, *ownerfence.Fence) error
	})
	return ok && volume.VerifyLegacyOwnerVolume(ctx, g.service.repo, g.service.identity, g.fence) == nil
}

func (g *LegacyReadGuard) ReadyFor(service *Service, volume any) bool {
	if g == nil || service == nil || g.service != service || service.repo == nil || service.identity == nil || g.fence == nil || volume == nil || !sameLegacyVolume(service.volume, g.volume) {
		return false
	}
	return sameLegacyVolume(g.volume, volume)
}

func NewLegacyReadGuard(service *Service, fence *ownerfence.Fence, nginxAccel bool) (*LegacyReadGuard, error) {
	if service == nil || service.repo == nil || service.identity == nil || fence == nil || nginxAccel {
		return nil, ErrCapability
	}
	if _, ok := service.repo.(interface {
		VerifyOwnerControlBinding(context.Context, string) error
	}); !ok {
		return nil, ErrCapability
	}
	guard := &LegacyReadGuard{service: service, fence: fence, volume: service.volume, control: make(chan struct{}, 1), status: make(chan struct{}, 1)}
	if !guard.validVolume(context.Background()) {
		return nil, ErrCapability
	}
	return guard, nil
}

// LegacyReadScope authenticates the local owner and relationship instances.
// It contains digests, never the sealed private key or credential themselves.
func (s *Service) LegacyReadScope(ctx context.Context, relationship string) (ownerfence.LegacyReadScope, error) {
	var scope ownerfence.LegacyReadScope
	if s == nil || s.repo == nil || s.identity == nil || ctx == nil {
		return scope, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" || identity.ID == "" || identity.PrivateKey == "" {
		return scope, ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, relationship)
	if err != nil || relation.State != "active" || relation.Direction != "upstream" || relation.Protocol != protocol.Version || relation.PeerID == "" {
		return scope, ErrCapability
	}
	encoded, err := protocol.Canonical(map[string]any{"id": identity.ID, "role": identity.Role, "endpoint": identity.Endpoint, "private_key": identity.PrivateKey, "created_at": identity.CreatedAt})
	if err != nil {
		return scope, ErrCapability
	}
	sum := sha256.Sum256(append([]byte("frontiercloud:legacy-owner-instance:v1\x00"), encoded...))
	clear(encoded)
	scope = ownerfence.LegacyReadScope{MasterID: relation.PeerID, OwnerID: identity.ID, RelationshipID: relation.ID, RelationshipBinding: opaqueRelationshipBinding(relation), OwnerBinding: hex.EncodeToString(sum[:])}
	return scope, nil
}

func (g *LegacyReadGuard) verify(ctx context.Context, scope ownerfence.LegacyReadScope, binding string) error {
	verifier, ok := g.service.repo.(interface {
		VerifyOwnerControlBinding(context.Context, string) error
	})
	if !ok || !g.validVolume(ctx) || verifier.VerifyOwnerControlBinding(ctx, binding) != nil {
		return ErrCapability
	}
	current, err := g.service.LegacyReadScope(ctx, scope.RelationshipID)
	if err != nil || current != scope || ctx.Err() != nil {
		return ErrCapability
	}
	return nil
}

// WithRead performs the legacy token verification again under the local
// shared lock, and retains that lock through the entire synchronous Go stream.
func (g *LegacyReadGuard) WithRead(ctx context.Context, token, object string, stream func(context.Context) error) error {
	if g == nil || g.service == nil || g.fence == nil || stream == nil {
		return ErrCapability
	}
	relation, _, err := g.service.VerifyOwnedMedia(ctx, token, object)
	if err != nil || !g.validVolume(ctx) {
		return ErrCapability
	}
	scope, err := g.service.LegacyReadScope(ctx, relation.ID)
	if err != nil {
		return ErrCapability
	}
	lease, err := g.fence.AcquireLegacyRead(ctx, scope)
	if err != nil {
		return ErrCapability
	}
	defer lease.Release()
	return lease.WithStream(ctx, func(held context.Context, ownerLease *ownerfence.Lease) error {
		binding, err := ownerLease.Binding(held)
		if err != nil || g.verify(held, scope, binding) != nil {
			return ErrCapability
		}
		current, _, err := g.service.VerifyOwnedMedia(held, token, object)
		if err != nil || opaqueRelationshipBinding(current) != scope.RelationshipBinding || ownerLease.Check(held) != nil {
			return ErrCapability
		}
		return nil
	}, stream)
}

// AttestEnrollment returns only owner-computed scope, signed after authenticating
// the paired Master under the same short owner lock. The Master must persist
// the exact signed result and its own pair binding before requesting a drain.
func (g *LegacyReadGuard) AttestEnrollment(ctx context.Context, request protocol.LegacyReadEnrollmentRequest, authenticate func(context.Context) (store.Relationship, error)) (Envelope, error) {
	if g == nil || ctx == nil || g.control == nil || !request.Valid() || authenticate == nil {
		return Envelope{}, ErrCapability
	}
	select {
	case g.control <- struct{}{}:
		defer func() { <-g.control }()
	default:
		return Envelope{}, ErrCapability
	}
	if !g.validVolume(ctx) {
		return Envelope{}, ErrCapability
	}
	scope, err := g.service.LegacyReadScope(ctx, request.RelationshipID)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	lease, err := g.fence.AcquireLegacyRead(ctx, scope)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	defer lease.Release()
	var signed Envelope
	err = lease.WithStream(ctx, func(held context.Context, ownerLease *ownerfence.Lease) error {
		relation, err := authenticate(held)
		if err != nil || relation.ID != scope.RelationshipID || opaqueRelationshipBinding(relation) != scope.RelationshipBinding {
			return ErrCapability
		}
		binding, err := ownerLease.Binding(held)
		if err != nil || g.verify(held, scope, binding) != nil {
			return ErrCapability
		}
		receipt := protocol.LegacyReadEnrollmentReceipt{Kind: "legacy-media-enrollment-v1", Challenge: request.Challenge, MasterID: scope.MasterID, OwnerID: scope.OwnerID, RelationshipID: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding, OwnerBinding: scope.OwnerBinding, FenceBinding: binding, State: "active"}
		payload, err := receipt.Payload()
		if err != nil {
			return ErrCapability
		}
		signed, err = g.service.signOpaqueOwnerReceipt(held, relation, scope.MasterID, scope.OwnerID, scope.RelationshipID, payload)
		if err != nil || ownerLease.Check(held) != nil || g.verify(held, scope, binding) != nil {
			return ErrCapability
		}
		return nil
	}, func(context.Context) error { return nil })
	if err != nil {
		return Envelope{}, ErrCapability
	}
	return signed, nil
}

// Drain authenticates the Master inside the owner's exclusive lease. Only the
// same operation may retry a persisted revocation. No network I/O belongs in
// authenticate: it must verify the already-received signed HTTP request.
func (g *LegacyReadGuard) Drain(ctx context.Context, receipt protocol.LegacyReadDrainReceipt, authenticate func(context.Context) (store.Relationship, error)) (Envelope, error) {
	if g == nil || ctx == nil || g.control == nil || authenticate == nil {
		return Envelope{}, ErrCapability
	}
	select {
	case g.control <- struct{}{}:
		defer func() { <-g.control }()
	default:
		return Envelope{}, ErrCapability
	}
	if !g.validVolume(ctx) {
		return Envelope{}, ErrCapability
	}
	payload, err := receipt.Payload()
	if err != nil || receipt.ExpiresAt <= time.Now().Unix() || receipt.ExpiresAt > time.Now().Unix()+300 {
		return Envelope{}, ErrCapability
	}
	scope := ownerfence.LegacyReadScope{MasterID: receipt.MasterID, OwnerID: receipt.OwnerID, RelationshipID: receipt.RelationshipID, RelationshipBinding: receipt.RelationshipBinding, OwnerBinding: receipt.OwnerBinding}
	var relation store.Relationship
	var signed Envelope
	check := func(held context.Context, lease *ownerfence.Lease) error {
		binding, err := lease.Binding(held)
		if err != nil || time.Now().Unix() >= receipt.ExpiresAt || binding != receipt.FenceBinding || g.verify(held, scope, binding) != nil || lease.Check(held) != nil {
			return ErrCapability
		}
		return nil
	}
	err = g.fence.RevokeLegacyReadChecked(ctx, scope, receipt.OperationID, receipt.Challenge, receipt.ExpiresAt, func(held context.Context, lease *ownerfence.Lease) error {
		var err error
		relation, err = authenticate(held)
		if err != nil || relation.ID != scope.RelationshipID || opaqueRelationshipBinding(relation) != scope.RelationshipBinding || check(held, lease) != nil {
			return ErrCapability
		}
		return nil
	}, check, func(held context.Context, lease *ownerfence.Lease) error {
		if check(held, lease) != nil {
			return ErrCapability
		}
		var err error
		signed, err = g.service.signOpaqueOwnerReceipt(held, relation, receipt.MasterID, receipt.OwnerID, receipt.RelationshipID, payload)
		if err != nil {
			return ErrCapability
		}
		return check(held, lease)
	})
	if err != nil {
		return Envelope{}, ErrCapability
	}
	return signed, nil
}

// ObserveStatus signs only the exact persisted draining/revoked operation for
// a fresh Master challenge. It never reactivates a legacy capability.
func (g *LegacyReadGuard) ObserveStatus(ctx context.Context, request protocol.LegacyReadStatusRequest, authenticate func(context.Context) (store.Relationship, error)) (Envelope, error) {
	if g == nil || ctx == nil || g.status == nil || authenticate == nil {
		return Envelope{}, ErrCapability
	}
	if _, err := request.Receipt("revoked"); err != nil {
		return Envelope{}, ErrCapability
	}
	if request.ExpiresAt <= time.Now().Unix() || request.ExpiresAt > time.Now().Unix()+300 {
		return Envelope{}, ErrCapability
	}
	bounded, cancel := context.WithDeadline(ctx, time.Unix(request.ExpiresAt, 0))
	defer cancel()
	ctx = bounded
	select {
	case g.status <- struct{}{}:
		defer func() { <-g.status }()
	default:
		return Envelope{}, ErrCapability
	}
	if !g.validVolume(ctx) {
		return Envelope{}, ErrCapability
	}
	scope := ownerfence.LegacyReadScope{MasterID: request.MasterID, OwnerID: request.OwnerID, RelationshipID: request.RelationshipID, RelationshipBinding: request.RelationshipBinding, OwnerBinding: request.OwnerBinding}
	var relation store.Relationship
	var signed Envelope
	check := func(held context.Context, lease *ownerfence.Lease) error {
		binding, err := lease.Binding(held)
		if err != nil || time.Now().Unix() >= request.ExpiresAt || binding != request.FenceBinding || g.verify(held, scope, binding) != nil || lease.Check(held) != nil {
			return ErrCapability
		}
		return nil
	}
	authorize := func(held context.Context, lease *ownerfence.Lease) error {
		var err error
		relation, err = authenticate(held)
		if err != nil || relation.ID != scope.RelationshipID || opaqueRelationshipBinding(relation) != scope.RelationshipBinding {
			return ErrCapability
		}
		return check(held, lease)
	}
	commit := func(held context.Context, lease *ownerfence.Lease, state string) error {
		if check(held, lease) != nil {
			return ErrCapability
		}
		receipt, err := request.Receipt(state)
		if err != nil {
			return ErrCapability
		}
		payload, err := receipt.Payload()
		if err != nil {
			return ErrCapability
		}
		signed, err = g.service.signOpaqueOwnerReceipt(held, relation, scope.MasterID, scope.OwnerID, scope.RelationshipID, payload)
		if err != nil {
			return ErrCapability
		}
		return check(held, lease)
	}
	var err error
	if request.Action == "resume" {
		err = g.fence.ResumeLegacyRead(ctx, scope, request.OriginalOperationID, request.OriginalChallenge, request.OriginalExpiresAt, request.ExpiresAt, authorize, check, func(held context.Context, lease *ownerfence.Lease) error { return commit(held, lease, "revoked") })
	} else {
		err = g.fence.ObserveLegacyReadStatus(ctx, scope, request.OriginalOperationID, request.OriginalChallenge, request.OriginalExpiresAt, authorize, commit)
	}
	if err != nil {
		return Envelope{}, ErrCapability
	}
	return signed, nil
}
