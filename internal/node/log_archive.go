package node

import (
	"context"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var ErrLogArchiveNodePinned = errors.New("node retains managed log archives")

func (s *Service) LogCaptureReady() bool      { return s.logHeartbeat != nil }
func (s *Service) LockLogDestination() func() { s.logPolicyMu.Lock(); return s.logPolicyMu.Unlock }

func (s *Service) ConfigureLogArchiveProtection(check func(context.Context, string) bool) {
	s.logArchiveProtect = check
}

func (s *Service) LogArchiveTarget(ctx context.Context, member string) (logarchive.Target, error) {
	var target logarchive.Target
	if !ValidIdentifier(member) {
		return target, store.ErrNodeState
	}
	identity, e := s.repo.ReadIdentity(ctx)
	if e != nil || identity.Role != "Master" || identity.ID == member {
		return target, store.ErrNodeState
	}
	routing, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return target, store.ErrNodeState
	}
	p, e := routing.NativeTransport(ctx, member)
	if e != nil || p.ConfiguredTransport != "Direct" || p.AppliedTransport != "Direct" {
		return target, store.ErrNodeState
	}
	relations, e := s.repo.Relationships(ctx, false)
	if e != nil {
		return target, e
	}
	for _, rel := range relations {
		if rel.PeerID == member && rel.Direction == "downstream" && rel.State == "active" {
			if target.MemberID != "" {
				return logarchive.Target{}, store.ErrNodeState
			}
			origin, e := s.VerifyFollowerResourceIdentity(ctx, rel.ID)
			if e != nil {
				return target, e
			}
			target = logarchive.Target{MemberID: member, RelationshipID: rel.ID, Origin: origin}
		}
	}
	if target.MemberID == "" {
		return target, store.ErrNodeState
	}
	return target, nil
}

func (s *Service) LogArchiveCall(ctx context.Context, target logarchive.Target, value map[string]any) (map[string]any, error) {
	identity, e := s.repo.ReadIdentity(ctx)
	if e != nil || identity.Role != "Master" {
		return nil, store.ErrNodeState
	}
	rel, e := s.repo.Relationship(ctx, target.RelationshipID)
	if e != nil || rel.PeerID != target.MemberID || rel.Direction != "downstream" || rel.State != "active" {
		return nil, store.ErrNodeState
	}
	wire, e := logarchive.ControlValue(value)
	if e != nil {
		return nil, e
	}
	return s.Call(ctx, rel, "/internal/v1/log-archive", wire)
}

// LogReadGrant gives an archive node read authority but contains no data key.
// The separate authenticated Admin response delivers the key to the browser.
func (s *Service) LogReadGrant(ctx context.Context, target logarchive.Target, ref logarchive.Reference, audience string) (Envelope, error) {
	if !ref.Valid() || MasterOriginInvalid(audience) {
		return Envelope{}, store.ErrNodeState
	}
	row, e := s.repo.ReadIdentity(ctx)
	if e != nil || row.Role != "Master" {
		return Envelope{}, store.ErrNodeState
	}
	rel, e := s.repo.Relationship(ctx, target.RelationshipID)
	if e != nil || rel.State != "active" || rel.Direction != "downstream" || rel.PeerID != target.MemberID {
		return Envelope{}, store.ErrNodeState
	}
	now := time.Now().Unix()
	return s.identity.signed(row, map[string]any{"domain": "frontiercloud:log-read:v1", "master": row.ID, "node": target.MemberID, "relationship": rel.ID, "id": ref.ID, "sha256": ref.SHA256, "bytes": ref.Bytes, "origin": audience, "issued": now, "expires": now + int64(logarchive.GrantLifetime/time.Second)})
}

func MasterOriginInvalid(origin string) bool {
	canonical, e := MasterEndpoint(origin)
	return e != nil || canonical != origin
}

func (s *Service) VerifyLogReadGrant(ctx context.Context, grant Envelope, origin string) (string, logarchive.Reference, error) {
	var ref logarchive.Reference
	row, e := s.repo.ReadIdentity(ctx)
	if e != nil || row.Role != "Follower" || grant.Payload["domain"] != "frontiercloud:log-read:v1" || MasterOriginInvalid(origin) {
		return "", ref, ErrCapability
	}
	p := grant.Payload
	rel, e := s.repo.Relationship(ctx, textField(p, "relationship"))
	if e != nil || rel.State != "active" || rel.Direction != "upstream" || rel.PeerID != textField(p, "master") || row.ID != textField(p, "node") || textField(p, "origin") != origin || protocol.Verify(rel.PublicKey, p, grant.Signature) != nil {
		return "", ref, ErrCapability
	}
	issued, a := intField(p, "issued")
	expires, b := intField(p, "expires")
	n, c := intField(p, "bytes")
	now := time.Now().Unix()
	if !a || !b || !c || issued > now+5 || expires <= now || expires-issued <= 0 || expires-issued > int64(logarchive.GrantLifetime/time.Second) || n > logarchive.MaxPlainBytes+128 {
		return "", ref, ErrCapability
	}
	ref = logarchive.Reference{ID: textField(p, "id"), SHA256: textField(p, "sha256"), Bytes: int(n)}
	if !ref.Valid() {
		return "", ref, ErrCapability
	}
	return rel.PeerID, ref, nil
}
