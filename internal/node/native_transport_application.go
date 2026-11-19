package node

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type nativeTransportApplicationRepository interface {
	AcceptNativeTransportApplication(context.Context, string, int64, string) error
	RecordNativeTransportApplication(context.Context, string, int64, string) error
}

type nativeDirectApplicationRepository interface {
	AcceptNativeDirectApplication(context.Context, string, int64, string) error
	RecordNativeDirectApplication(context.Context, string, int64, string) error
}

// ConfigureNativeTransportReadiness installs a startup-only deployment verifier.
// A nil verifier leaves application blocked: a configuration flag or heartbeat
// alone is not proof that the relay data path is usable.
func (s *Service) ConfigureNativeTransportReadiness(verify func(context.Context, store.Relationship, string) error) {
	s.nativeTransportReady = verify
}

func (s *Service) acceptNativeTransportRequest(ctx context.Context, relation store.Relationship, raw any) map[string]any {
	result := map[string]any{"state": "blocked"}
	value, ok := raw.(map[string]any)
	if !ok {
		return result
	}
	revision, ok := intField(value, "revision")
	transport := textField(value, "transport")
	if !ok || revision < 1 || transport != "Relay" && transport != "Direct" {
		return result
	}
	result["revision"] = revision
	result["transport"] = transport
	if transport == "Direct" {
		origin := textField(value, "origin")
		result["origin"] = origin
		repo, ok := s.repo.(nativeDirectApplicationRepository)
		if !ok || origin == "" || origin != s.followerResourceOrigin || s.nativeTransportReady == nil || s.nativeTransportReady(ctx, relation, transport) != nil || repo.AcceptNativeDirectApplication(ctx, relation.ID, revision, origin) != nil {
			return result
		}
		result["state"] = "applied"
		return result
	}
	repo, ok := s.repo.(nativeTransportApplicationRepository)
	if !ok || s.nativeTransportReady == nil || s.nativeTransportReady(ctx, relation, transport) != nil {
		return result
	}
	if repo.AcceptNativeTransportApplication(ctx, relation.ID, revision, transport) != nil {
		return result
	}
	result["state"] = "applied"
	return result
}
