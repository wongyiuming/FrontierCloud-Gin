package node

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type nativeMediaEndpointProber interface {
	ProbeNativeMediaEndpoint(context.Context, string) error
}

// ProbeNativeMediaEndpoint checks the fixed, unauthenticated media route on a
// previously identity-verified HTTPS origin. It sends no capability and accepts
// only the node reader's authorization rejection. It cannot prove that a
// browser on a different network can reach the same address.
func (t *Transport) ProbeNativeMediaEndpoint(ctx context.Context, origin string) error {
	canonical, err := Endpoint(origin)
	if t == nil || t.client == nil || err != nil || canonical != origin {
		return errors.New("invalid native resource endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/internal/v1/media/"+strings.Repeat("0", 64), nil)
	if err != nil {
		return errors.New("invalid native resource endpoint")
	}
	response, err := t.client.Do(req)
	if err != nil {
		return errors.New("native resource HTTPS probe failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		return errors.New("native resource authorization endpoint unavailable")
	}
	var body struct {
		Detail string `json:"detail"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1025))
	if decoder.Decode(&body) != nil || body.Detail != "Media capability invalid or expired" || decoder.Decode(new(any)) != io.EOF {
		return errors.New("native resource authorization endpoint unavailable")
	}
	return nil
}

// VerifyNativeTransportReadiness checks the local handler's dependencies on a
// Follower and verifies the paired HTTPS identity and fixed media route on
// Master. It does not select a policy or activate an ingress; the caller must
// additionally ensure that the local HTTP handlers are registered and ready.
func (s *Service) VerifyNativeTransportReadiness(ctx context.Context, relation store.Relationship, mode string) error {
	if s == nil || s.repo == nil || relation.State != "active" || mode != "Direct" && mode != "Relay" {
		return store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return err
	}
	switch identity.Role {
	case "Follower":
		current, err := s.repo.Relationship(ctx, relation.ID)
		if err != nil || current.State != "active" || current.Direction != "upstream" || current.PeerID != relation.PeerID {
			return store.ErrNodeState
		}
		if mode == "Direct" && s.followerResourceOrigin == "" {
			return store.ErrNodeState
		}
		if s.plainReadProbe == nil || s.plainReadProbe(ctx) != nil {
			return store.ErrNodeState
		}
		return nil
	case "Master":
		if relation.Direction != "downstream" || s.transport == nil {
			return store.ErrNodeState
		}
		var origin string
		if mode == "Direct" {
			origin, err = s.VerifyFollowerResourceIdentity(ctx, relation.ID)
		} else {
			origin, err = Endpoint(relation.Endpoint)
			if err == nil && origin == relation.Endpoint {
				_, err = s.transport.Identity(ctx, origin, relation.PeerID, relation.PublicKey, "Follower")
			} else {
				err = store.ErrNodeState
			}
		}
		if err != nil {
			return store.ErrNodeState
		}
		probe, ok := s.transport.(nativeMediaEndpointProber)
		if !ok || probe.ProbeNativeMediaEndpoint(ctx, origin) != nil {
			return store.ErrNodeState
		}
		if s.VerifyFollowerPlainReadiness(ctx, relation, origin) != nil {
			return store.ErrNodeState
		}
		return nil
	default:
		return store.ErrNodeState
	}
}

// VerifyNativeOpaqueTransportReadiness additionally requires a paired v5
// Owner reader proof. Relay uses the already paired control endpoint; Direct
// uses the separately advertised, identity-verified resource origin.
func (s *Service) VerifyNativeOpaqueTransportReadiness(ctx context.Context, relation store.Relationship, mode string) error {
	if s == nil || s.repo == nil || (mode != "Direct" && mode != "Relay") || s.VerifyNativeTransportReadiness(ctx, relation, mode) != nil {
		return store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return store.ErrNodeState
	}
	switch identity.Role {
	case "Follower":
		if s.opaqueReadProbe == nil || s.opaqueReadProbe(ctx) != nil {
			return store.ErrNodeState
		}
		return nil
	case "Master":
		var origin string
		if mode == "Direct" {
			origin, err = s.VerifyFollowerResourceIdentity(ctx, relation.ID)
		} else {
			origin, err = Endpoint(relation.Endpoint)
			if err == nil && origin != relation.Endpoint {
				return store.ErrNodeState
			}
		}
		if err != nil || s.VerifyFollowerOpaqueReadiness(ctx, relation, origin) != nil || ctx.Err() != nil {
			return store.ErrNodeState
		}
		return nil
	default:
		return store.ErrNodeState
	}
}
