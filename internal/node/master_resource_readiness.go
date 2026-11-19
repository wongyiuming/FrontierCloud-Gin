package node

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type masterDirectEndpointProber interface {
	ProbeMasterDirectEndpoint(context.Context, string, string) error
}

func (t *Transport) ProbeMasterDirectEndpoint(ctx context.Context, origin, browserOrigin string) error {
	if t == nil || t.client == nil || ValidateMasterResourceOrigin(origin) != nil || !validMasterDirectOrigin(browserOrigin) {
		return store.ErrNodeState
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/api/v1/media/master-direct/"+strings.Repeat("0", 64), nil)
	if err != nil {
		return store.ErrNodeState
	}
	req.Header.Set("Origin", browserOrigin)
	response, err := t.client.Do(req)
	if err != nil {
		return errors.New("Master resource HTTPS probe failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		return store.ErrNodeState
	}
	var body struct {
		Detail string `json:"detail"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1025))
	if decoder.Decode(&body) != nil || body.Detail != "Resource authorization invalid or expired" || decoder.Decode(new(any)) != io.EOF {
		return store.ErrNodeState
	}
	return nil
}

// VerifyMasterResourceReadiness verifies configured Direct HTTPS at the unique
// Master identity or the selected Follower's authenticated Relay proxy chain.
// It never changes a policy, selects a peer or guarantees browser reachability.
func (s *Service) VerifyMasterResourceReadiness(ctx context.Context, ingress store.PublicIngress, mode, origin string) error {
	if s == nil || s.repo == nil || s.transport == nil {
		return store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return store.ErrNodeState
	}
	switch mode {
	case "Direct":
		if ValidateMasterResourceOrigin(origin) != nil {
			return store.ErrNodeState
		}
		challenge, err := randomNodeID()
		if err != nil {
			return err
		}
		value, err := s.transport.Request(ctx, origin, "/internal/v1/identity?"+url.Values{"challenge": {challenge}}.Encode(), http.MethodGet, nil, "", "")
		if err != nil {
			return store.ErrNodeState
		}
		signed, err := envelope(value)
		public, keyErr := s.public(identity)
		if err != nil || keyErr != nil || protocol.Verify(public, signed.Payload, signed.Signature) != nil {
			return store.ErrNodeState
		}
		payload := signed.Payload
		version, valid := intField(payload, "protocol")
		endpoint, endpointErr := Endpoint(textField(payload, "endpoint"))
		expected, expectedErr := Endpoint(identity.Endpoint)
		if !valid || version != protocol.Version || endpointErr != nil || expectedErr != nil || endpoint != expected || textField(payload, "node_id") != identity.ID || textField(payload, "public_key") != public || textField(payload, "role") != "Master" || textField(payload, "challenge") != challenge {
			return store.ErrNodeState
		}
		if _, err := protocol.ReadCapabilities(payload); err != nil {
			return store.ErrNodeState
		}
		probe, ok := s.transport.(masterDirectEndpointProber)
		if !ok || probe.ProbeMasterDirectEndpoint(ctx, origin, ingress.PublicOrigin) != nil {
			return store.ErrNodeState
		}
		return nil
	case "Relay":
		if ingress.NodeID == identity.ID || origin != "" {
			return store.ErrNodeState
		}
		relations, err := s.repo.Relationships(ctx, false)
		if err != nil {
			return err
		}
		for _, relation := range relations {
			if relation.PeerID == ingress.NodeID && relation.Direction == "downstream" && relation.State == "active" {
				checked, err := s.VerifyFollowerIngressProxy(ctx, relation.ID)
				if err == nil && checked == ingress.PublicOrigin {
					return nil
				}
				return store.ErrNodeState
			}
		}
		return store.ErrNodeState
	default:
		return store.ErrNodeState
	}
}

// MasterRelayObservationValid checks that the current authenticated peer and
// its latest advertised origin still match the verified Relay proof.
func (s *Service) MasterRelayObservationValid(ctx context.Context, ingress store.PublicIngress) error {
	if s == nil || s.repo == nil {
		return store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || ingress.NodeID == identity.ID {
		return store.ErrNodeState
	}
	relations, err := s.repo.Relationships(ctx, false)
	if err != nil {
		return err
	}
	for _, relation := range relations {
		if relation.PeerID == ingress.NodeID && relation.Direction == "downstream" && relation.State == "active" {
			origin, err := s.ObservedFollowerIngressCandidate(ctx, relation.ID)
			if err == nil && origin == ingress.PublicOrigin {
				return nil
			}
			return store.ErrNodeState
		}
	}
	return store.ErrNodeState
}
