package node

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const selectedRelayPath = "/internal/v1/selected-upload/relay"

type selectedRelayStreamingClient interface {
	selectedRelayUpload(context.Context, string, string, string, string, io.Reader, int64) (map[string]any, error)
	selectedRelayControl(context.Context, string, string, string, string, string) (map[string]any, error)
}

// ForwardSelectedRelay sends opaque ciphertext over a verified TLS pool.
// The caller must authenticate the Admin and obtain token from the
// same durable selected reservation; this method never chooses a new owner.
// Node request authentication signs the exact token (including its ciphertext
// digest and size), while the Owner verifies the byte stream as it consumes it.
func (s *Service) ForwardSelectedRelay(ctx context.Context, relationshipID, token string, reader io.Reader, size int64) (map[string]any, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || ctx == nil || reader == nil || !nodeIdentifier.MatchString(relationshipID) || token == "" || len(token) > 4096 || size <= 0 {
		return nil, store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return nil, store.ErrNodeState
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || relation.ID != relationshipID || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version {
		return nil, store.ErrNodeState
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return nil, store.ErrNodeState
	}
	claim, err := protocol.VerifySelectedStorageUpload(credential, token, time.Now().Unix())
	if err != nil || claim.Encryption == nil || claim.Policy != "Relay" || claim.Relationship != relationshipID || claim.Master != identity.ID || claim.Owner != relation.PeerID || claim.Size != size {
		return nil, store.ErrNodeState
	}
	client, ok := s.transport.(selectedRelayStreamingClient)
	if !ok {
		return nil, store.ErrNodeState
	}
	return client.selectedRelayUpload(ctx, relation.Endpoint, relationshipID, credential, token, reader, size)
}

func (t *Transport) selectedRelayUpload(ctx context.Context, rawOrigin, relationship, credential, token string, reader io.Reader, size int64) (map[string]any, error) {
	origin, err := Endpoint(rawOrigin)
	if err != nil || t == nil || t.selectedRelay == nil || ctx == nil || reader == nil || size <= 0 || token == "" || len(token) > 4096 {
		return nil, store.ErrNodeState
	}
	headers, err := protocol.AuthHeaders(credential, relationship, http.MethodPut, selectedRelayPath, []byte(token), time.Now().Unix())
	if err != nil {
		return nil, store.ErrNodeState
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, origin+selectedRelayPath, reader)
	if err != nil {
		return nil, errors.New("invalid selected relay request")
	}
	req.ContentLength = size
	req.Header.Set("X-Fc-Selected-Upload", token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := t.selectedRelay.Do(req)
	if err != nil {
		return nil, errors.New("selected relay HTTPS upload failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("selected relay rejected")
	}
	return readNodeResponse(resp.Body, MaxControlBytes)
}

// RecoverSelectedRelay and CleanupSelectedRelay use separately authenticated
// control paths. Cleanup requires the distinct Master cancellation capability;
// its caller must first durably fence completion on the Master.
func (s *Service) RecoverSelectedRelay(ctx context.Context, relationshipID, token string) (map[string]any, error) {
	return s.selectedRelayControl(ctx, relationshipID, token, false)
}
func (s *Service) CleanupSelectedRelay(ctx context.Context, relationshipID, token string) (map[string]any, error) {
	return s.selectedRelayControl(ctx, relationshipID, token, true)
}
func (s *Service) selectedRelayControl(ctx context.Context, relationshipID, token string, cleanup bool) (map[string]any, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || ctx == nil || !nodeIdentifier.MatchString(relationshipID) || token == "" || len(token) > 4096 {
		return nil, store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return nil, store.ErrNodeState
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || relation.ID != relationshipID || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version {
		return nil, store.ErrNodeState
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return nil, store.ErrNodeState
	}
	verify := protocol.VerifySelectedStorageUpload
	route := selectedRelayPath + "/recover"
	if cleanup {
		verify = protocol.VerifySelectedStorageCleanup
		route = selectedRelayPath + "/cleanup"
	}
	claim, err := verify(credential, token, time.Now().Unix())
	if err != nil || claim.Encryption == nil || claim.Policy != "Relay" || claim.Relationship != relationshipID || claim.Master != identity.ID || claim.Owner != relation.PeerID {
		return nil, store.ErrNodeState
	}
	client, ok := s.transport.(selectedRelayStreamingClient)
	if !ok {
		return nil, store.ErrNodeState
	}
	return client.selectedRelayControl(ctx, relation.Endpoint, relationshipID, credential, token, route)
}
func (t *Transport) selectedRelayControl(ctx context.Context, rawOrigin, relationship, credential, token, route string) (map[string]any, error) {
	if route != selectedRelayPath+"/recover" && route != selectedRelayPath+"/cleanup" {
		return nil, store.ErrNodeState
	}
	origin, err := Endpoint(rawOrigin)
	if err != nil || t == nil || t.selectedRelay == nil || ctx == nil || token == "" || len(token) > 4096 {
		return nil, store.ErrNodeState
	}
	headers, err := protocol.AuthHeaders(credential, relationship, http.MethodPost, route, []byte(token), time.Now().Unix())
	if err != nil {
		return nil, store.ErrNodeState
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+route, nil)
	if err != nil {
		return nil, errors.New("invalid selected relay control request")
	}
	req.Header.Set("X-Fc-Selected-Upload", token)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := t.selectedRelay.Do(req)
	if err != nil {
		return nil, errors.New("selected relay HTTPS control failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("selected relay control rejected")
	}
	return readNodeResponse(resp.Body, MaxControlBytes)
}
