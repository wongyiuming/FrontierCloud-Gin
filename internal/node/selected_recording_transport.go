package node

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

// CleanupDirectRecording delivers a bounded control request to the resource
// origin resolved by the Master. The caller verifies and settles the receipt.
func (s *Service) CleanupDirectRecording(ctx context.Context, origin, publicOrigin, capability string) (protocol.OpaqueCapacityReceipt, string, error) {
	if s == nil {
		return protocol.OpaqueCapacityReceipt{}, "", ErrCapability
	}
	transport, ok := s.transport.(*Transport)
	if !ok {
		return protocol.OpaqueCapacityReceipt{}, "", ErrCapability
	}
	return transport.cleanupDirectRecording(ctx, origin, publicOrigin, capability)
}

func (t *Transport) cleanupDirectRecording(ctx context.Context, origin, publicOrigin, capability string) (protocol.OpaqueCapacityReceipt, string, error) {
	var empty protocol.OpaqueCapacityReceipt
	canonical, err := Endpoint(origin)
	ingress, ingressErr := Endpoint(publicOrigin)
	if t == nil || t.storage == nil || ctx == nil || err != nil || canonical != origin || ingressErr != nil || ingress != publicOrigin || capability == "" || len(capability) > 4096 {
		return empty, "", ErrCapability
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/api/v1/node/recording-selected-upload/cleanup", nil)
	if err != nil {
		return empty, "", ErrCapability
	}
	req.Header.Set("Origin", publicOrigin)
	req.Header.Set("X-Fc-Selected-Upload", capability)
	req.Header.Set("Accept", "application/json")
	resp, err := t.storage.Do(req)
	if err != nil {
		return empty, "", ErrCapability
	}
	defer resp.Body.Close()
	const maxReceipt = 8192
	if resp.StatusCode != http.StatusOK || resp.ContentLength > maxReceipt {
		return empty, "", ErrCapability
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReceipt+1))
	if err != nil || len(raw) > maxReceipt {
		return empty, "", ErrCapability
	}
	if _, err = protocol.ParseStrictJSON(raw, maxReceipt); err != nil {
		return empty, "", ErrCapability
	}
	var signed struct {
		Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
		Signature string                         `json:"signature"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&signed) != nil || signed.Signature == "" || len(signed.Signature) > 4096 {
		return empty, "", ErrCapability
	}
	return signed.Receipt, signed.Signature, nil
}
