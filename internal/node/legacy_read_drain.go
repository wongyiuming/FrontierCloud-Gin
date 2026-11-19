package node

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

// RequestLegacyReadEnrollment obtains owner-computed scope via an authenticated
// relationship. The caller must durably store the exact signature, challenge
// and Master-side relationship binding before using this scope for a drain.
func (s *Service) requestLegacyReadEnrollment(ctx context.Context, request protocol.LegacyReadEnrollmentRequest, expectedRelationshipBinding string) (protocol.LegacyReadEnrollmentReceipt, Envelope, error) {
	var empty protocol.LegacyReadEnrollmentReceipt
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || s.transport == nil || !request.Valid() || !resourceIdentifier.MatchString(expectedRelationshipBinding) {
		return empty, Envelope{}, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return empty, Envelope{}, ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, request.RelationshipID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version || opaqueRelationshipBinding(relation) != expectedRelationshipBinding {
		return empty, Envelope{}, ErrCapability
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return empty, Envelope{}, ErrCapability
	}
	requestPayload := map[string]any{"relationship_id": request.RelationshipID, "challenge": request.Challenge}
	response, err := s.transport.Request(ctx, relation.Endpoint, protocol.LegacyReadEnrollmentPath, http.MethodPost, requestPayload, relation.ID, credential)
	if err != nil {
		return empty, Envelope{}, ErrCapability
	}
	signed, err := envelope(response)
	if err != nil {
		return empty, Envelope{}, ErrCapability
	}
	raw, err := protocol.Canonical(signed.Payload)
	if err != nil {
		return empty, Envelope{}, ErrCapability
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt protocol.LegacyReadEnrollmentReceipt
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF {
		return empty, Envelope{}, ErrCapability
	}
	payload, err := receipt.Payload()
	if err != nil || receipt.Challenge != request.Challenge || receipt.MasterID != identity.ID || receipt.OwnerID != relation.PeerID || receipt.RelationshipID != relation.ID {
		return empty, Envelope{}, ErrCapability
	}
	canonical, err := protocol.Canonical(payload)
	if err != nil || !bytes.Equal(raw, canonical) || protocol.Verify(relation.PublicKey, signed.Payload, signed.Signature) != nil {
		return empty, Envelope{}, ErrCapability
	}
	currentIdentity, err := s.repo.ReadIdentity(ctx)
	if err != nil || currentIdentity != identity {
		return empty, Envelope{}, ErrCapability
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "downstream" || current.Protocol != protocol.Version || opaqueRelationshipBinding(current) != expectedRelationshipBinding || ctx.Err() != nil {
		return empty, Envelope{}, ErrCapability
	}
	return receipt, signed, nil
}

func (s *Service) VerifyLegacyReadEnrollment(ctx context.Context, expected protocol.LegacyReadEnrollmentReceipt, signed Envelope) error {
	if s == nil || s.repo == nil {
		return ErrCapability
	}
	payload, err := expected.Payload()
	if err != nil {
		return ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != expected.MasterID {
		return ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, expected.RelationshipID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version || relation.PeerID != expected.OwnerID {
		return ErrCapability
	}
	got, err := protocol.Canonical(signed.Payload)
	if err != nil {
		return ErrCapability
	}
	want, err := protocol.Canonical(payload)
	if err != nil || !bytes.Equal(got, want) || protocol.Verify(relation.PublicKey, signed.Payload, signed.Signature) != nil || ctx.Err() != nil {
		return ErrCapability
	}
	return nil
}

// RequestLegacyReadStatus is a read-only transport primitive. An administrator
// must first persist a new status request ID/challenge linked to the original
// operation; no in-memory result by itself grants activation.
func (s *Service) requestLegacyReadStatus(ctx context.Context, request protocol.LegacyReadStatusRequest, enrollment protocol.LegacyReadEnrollmentReceipt, enrollmentSigned Envelope, expectedRelationshipBinding string) (protocol.LegacyReadStatus, Envelope, error) {
	var empty protocol.LegacyReadStatus
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || s.transport == nil || !resourceIdentifier.MatchString(expectedRelationshipBinding) {
		return empty, Envelope{}, ErrCapability
	}
	if _, err := request.Receipt("revoked"); err != nil || s.VerifyLegacyReadEnrollment(ctx, enrollment, enrollmentSigned) != nil || request.MasterID != enrollment.MasterID || request.OwnerID != enrollment.OwnerID || request.RelationshipID != enrollment.RelationshipID || request.RelationshipBinding != enrollment.RelationshipBinding || request.OwnerBinding != enrollment.OwnerBinding || request.FenceBinding != enrollment.FenceBinding {
		return empty, Envelope{}, ErrCapability
	}
	if request.ExpiresAt <= time.Now().Unix() || request.ExpiresAt > time.Now().Unix()+300 {
		return empty, Envelope{}, ErrCapability
	}
	bounded, cancel := context.WithDeadline(ctx, time.Unix(request.ExpiresAt, 0))
	defer cancel()
	ctx = bounded
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != request.MasterID {
		return empty, Envelope{}, ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, request.RelationshipID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version || relation.PeerID != request.OwnerID || opaqueRelationshipBinding(relation) != expectedRelationshipBinding {
		return empty, Envelope{}, ErrCapability
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return empty, Envelope{}, ErrCapability
	}
	payload := map[string]any{"action": request.Action, "request_id": request.RequestID, "challenge": request.Challenge, "original_operation_id": request.OriginalOperationID, "original_challenge": request.OriginalChallenge, "original_expires_at": request.OriginalExpiresAt, "expires_at": request.ExpiresAt, "master_id": request.MasterID, "owner_id": request.OwnerID, "relationship_id": request.RelationshipID, "relationship_binding": request.RelationshipBinding, "owner_binding": request.OwnerBinding, "fence_binding": request.FenceBinding}
	response, err := s.transport.Request(ctx, relation.Endpoint, protocol.LegacyReadStatusPath, http.MethodPost, payload, relation.ID, credential)
	if err != nil {
		return empty, Envelope{}, ErrCapability
	}
	signed, err := envelope(response)
	if err != nil {
		return empty, Envelope{}, ErrCapability
	}
	raw, err := protocol.Canonical(signed.Payload)
	if err != nil {
		return empty, Envelope{}, ErrCapability
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result protocol.LegacyReadStatus
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
		return empty, Envelope{}, ErrCapability
	}
	expected, err := request.Receipt(result.State)
	if err != nil || expected != result {
		return empty, Envelope{}, ErrCapability
	}
	wantPayload, err := expected.Payload()
	if err != nil {
		return empty, Envelope{}, ErrCapability
	}
	want, err := protocol.Canonical(wantPayload)
	if err != nil || !bytes.Equal(raw, want) || protocol.Verify(relation.PublicKey, signed.Payload, signed.Signature) != nil {
		return empty, Envelope{}, ErrCapability
	}
	currentIdentity, err := s.repo.ReadIdentity(ctx)
	if err != nil || currentIdentity != identity {
		return empty, Envelope{}, ErrCapability
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "downstream" || current.Protocol != protocol.Version || opaqueRelationshipBinding(current) != expectedRelationshipBinding || ctx.Err() != nil || time.Now().Unix() >= request.ExpiresAt {
		return empty, Envelope{}, ErrCapability
	}
	return result, signed, nil
}

// VerifyLegacyReadDrainReceipt verifies the exact staged receipt against the
// currently paired owner. Persisting it and checking an external rollback
// anchor are separate activation requirements.
func (s *Service) VerifyLegacyReadDrainReceipt(ctx context.Context, expected protocol.LegacyReadDrainReceipt, signed Envelope) error {
	if s == nil || s.repo == nil {
		return ErrCapability
	}
	want, err := expected.Payload()
	if err != nil {
		return ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != expected.MasterID {
		return ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, expected.RelationshipID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version || relation.PeerID != expected.OwnerID {
		return ErrCapability
	}
	got, err := protocol.Canonical(signed.Payload)
	if err != nil {
		return ErrCapability
	}
	canonical, err := protocol.Canonical(want)
	if err != nil || !bytes.Equal(got, canonical) || protocol.Verify(relation.PublicKey, signed.Payload, signed.Signature) != nil || ctx.Err() != nil {
		return ErrCapability
	}
	return nil
}

// RequestLegacyReadDrain is an isolated transport primitive, not an activation
// transaction. The caller must stage and persist the exact operation and owner
// scope, and recheck its own authority after this network request. No local
// owner/tree/ingress fence is held while waiting for the remote owner to drain.
func (s *Service) requestLegacyReadDrain(ctx context.Context, receipt protocol.LegacyReadDrainReceipt, enrollment protocol.LegacyReadEnrollmentReceipt, enrollmentSigned Envelope, expectedRelationshipBinding string) (Envelope, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || s.transport == nil {
		return Envelope{}, ErrCapability
	}
	payload, err := receipt.Payload()
	if err != nil || !resourceIdentifier.MatchString(expectedRelationshipBinding) {
		return Envelope{}, ErrCapability
	}
	if s.VerifyLegacyReadEnrollment(ctx, enrollment, enrollmentSigned) != nil || receipt.MasterID != enrollment.MasterID || receipt.OwnerID != enrollment.OwnerID || receipt.RelationshipID != enrollment.RelationshipID || receipt.RelationshipBinding != enrollment.RelationshipBinding || receipt.OwnerBinding != enrollment.OwnerBinding || receipt.FenceBinding != enrollment.FenceBinding {
		return Envelope{}, ErrCapability
	}
	if receipt.ExpiresAt <= time.Now().Unix() || receipt.ExpiresAt > time.Now().Unix()+300 {
		return Envelope{}, ErrCapability
	}
	bounded, cancel := context.WithDeadline(ctx, time.Unix(receipt.ExpiresAt, 0))
	defer cancel()
	ctx = bounded
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != receipt.MasterID {
		return Envelope{}, ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, receipt.RelationshipID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version || relation.PeerID != receipt.OwnerID || opaqueRelationshipBinding(relation) != expectedRelationshipBinding {
		return Envelope{}, ErrCapability
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	response, err := s.transport.Request(ctx, relation.Endpoint, protocol.LegacyReadDrainPath, http.MethodPost, payload, relation.ID, credential)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	signed, err := envelope(response)
	if err != nil || s.VerifyLegacyReadDrainReceipt(ctx, receipt, signed) != nil {
		return Envelope{}, ErrCapability
	}
	currentIdentity, err := s.repo.ReadIdentity(ctx)
	if err != nil || currentIdentity != identity {
		return Envelope{}, ErrCapability
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "downstream" || current.Protocol != protocol.Version || opaqueRelationshipBinding(current) != expectedRelationshipBinding || ctx.Err() != nil || time.Now().Unix() >= receipt.ExpiresAt {
		return Envelope{}, ErrCapability
	}
	return signed, nil
}
