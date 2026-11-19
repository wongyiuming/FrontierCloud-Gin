package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type legacyReadControlRepository interface {
	CurrentLegacyReadControl(context.Context, store.NodeIdentity, *vault.Vault, string) (store.LegacyReadControlCurrent, error)
	FindCurrentLegacyReadControl(context.Context, store.NodeIdentity, *vault.Vault, string) (store.LegacyReadControlCurrent, bool, error)
	BeginLegacyReadEnrollment(context.Context, store.NodeIdentity, *vault.Vault, string, string, string, int64) (store.LegacyReadEnrollmentIntent, error)
	ConfirmLegacyReadEnrollment(context.Context, store.NodeIdentity, *vault.Vault, string, protocol.LegacyReadEnrollmentReceipt, string) (store.LegacyReadEnrollmentIntent, error)
	RecoverLegacyReadEnrollment(context.Context, store.NodeIdentity, *vault.Vault, string, string, string) (store.LegacyReadEnrollmentIntent, bool, error)
	BeginLegacyReadDrain(context.Context, store.NodeIdentity, *vault.Vault, string, string, string, string, string) (store.LegacyReadDrainIntent, error)
	ConfirmLegacyReadDrain(context.Context, store.NodeIdentity, *vault.Vault, string, protocol.LegacyReadDrainReceipt, string) (store.LegacyReadDrainIntent, error)
	RecoverLegacyReadDrain(context.Context, store.NodeIdentity, *vault.Vault, string, string, string) (store.LegacyReadDrainIntent, bool, error)
	BeginLegacyReadStatus(context.Context, store.NodeIdentity, *vault.Vault, string, string, string, string, string, string, int64) (store.LegacyReadStatusIntent, error)
	ConfirmLegacyReadStatus(context.Context, store.NodeIdentity, *vault.Vault, protocol.LegacyReadStatus, string) (store.LegacyReadStatusIntent, error)
	RecoverLegacyReadStatus(context.Context, store.NodeIdentity, *vault.Vault, string, string, string) (store.LegacyReadStatusIntent, bool, error)
}

// LegacyReadCoordinator is a dormant control-plane primitive. It generates
// all operation IDs and challenges itself and returns no bearer or random ID
// to a browser. Its caller must enforce Admin session/CSRF and audit, and the
// product must not install it before external recovery and process fences exist.
type LegacyReadCoordinator struct {
	service *Service
	repo    legacyReadControlRepository
}

func NewLegacyReadCoordinator(service *Service) (*LegacyReadCoordinator, error) {
	if service == nil || service.repo == nil || service.identity == nil || service.identity.vault == nil || service.transport == nil {
		return nil, ErrCapability
	}
	repo, ok := service.repo.(legacyReadControlRepository)
	if !ok {
		return nil, ErrCapability
	}
	return &LegacyReadCoordinator{service: service, repo: repo}, nil
}

func legacyControlRandom() (string, string, error) {
	for range 8 {
		operation, challenge := make([]byte, 16), make([]byte, 32)
		if _, err := rand.Read(operation); err != nil {
			return "", "", err
		}
		if _, err := rand.Read(challenge); err != nil {
			clear(operation)
			return "", "", err
		}
		id, value := hex.EncodeToString(operation), hex.EncodeToString(challenge)
		clear(operation)
		clear(challenge)
		if id != strings.Repeat("0", 32) && value != strings.Repeat("0", 64) {
			return id, value, nil
		}
	}
	return "", "", ErrCapability
}

func (c *LegacyReadCoordinator) identity(ctx context.Context, relationship string) (store.NodeIdentity, error) {
	if c == nil || c.service == nil || c.repo == nil || !ValidIdentifier(relationship) {
		return store.NodeIdentity{}, ErrCapability
	}
	identity, err := c.service.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return store.NodeIdentity{}, ErrCapability
	}
	return identity, nil
}

// EnrollLegacyReads persists a new challenge before the authenticated owner
// observation and commits the exact signed response in a new transaction.
func (c *LegacyReadCoordinator) EnrollLegacyReads(ctx context.Context, relationship string) (string, error) {
	identity, err := c.identity(ctx, relationship)
	if err != nil {
		return "", err
	}
	current, found, err := c.repo.FindCurrentLegacyReadControl(ctx, identity, c.service.identity.vault, relationship)
	if err != nil || found && current.Drain != nil {
		return "", ErrCapability
	}
	var intent store.LegacyReadEnrollmentIntent
	if found && time.Now().Unix() < current.Enrollment.ExpiresAt {
		intent = current.Enrollment
		if intent.State == "confirmed" {
			confirmed, fresh, e := c.repo.RecoverLegacyReadEnrollment(ctx, identity, c.service.identity.vault, relationship, intent.OperationID, intent.Challenge)
			if e != nil || !fresh || confirmed.State != "confirmed" || confirmed.Receipt == nil {
				return "", ErrCapability
			}
			latest, exists, e := c.repo.FindCurrentLegacyReadControl(ctx, identity, c.service.identity.vault, relationship)
			if e != nil || !exists || latest.Drain != nil || latest.Enrollment.OperationID != intent.OperationID || time.Now().Unix() >= latest.Enrollment.ExpiresAt {
				return "", ErrCapability
			}
			return "active", nil
		}
		if intent.State != "pending" {
			return "", ErrCapability
		}
	} else {
		op, challenge, e := legacyControlRandom()
		if e != nil {
			return "", ErrCapability
		}
		intent, err = c.repo.BeginLegacyReadEnrollment(ctx, identity, c.service.identity.vault, relationship, op, challenge, time.Now().Unix()+120)
		if err != nil {
			return "", ErrCapability
		}
	}
	op, challenge := intent.OperationID, intent.Challenge
	bounded, cancel := context.WithDeadline(ctx, time.Unix(intent.ExpiresAt, 0))
	defer cancel()
	receipt, signed, err := c.service.requestLegacyReadEnrollment(bounded, protocol.LegacyReadEnrollmentRequest{RelationshipID: relationship, Challenge: challenge}, intent.MasterRelationshipBinding)
	if err != nil {
		return "", ErrCapability
	}
	if _, err = c.repo.ConfirmLegacyReadEnrollment(ctx, identity, c.service.identity.vault, op, receipt, signed.Signature); err != nil {
		return "", ErrCapability
	}
	confirmed, fresh, err := c.repo.RecoverLegacyReadEnrollment(ctx, identity, c.service.identity.vault, relationship, op, challenge)
	if err != nil || !fresh || confirmed.State != "confirmed" || confirmed.Receipt == nil || *confirmed.Receipt != receipt || confirmed.Signature != signed.Signature {
		return "", ErrCapability
	}
	latest, found, err := c.repo.FindCurrentLegacyReadControl(ctx, identity, c.service.identity.vault, relationship)
	if err != nil || !found || latest.Drain != nil || latest.Enrollment.OperationID != op || latest.Enrollment.State != "confirmed" || time.Now().Unix() >= latest.Enrollment.ExpiresAt {
		return "", ErrCapability
	}
	return "active", nil
}

// DrainLegacyReads accepts only the relationship from its trusted caller.
// Current and Recover revalidate the durable intent; network I/O is outside
// all owner/tree/ingress transactions and Confirm atomically persists proof.
func (c *LegacyReadCoordinator) DrainLegacyReads(ctx context.Context, relationship string) (string, error) {
	identity, err := c.identity(ctx, relationship)
	if err != nil {
		return "", err
	}
	current, err := c.repo.CurrentLegacyReadControl(ctx, identity, c.service.identity.vault, relationship)
	if err != nil || current.Enrollment.State != "confirmed" || current.Enrollment.Receipt == nil || time.Now().Unix() >= current.Enrollment.ExpiresAt {
		return "", ErrCapability
	}
	var intent store.LegacyReadDrainIntent
	if current.Drain == nil {
		op, challenge, e := legacyControlRandom()
		if e != nil {
			return "", ErrCapability
		}
		intent, err = c.repo.BeginLegacyReadDrain(ctx, identity, c.service.identity.vault, relationship, current.Enrollment.OperationID, current.Enrollment.Challenge, op, challenge)
	} else {
		intent = *current.Drain
	}
	if err == nil && intent.State == "confirmed" {
		confirmed, fresh, e := c.repo.RecoverLegacyReadDrain(ctx, identity, c.service.identity.vault, relationship, intent.OperationID, intent.Challenge)
		if e != nil || !fresh || confirmed.State != "confirmed" || confirmed.Receipt == nil || confirmed.Receipt.State != "revoked" || time.Now().Unix() >= confirmed.ExpiresAt {
			return "", ErrCapability
		}
		return "revoked", nil
	}
	if err != nil || intent.State != "pending" || time.Now().Unix() >= intent.ExpiresAt {
		return "", ErrCapability
	}
	enrollment, fresh, err := c.repo.RecoverLegacyReadEnrollment(ctx, identity, c.service.identity.vault, relationship, intent.EnrollmentOperation, intent.EnrollmentChallenge)
	if err != nil || !fresh || enrollment.State != "confirmed" || enrollment.Receipt == nil || *enrollment.Receipt != intent.Enrollment || enrollment.Signature != intent.EnrollmentSignature {
		return "", ErrCapability
	}
	intent, _, err = c.repo.RecoverLegacyReadDrain(ctx, identity, c.service.identity.vault, relationship, intent.OperationID, intent.Challenge)
	if err != nil || intent.State != "pending" || time.Now().Unix() >= intent.ExpiresAt {
		return "", ErrCapability
	}
	payload, err := intent.Enrollment.Payload()
	if err != nil {
		return "", ErrCapability
	}
	envelope := Envelope{Payload: payload, Signature: intent.EnrollmentSignature}
	receipt := protocol.LegacyReadDrainReceipt{Kind: "legacy-media-drain-v1", OperationID: intent.OperationID, Challenge: intent.Challenge, ExpiresAt: intent.ExpiresAt, MasterID: intent.MasterID, OwnerID: intent.OwnerID, RelationshipID: intent.RelationshipID, RelationshipBinding: intent.Enrollment.RelationshipBinding, OwnerBinding: intent.Enrollment.OwnerBinding, FenceBinding: intent.Enrollment.FenceBinding, State: "revoked"}
	signed, err := c.service.requestLegacyReadDrain(ctx, receipt, intent.Enrollment, envelope, intent.MasterRelationshipBinding)
	if err != nil {
		return "", ErrCapability
	}
	if _, err = c.repo.ConfirmLegacyReadDrain(ctx, identity, c.service.identity.vault, intent.OperationID, receipt, signed.Signature); err != nil {
		return "", ErrCapability
	}
	confirmed, fresh, err := c.repo.RecoverLegacyReadDrain(ctx, identity, c.service.identity.vault, relationship, intent.OperationID, intent.Challenge)
	if err != nil || !fresh || confirmed.State != "confirmed" || confirmed.Receipt == nil || *confirmed.Receipt != receipt || confirmed.Signature != signed.Signature || time.Now().Unix() >= confirmed.ExpiresAt {
		return "", ErrCapability
	}
	return "revoked", nil
}

// ObserveLegacyReads uses a separately persisted, freshly generated challenge.
// A signed draining observation is never a successful drain proof.
func (c *LegacyReadCoordinator) ObserveLegacyReads(ctx context.Context, relationship string) (string, error) {
	return c.controlLegacyReads(ctx, relationship, "status")
}

// ResumeLegacyReads uses a new independently authorized challenge to finish
// an existing draining operation. It never creates or changes that operation.
func (c *LegacyReadCoordinator) ResumeLegacyReads(ctx context.Context, relationship string) (string, error) {
	return c.controlLegacyReads(ctx, relationship, "resume")
}

func (c *LegacyReadCoordinator) controlLegacyReads(ctx context.Context, relationship, action string) (string, error) {
	identity, err := c.identity(ctx, relationship)
	if err != nil {
		return "", err
	}
	current, err := c.repo.CurrentLegacyReadControl(ctx, identity, c.service.identity.vault, relationship)
	if err != nil || current.Drain == nil {
		return "", ErrCapability
	}
	if current.Status != nil && current.Status.Request.Action == action && current.Status.State == "confirmed" && current.Status.Receipt != nil && current.Status.Receipt.State == "revoked" && time.Now().Unix() < current.Status.ExpiresAt {
		confirmed, fresh, e := c.repo.RecoverLegacyReadStatus(ctx, identity, c.service.identity.vault, relationship, current.Status.Request.RequestID, current.Status.Request.Challenge)
		if e != nil || !fresh || confirmed.State != "confirmed" || confirmed.Receipt == nil || confirmed.Receipt.State != "revoked" || time.Now().Unix() >= confirmed.ExpiresAt {
			return "", ErrCapability
		}
		return "revoked", nil
	}
	var intent store.LegacyReadStatusIntent
	if current.Status != nil && current.Status.State == "pending" && time.Now().Unix() < current.Status.ExpiresAt {
		if current.Status.Request.Action != action {
			return "", ErrCapability
		}
		intent = *current.Status
	} else {
		id, challenge, e := legacyControlRandom()
		if e != nil {
			return "", ErrCapability
		}
		intent, err = c.repo.BeginLegacyReadStatus(ctx, identity, c.service.identity.vault, relationship, action, current.Drain.OperationID, current.Drain.Challenge, id, challenge, time.Now().Unix()+120)
	}
	if err != nil || intent.State != "pending" || time.Now().Unix() >= intent.ExpiresAt {
		return "", ErrCapability
	}
	intent, _, err = c.repo.RecoverLegacyReadStatus(ctx, identity, c.service.identity.vault, relationship, intent.Request.RequestID, intent.Request.Challenge)
	if err != nil || intent.State != "pending" || time.Now().Unix() >= intent.ExpiresAt {
		return "", ErrCapability
	}
	drain, _, err := c.repo.RecoverLegacyReadDrain(ctx, identity, c.service.identity.vault, relationship, intent.Request.OriginalOperationID, intent.Request.OriginalChallenge)
	if err != nil || drain.EnrollmentSignature == "" {
		return "", ErrCapability
	}
	payload, err := drain.Enrollment.Payload()
	if err != nil {
		return "", ErrCapability
	}
	status, signed, err := c.service.requestLegacyReadStatus(ctx, intent.Request, drain.Enrollment, Envelope{Payload: payload, Signature: drain.EnrollmentSignature}, intent.MasterRelationshipBinding)
	if err != nil {
		return "", ErrCapability
	}
	if _, err = c.repo.ConfirmLegacyReadStatus(ctx, identity, c.service.identity.vault, status, signed.Signature); err != nil {
		return "", ErrCapability
	}
	confirmed, fresh, err := c.repo.RecoverLegacyReadStatus(ctx, identity, c.service.identity.vault, relationship, intent.Request.RequestID, intent.Request.Challenge)
	if err != nil || confirmed.State != "confirmed" || confirmed.Receipt == nil || *confirmed.Receipt != status || confirmed.Signature != signed.Signature || time.Now().Unix() >= confirmed.ExpiresAt {
		return "", ErrCapability
	}
	if status.State == "revoked" && !fresh || action == "resume" && status.State != "revoked" {
		return "", ErrCapability
	}
	return status.State, nil
}
