package node

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var ErrCapability = errors.New("resource capability invalid or expired")

func (s *Service) MediaCapability(ctx context.Context, id, owner, objectID, resourceID, requestID, traceID string) (string, error) {
	node, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return "", err
	}
	relation, err := s.repo.Relationship(ctx, id)
	if err != nil {
		return "", err
	}
	if node.Role != "Master" || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version || relation.PeerID != owner {
		return "", ErrCapability
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return "", ErrCapability
	}
	return protocol.MediaToken(credential, relation.ID, node.ID, owner, objectID, resourceID, time.Now().Unix(), requestID, traceID)
}

// MediaIngressCapability issues an origin-bound grant only inside a request
// authenticated by the Master ingress verifier while its lease is held. The
// caller remains responsible for object authorization and visibility checks.
func (s *Service) MediaIngressCapability(ctx context.Context, id, owner, objectID, resourceID string, size, sessionExpiresAt int64, meta *mediacrypto.Metadata) (string, error) {
	if meta == nil {
		return "", ErrCapability
	}
	return s.mediaIngressCapability(ctx, id, owner, objectID, resourceID, size, sessionExpiresAt, meta, "", "")
}

// MediaPlainIngressCapability is used only after Master has authorized the
// object and obtained its strong content digest from the durable placement.
func (s *Service) MediaPlainIngressCapability(ctx context.Context, id, owner, objectID, resourceID string, size, sessionExpiresAt int64, digest string) (string, error) {
	if !resourceIdentifier.MatchString(digest) {
		return "", ErrCapability
	}
	return s.mediaIngressCapability(ctx, id, owner, objectID, resourceID, size, sessionExpiresAt, nil, digest, "")
}

// MediaOpaqueIngressCapability requires the same authorized admission and
// session as the existing issuer. The caller must have resolved and validated
// this exact placement under its held tree lease before invoking it.
func (s *Service) MediaOpaqueIngressCapability(ctx context.Context, id, owner, alias, blob string, size, sessionExpiresAt int64, digest string, meta *mediacrypto.Metadata) (string, error) {
	prerequisite, ok := store.IngressPrerequisiteFromContext(ctx)
	if !ok || prerequisite.Check(ctx) != nil || !resourceIdentifier.MatchString(digest) || !resourceIdentifier.MatchString(blob) || !resourceIdentifier.MatchString(alias) || alias == blob {
		return "", ErrCapability
	}
	// The Follower sees only this independently random wire alias, never the
	// historical logical or native IDs that may be derived from a filename.
	return s.mediaIngressCapability(ctx, id, owner, alias, alias, size, sessionExpiresAt, meta, digest, blob)
}

func (s *Service) mediaIngressCapability(ctx context.Context, id, owner, objectID, resourceID string, size, sessionExpiresAt int64, meta *mediacrypto.Metadata, digest, blob string) (string, error) {
	ingress, local, ok := network.PublicIngressIdentityFromContext(ctx)
	if !ok || !network.HasActivePublicAdmission(ctx) || local && blob == "" {
		return "", ErrCapability
	}
	authority := mediacrypto.DirectSessionFromContext(ctx)
	_, sessionID, sessionDeadline, valid := authority.Values()
	if !valid || sessionExpiresAt > sessionDeadline {
		return "", ErrCapability
	}
	public, err := Endpoint(ingress.PublicOrigin)
	if err != nil || public != ingress.PublicOrigin {
		return "", ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return "", err
	}
	relation, err := s.repo.Relationship(ctx, id)
	if err != nil {
		return "", err
	}
	if identity.Role != "Master" || local != (ingress.NodeID == identity.ID) || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version || relation.PeerID != owner {
		return "", ErrCapability
	}
	if local {
		routing, ok := s.repo.(store.PublicRoutingRepository)
		if !ok {
			return "", ErrCapability
		}
		current, err := routing.PublicIngress(ctx)
		if err != nil || current.NodeID != ingress.NodeID || current.Generation != ingress.Generation || current.PublicOrigin != ingress.PublicOrigin {
			return "", ErrCapability
		}
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return "", ErrCapability
	}
	now := time.Now().Unix()
	expires := min(sessionExpiresAt, now+protocol.TokenSeconds)
	if blob != "" {
		return protocol.OpaqueIngressMediaToken(credential, relation.ID, identity.ID, owner, objectID, ingress.NodeID, public, sessionID, blob, ingress.Generation, now, expires, size, digest, meta)
	}
	if digest != "" {
		return protocol.PlainIngressMediaToken(credential, relation.ID, identity.ID, owner, objectID, resourceID, ingress.NodeID, public, sessionID, ingress.Generation, now, expires, size, digest)
	}
	return protocol.IngressMediaToken(credential, relation.ID, identity.ID, owner, objectID, resourceID, ingress.NodeID, public, sessionID, ingress.Generation, now, expires, size, meta)
}
func capabilityHint(token string) (string, error) {
	if len(token) > 4096 {
		return "", ErrCapability
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", ErrCapability
	}
	raw, err := protocol.Decode(parts[0])
	if err != nil {
		return "", ErrCapability
	}
	var hint map[string]any
	if json.Unmarshal(raw, &hint) != nil {
		return "", ErrCapability
	}
	id := textField(hint, "r")
	if !nodeIdentifier.MatchString(id) {
		return "", ErrCapability
	}
	return id, nil
}
func (s *Service) VerifyOwnedMedia(ctx context.Context, token, objectID string) (store.Relationship, map[string]any, error) {
	return s.verifyOwnedMedia(ctx, token, objectID, nil)
}

// VerifyOwnedOpaqueMedia is separate from legacy readers so a new physical
// locator cannot be interpreted as an old path-based capability.
func (s *Service) VerifyOwnedOpaqueMedia(ctx context.Context, token, objectID string) (store.Relationship, map[string]any, error) {
	return s.verifyOwnedMedia(ctx, token, objectID, protocol.VerifyOpaqueIngressMediaToken)
}

func (s *Service) VerifyOwnedOpaqueAdminDownload(ctx context.Context, token, objectID string) (store.Relationship, map[string]any, error) {
	return s.verifyOwnedMedia(ctx, token, objectID, protocol.VerifyOpaqueAdminDownloadToken)
}

func (s *Service) verifyOwnedMedia(ctx context.Context, token, objectID string, verifyOpaque func(string, string, int64) (map[string]any, error)) (store.Relationship, map[string]any, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil {
		return store.Relationship{}, nil, ErrCapability
	}
	id, err := capabilityHint(token)
	if err != nil {
		return store.Relationship{}, nil, err
	}
	node, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return store.Relationship{}, nil, err
	}
	relation, err := s.repo.Relationship(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNodeState) {
			return store.Relationship{}, nil, ErrCapability
		}
		return store.Relationship{}, nil, err
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return store.Relationship{}, nil, ErrCapability
	}
	var value map[string]any
	if verifyOpaque != nil {
		value, err = verifyOpaque(credential, token, time.Now().Unix())
	} else if value, err = protocol.VerifyMediaToken(credential, token, time.Now().Unix()); err == nil {
		// Legacy capabilities cannot acquire the v3 CORS semantics by adding
		// fields that older v2 decoders historically ignored.
		for _, name := range []string{"kind", "origin", "ingress", "generation", "descriptor", "session", "content_sha256"} {
			if _, present := value[name]; present {
				return store.Relationship{}, nil, ErrCapability
			}
		}
	} else {
		value, err = protocol.VerifyIngressMediaToken(credential, token, time.Now().Unix())
		if err != nil {
			value, err = protocol.VerifyPlainIngressMediaToken(credential, token, time.Now().Unix())
		}
	}
	if err != nil || node.Role != "Follower" || relation.State != "active" || relation.Direction != "upstream" || relation.Protocol != protocol.Version || textField(value, "o") != node.ID || textField(value, "i") != objectID || textField(value, "m") != relation.PeerID || textField(value, "r") != relation.ID {
		return store.Relationship{}, nil, ErrCapability
	}
	return relation, value, nil
}
func (s *Service) StorageCapability(ctx context.Context, v store.UploadReservation, operation string) (string, error) {
	if v.Member.RelationshipID == nil {
		return "", ErrCapability
	}
	row, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return "", err
	}
	relation, err := s.repo.Relationship(ctx, *v.Member.RelationshipID)
	if err != nil {
		return "", err
	}
	if row.Role != "Master" || relation.State != "active" || relation.Direction != "downstream" || relation.PeerID != v.MemberID || relation.Protocol != protocol.Version {
		return "", ErrCapability
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return "", ErrCapability
	}
	if operation == "upload" {
		if v.Encryption != nil {
			return protocol.EncryptedStorageUploadToken(credential, relation.ID, row.ID, v.MemberID, v.MediaID, v.MediaID, v.Path, v.ID, v.ExpectedBytes, time.Now().Unix(), *v.Encryption)
		}
		return protocol.StorageUploadToken(credential, relation.ID, row.ID, v.MemberID, v.MediaID, v.MediaID, v.Path, v.ID, v.ExpectedBytes, time.Now().Unix())
	}
	return protocol.StorageToken(credential, relation.ID, row.ID, v.MemberID, v.MediaID, v.MediaID, operation, v.Path, v.ExpectedBytes, time.Now().Unix())
}
func (s *Service) VerifyOwnedStorage(ctx context.Context, token, objectID, operation string) (store.Relationship, map[string]any, error) {
	id, err := capabilityHint(token)
	if err != nil {
		return store.Relationship{}, nil, err
	}
	row, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return store.Relationship{}, nil, err
	}
	relation, err := s.repo.Relationship(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNodeState) {
			return store.Relationship{}, nil, ErrCapability
		}
		return store.Relationship{}, nil, err
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return store.Relationship{}, nil, ErrCapability
	}
	v, err := protocol.VerifyStorageToken(credential, token, time.Now().Unix())
	operationOK := textField(v, "op") == operation || operation == "upload" && textField(v, "op") == "upload-encrypted"
	if err != nil || row.Role != "Follower" || relation.State != "active" || relation.Direction != "upstream" || relation.Protocol != protocol.Version || textField(v, "n") != row.ID || textField(v, "i") != objectID || textField(v, "m") != relation.PeerID || textField(v, "r") != relation.ID || !operationOK {
		return store.Relationship{}, nil, ErrCapability
	}
	return relation, v, nil
}
