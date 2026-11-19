package node

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const NativePlainProbePath = "/internal/v1/native-plain-probe"
const NativePlainMediaProbePath = "/internal/v1/media/" + "0000000000000000000000000000000000000000000000000000000000000000"
const NativeOpaqueMediaProbePath = "/internal/v1/opaque-media/" + "0000000000000000000000000000000000000000000000000000000000000000"

type nativePlainMediaProber interface {
	ProbeNativePlainMedia(context.Context, string, string, string, string, string) (map[string]any, error)
}

type nativeOpaqueMediaProber interface {
	ProbeNativeOpaqueMedia(context.Context, string, string, string, string, string) (map[string]any, error)
}

// ProbeNativePlainMedia reaches the actual owner media route with a token that
// is scoped to synthetic data and cannot authorize a user resource.
func (t *Transport) ProbeNativePlainMedia(ctx context.Context, origin, relationship, credential, challenge, token string) (map[string]any, error) {
	return t.probeNativeMedia(ctx, origin, relationship, credential, challenge, token, NativePlainMediaProbePath, "X-Fc-Plain-Probe")
}

func (t *Transport) ProbeNativeOpaqueMedia(ctx context.Context, origin, relationship, credential, challenge, token string) (map[string]any, error) {
	return t.probeNativeMedia(ctx, origin, relationship, credential, challenge, token, NativeOpaqueMediaProbePath, "X-Fc-Opaque-Probe")
}

func (t *Transport) probeNativeMedia(ctx context.Context, origin, relationship, credential, challenge, token, route, probeHeader string) (map[string]any, error) {
	canonical, err := Endpoint(origin)
	if t == nil || t.client == nil || err != nil || canonical != origin || !ValidIdentifier(challenge) || token == "" || len(token) > 4096 {
		return nil, store.ErrNodeState
	}
	headers, err := protocol.AuthHeaders(credential, relationship, http.MethodGet, route, nil, time.Now().Unix())
	if err != nil {
		return nil, store.ErrNodeState
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+route, nil)
	if err != nil {
		return nil, store.ErrNodeState
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	request.Header.Set(probeHeader, challenge)
	request.Header.Set("X-Media-Capability", token)
	request.Header.Set("Accept-Encoding", "identity")
	response, err := t.client.Do(request)
	if err != nil {
		return nil, errors.New("plain media HTTPS probe failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" && !strings.EqualFold(response.Header.Get("Content-Encoding"), "identity") {
		return nil, store.ErrNodeState
	}
	return readNodeResponse(response.Body, 8192)
}

// ConfigurePlainReadProbe is startup-only and is installed only after the
// actual owner reader and its fixed probe handler have been registered.
func (s *Service) ConfigurePlainReadProbe(probe func(context.Context) error) {
	s.plainReadProbe = probe
}

// ConfigureOpaqueReadProbe is installed only when the v5 handler exists.
func (s *Service) ConfigureOpaqueReadProbe(probe func(context.Context) error) {
	s.opaqueReadProbe = probe
}

// VerifyOwnedPlainProbe is called after relationship request authentication.
// Its capability has a distinct kind that can never authorize a media read.
func (s *Service) VerifyOwnedPlainProbe(ctx context.Context, relation store.Relationship, challenge, token string) (Envelope, error) {
	return s.verifyOwnedPlainProbe(ctx, relation, challenge, token, "verified-v4-control", false)
}

func (s *Service) VerifyOwnedPlainMediaProbe(ctx context.Context, relation store.Relationship, challenge, token string) (Envelope, error) {
	return s.verifyOwnedPlainProbe(ctx, relation, challenge, token, "verified-v4-media", false)
}

func (s *Service) VerifyOwnedOpaqueMediaProbe(ctx context.Context, relation store.Relationship, challenge, token string) (Envelope, error) {
	return s.verifyOwnedPlainProbe(ctx, relation, challenge, token, "verified-v5-opaque", true)
}

func (s *Service) verifyOwnedPlainProbe(ctx context.Context, relation store.Relationship, challenge, token, marker string, opaque bool) (Envelope, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || relation.State != "active" || relation.Direction != "upstream" || !ValidIdentifier(challenge) {
		return Envelope{}, ErrCapability
	}
	probe := s.plainReadProbe
	if opaque {
		probe = s.opaqueReadProbe
	}
	if probe == nil {
		return Envelope{}, ErrCapability
	}
	// An opaque proof is evidence about a prepared Owner. Hold the same
	// relationship/identity fence as the real Owner routes until the proof is
	// signed, so a concurrent revocation cannot overtake the final recheck.
	var ownerFence IngressPrerequisiteLease
	if opaque {
		var err error
		ownerFence, err = s.AcquireOpaqueOwnerRequestFence(ctx)
		if err != nil {
			return Envelope{}, ErrCapability
		}
		defer ownerFence.Release()
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" {
		return Envelope{}, ErrCapability
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "upstream" || current.Protocol != protocol.Version || current.PeerID != relation.PeerID || current.Endpoint != relation.Endpoint || current.Credential != relation.Credential || current.PublicKey != relation.PublicKey || current.CreatedAt != relation.CreatedAt {
		return Envelope{}, ErrCapability
	}
	credential, err := s.identity.vault.Unseal(current.Credential)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	var claim map[string]any
	if opaque {
		claim, err = protocol.VerifyOpaqueIngressProbeToken(credential, token, challenge, time.Now().Unix())
	} else {
		claim, err = protocol.VerifyPlainIngressProbeToken(credential, token, challenge, time.Now().Unix())
	}
	if err != nil || textField(claim, "r") != relation.ID || textField(claim, "m") != relation.PeerID || textField(claim, "o") != identity.ID {
		return Envelope{}, ErrCapability
	}
	if err := probe(ctx); err != nil {
		return Envelope{}, ErrCapability
	}
	current, err = s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "upstream" || current.Protocol != protocol.Version || current.Credential != relation.Credential || current.PeerID != relation.PeerID || current.Endpoint != relation.Endpoint || current.PublicKey != relation.PublicKey || current.CreatedAt != relation.CreatedAt || ctx.Err() != nil || opaque && ownerFence.Check(ctx) != nil {
		return Envelope{}, ErrCapability
	}
	identityProof, err := s.SignedIdentity(ctx, challenge)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	identityProof.Payload["native_plain_probe"] = marker
	signed, err := s.identity.signed(identity, identityProof.Payload)
	if err != nil || ctx.Err() != nil || opaque && ownerFence.Check(ctx) != nil {
		return Envelope{}, ErrCapability
	}
	return signed, nil
}

// VerifyFollowerPlainReadiness proves a pinned paired owner can process a
// fresh, non-user v4 token and its actual verified chunk reader at origin.
// It does not authorize browser data, prove browser reachability or tree health.
func (s *Service) VerifyFollowerPlainReadiness(ctx context.Context, relation store.Relationship, origin string) error {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || s.transport == nil || relation.State != "active" || relation.Direction != "downstream" {
		return store.ErrNodeState
	}
	canonical, err := Endpoint(origin)
	if err != nil || canonical != origin {
		return store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return store.ErrNodeState
	}
	initial, err := s.verifyFollowerIdentityAt(ctx, relation, origin)
	features, featureErr := protocol.ReadCapabilities(initial)
	if err != nil || featureErr != nil || !slices.Contains(features, protocol.NativePlainProofCapability) {
		return store.ErrNodeState
	}
	challenge, err := randomNodeID()
	if err != nil {
		return store.ErrNodeState
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return store.ErrNodeState
	}
	token, err := protocol.PlainIngressProbeToken(credential, relation.ID, identity.ID, relation.PeerID, challenge, time.Now().Unix())
	if err != nil {
		return store.ErrNodeState
	}
	response, err := s.transport.Request(ctx, origin, NativePlainProbePath, http.MethodPost, map[string]any{"challenge": challenge, "token": token}, relation.ID, credential)
	if err != nil {
		return store.ErrNodeState
	}
	signed, err := envelope(response)
	if err != nil {
		return store.ErrNodeState
	}
	payload, err := validateFollowerIdentityEnvelope(relation, challenge, signed)
	if err != nil || textField(payload, "native_plain_probe") != "verified-v4-control" {
		return store.ErrNodeState
	}
	features, err = protocol.ReadCapabilities(payload)
	if err != nil || !slices.Contains(features, protocol.NativePlainProofCapability) {
		return store.ErrNodeState
	}
	mediaProbe, ok := s.transport.(nativePlainMediaProber)
	if !ok {
		return store.ErrNodeState
	}
	mediaChallenge, err := randomNodeID()
	if err != nil {
		return store.ErrNodeState
	}
	mediaToken, err := protocol.PlainIngressProbeToken(credential, relation.ID, identity.ID, relation.PeerID, mediaChallenge, time.Now().Unix())
	if err != nil {
		return store.ErrNodeState
	}
	mediaResponse, err := mediaProbe.ProbeNativePlainMedia(ctx, origin, relation.ID, credential, mediaChallenge, mediaToken)
	if err != nil {
		return store.ErrNodeState
	}
	mediaSigned, err := envelope(mediaResponse)
	if err != nil {
		return store.ErrNodeState
	}
	mediaPayload, err := validateFollowerIdentityEnvelope(relation, mediaChallenge, mediaSigned)
	if err != nil || textField(mediaPayload, "native_plain_probe") != "verified-v4-media" {
		return store.ErrNodeState
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "downstream" || current.Protocol != protocol.Version || current.PeerID != relation.PeerID || current.PublicKey != relation.PublicKey || current.Endpoint != relation.Endpoint || current.Credential != relation.Credential || current.CreatedAt != relation.CreatedAt {
		return store.ErrNodeState
	}
	return nil
}

// VerifyFollowerOpaqueReadiness reaches the exact v5 owner route with a
// challenge-bound, synthetic-only capability. It cannot establish user-tree
// readiness or browser reachability; both remain separate prerequisites.
func (s *Service) VerifyFollowerOpaqueReadiness(ctx context.Context, relation store.Relationship, origin string) error {
	_, _, err := s.verifyFollowerOpaqueReadinessEvidence(ctx, relation, origin)
	return err
}

func (s *Service) verifyFollowerOpaqueReadinessEvidence(ctx context.Context, relation store.Relationship, origin string) (string, Envelope, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || s.transport == nil || relation.State != "active" || relation.Direction != "downstream" {
		return "", Envelope{}, store.ErrNodeState
	}
	canonical, err := Endpoint(origin)
	if err != nil || canonical != origin {
		return "", Envelope{}, store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return "", Envelope{}, store.ErrNodeState
	}
	initial, err := s.verifyFollowerIdentityAt(ctx, relation, origin)
	features, featureErr := protocol.ReadCapabilities(initial)
	if err != nil || featureErr != nil || !slices.Contains(features, protocol.NativeOpaqueProofCapability) {
		return "", Envelope{}, store.ErrNodeState
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return "", Envelope{}, store.ErrNodeState
	}
	challenge, err := randomNodeID()
	if err != nil {
		return "", Envelope{}, store.ErrNodeState
	}
	token, err := protocol.OpaqueIngressProbeToken(credential, relation.ID, identity.ID, relation.PeerID, challenge, time.Now().Unix())
	if err != nil {
		return "", Envelope{}, store.ErrNodeState
	}
	prober, ok := s.transport.(nativeOpaqueMediaProber)
	if !ok {
		return "", Envelope{}, store.ErrNodeState
	}
	response, err := prober.ProbeNativeOpaqueMedia(ctx, origin, relation.ID, credential, challenge, token)
	if err != nil {
		return "", Envelope{}, store.ErrNodeState
	}
	signed, err := envelope(response)
	if err != nil {
		return "", Envelope{}, store.ErrNodeState
	}
	payload, err := validateFollowerIdentityEnvelope(relation, challenge, signed)
	if err != nil || textField(payload, "native_plain_probe") != "verified-v5-opaque" {
		return "", Envelope{}, store.ErrNodeState
	}
	features, err = protocol.ReadCapabilities(payload)
	if err != nil || !slices.Contains(features, protocol.NativeOpaqueProofCapability) {
		return "", Envelope{}, store.ErrNodeState
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "downstream" || current.Protocol != protocol.Version || current.PeerID != relation.PeerID || current.PublicKey != relation.PublicKey || current.Endpoint != relation.Endpoint || current.Credential != relation.Credential || current.CreatedAt != relation.CreatedAt || ctx.Err() != nil {
		return "", Envelope{}, store.ErrNodeState
	}
	return challenge, signed, nil
}
