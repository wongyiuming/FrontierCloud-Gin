package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const IngressCandidateEdgePath = "/_fc_public_proxy/_candidate_probe"
const ingressCandidateProofDomain = "/internal/v1/public-ingress-candidate-proof"
const IngressCandidatePublicPath = "/_fc_ingress_probe"
const ingressCandidateListenerDomain = "/internal/v1/public-ingress-listener-proof"

type candidateEdgeProof struct {
	PeerID    string `json:"peer_id"`
	Origin    string `json:"origin"`
	Challenge string `json:"challenge"`
}

type candidateListenerProof struct {
	MasterID  string `json:"master_id"`
	PeerID    string `json:"peer_id"`
	Origin    string `json:"origin"`
	Challenge string `json:"challenge"`
}

type candidateEdgeTransport interface {
	CandidateEdge(context.Context, string, []byte, http.Header) (map[string]any, error)
}

type candidatePublicTransport interface {
	CandidatePublic(context.Context, string, []byte, http.Header) (map[string]any, error)
}

// CandidatePublic contacts only the checked public candidate origin on the
// fixed listener probe path, using verified TLS and no redirects.
func (t *Transport) CandidatePublic(ctx context.Context, origin string, body []byte, headers http.Header) (map[string]any, error) {
	if t == nil || t.client == nil || ValidateFollowerIngressOrigin(origin) != nil || len(body) == 0 || len(body) > 1024 {
		return nil, store.ErrNodeState
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+IngressCandidatePublicPath, bytes.NewReader(body))
	if err != nil {
		return nil, store.ErrNodeState
	}
	r.Header = headers.Clone()
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-Encoding", "identity")
	response, err := t.client.Do(r)
	if err != nil {
		return nil, errors.New("candidate public HTTPS probe failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("candidate public probe rejected")
	}
	return readNodeResponse(response.Body, 8192)
}

// VerifyCandidatePublicProbe runs only behind the peer ingress wrapper. It
// authenticates the paired Master and signs a fresh challenge; it never admits
// a browser or serves business data.
func (s *Service) VerifyCandidatePublicProbe(ctx context.Context, host string, headers http.Header, body []byte) (Envelope, error) {
	if s == nil || s.repo == nil || s.followerIngressOrigin == "" || len(body) == 0 || len(body) > 1024 {
		return Envelope{}, ErrAuthentication
	}
	var proof candidateListenerProof
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF {
		return Envelope{}, ErrAuthentication
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(canonical, body) || !ValidIdentifier(proof.MasterID) || !ValidIdentifier(proof.PeerID) || !ValidIdentifier(proof.Challenge) || proof.Origin != s.followerIngressOrigin {
		return Envelope{}, ErrAuthentication
	}
	parsed, err := url.Parse(s.followerIngressOrigin)
	if err != nil || !strings.EqualFold(host, parsed.Host) {
		return Envelope{}, ErrAuthentication
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" || identity.ID != proof.PeerID {
		return Envelope{}, ErrAuthentication
	}
	relation, err := s.Authenticate(ctx, headers, http.MethodPost, ingressCandidateListenerDomain, body, false, false)
	if err != nil || relation.Direction != "upstream" || relation.State != "active" || relation.PeerID != proof.MasterID {
		return Envelope{}, ErrAuthentication
	}
	return s.SignedIdentity(ctx, proof.Challenge)
}

func (s *Service) probeFollowerIngressListener(ctx context.Context, relation store.Relationship, origin string) error {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || relation.State != "active" || relation.Direction != "downstream" {
		return store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return store.ErrNodeState
	}
	challenge, err := randomNodeID()
	if err != nil {
		return err
	}
	body, err := json.Marshal(candidateListenerProof{MasterID: identity.ID, PeerID: relation.PeerID, Origin: origin, Challenge: challenge})
	if err != nil {
		return store.ErrNodeState
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return store.ErrNodeState
	}
	values, err := protocol.AuthHeaders(credential, relation.ID, http.MethodPost, ingressCandidateListenerDomain, body, time.Now().Unix())
	if err != nil {
		return store.ErrNodeState
	}
	headers := http.Header{}
	for name, value := range values {
		headers.Set(name, value)
	}
	client, ok := s.transport.(candidatePublicTransport)
	if !ok {
		return store.ErrNodeState
	}
	value, err := client.CandidatePublic(ctx, origin, body, headers)
	if err != nil {
		return store.ErrNodeState
	}
	signed, err := envelope(value)
	if err != nil {
		return store.ErrNodeState
	}
	payload, err := validateFollowerIdentityEnvelope(relation, challenge, signed)
	if err != nil {
		return err
	}
	features, err := protocol.ReadCapabilities(payload)
	if err != nil || !slices.Contains(features, peerIngressProxyCapability) {
		return store.ErrNodeState
	}
	return nil
}

// CandidateEdge uses the ordinary restricted TLS transport but a single fixed
// edge path. It follows no redirect and exposes no media or browser credential.
func (t *Transport) CandidateEdge(ctx context.Context, master string, body []byte, headers http.Header) (map[string]any, error) {
	canonical, err := Endpoint(master)
	if t == nil || t.client == nil || err != nil || canonical != master || len(body) == 0 || len(body) > 1024 {
		return nil, store.ErrNodeState
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, master+IngressCandidateEdgePath, bytes.NewReader(body))
	if err != nil {
		return nil, store.ErrNodeState
	}
	r.Header = headers.Clone()
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-Encoding", "identity")
	response, err := t.client.Do(r)
	if err != nil {
		return nil, errors.New("candidate edge HTTPS probe failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("candidate edge probe rejected")
	}
	return readNodeResponse(response.Body, 8192)
}

// VerifyCandidateEdge authenticates the paired candidate on the dedicated
// trusted Master edge. It reveals only a fresh signed Master identity and does
// not admit any business operation or select the candidate.
func (s *Service) VerifyCandidateEdge(ctx context.Context, headers http.Header, body []byte) (Envelope, error) {
	var proof candidateEdgeProof
	if s == nil || s.repo == nil || len(body) == 0 || len(body) > 1024 {
		return Envelope{}, ErrAuthentication
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF {
		return Envelope{}, ErrAuthentication
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(canonical, body) || !ValidIdentifier(proof.PeerID) || !ValidIdentifier(proof.Challenge) || ValidateFollowerIngressOrigin(proof.Origin) != nil {
		return Envelope{}, ErrAuthentication
	}
	relation, err := s.Authenticate(ctx, headers, http.MethodPost, ingressCandidateProofDomain, body, false, false)
	if err != nil || relation.Direction != "downstream" || relation.State != "active" || relation.PeerID != proof.PeerID {
		return Envelope{}, ErrAuthentication
	}
	origin, err := s.ObservedFollowerIngressCandidate(ctx, relation.ID)
	if err != nil || origin != proof.Origin {
		return Envelope{}, ErrAuthentication
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return Envelope{}, ErrAuthentication
	}
	return s.SignedIdentity(ctx, proof.Challenge)
}

// ProbeMasterIngressEdge runs only at an explicitly configured Follower. The
// Master destination is its paired control endpoint, never request input.
func (s *Service) ProbeMasterIngressEdge(ctx context.Context, relation store.Relationship, challenge string) (Envelope, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || s.followerIngressOrigin == "" || !ValidIdentifier(challenge) {
		return Envelope{}, store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" {
		return Envelope{}, store.ErrNodeState
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "upstream" || current.PeerID != relation.PeerID {
		return Envelope{}, store.ErrNodeState
	}
	proof := candidateEdgeProof{PeerID: identity.ID, Origin: s.followerIngressOrigin, Challenge: challenge}
	body, err := json.Marshal(proof)
	if err != nil {
		return Envelope{}, store.ErrNodeState
	}
	credential, err := s.identity.vault.Unseal(current.Credential)
	if err != nil {
		return Envelope{}, store.ErrNodeState
	}
	headers, err := protocol.AuthHeaders(credential, current.ID, http.MethodPost, ingressCandidateProofDomain, body, time.Now().Unix())
	if err != nil {
		return Envelope{}, store.ErrNodeState
	}
	forward := http.Header{}
	for name, value := range headers {
		forward.Set(name, value)
	}
	client, ok := s.transport.(candidateEdgeTransport)
	if !ok {
		return Envelope{}, store.ErrNodeState
	}
	value, err := client.CandidateEdge(ctx, current.Endpoint, body, forward)
	if err != nil {
		return Envelope{}, store.ErrNodeState
	}
	signed, err := envelope(value)
	if err != nil || protocol.Verify(current.PublicKey, signed.Payload, signed.Signature) != nil {
		return Envelope{}, store.ErrNodeState
	}
	master := signed.Payload
	version, valid := intField(master, "protocol")
	endpoint, e := Endpoint(textField(master, "endpoint"))
	if !valid || version != protocol.Version || e != nil || endpoint != current.Endpoint || textField(master, "node_id") != current.PeerID || textField(master, "public_key") != current.PublicKey || textField(master, "role") != "Master" || textField(master, "challenge") != challenge {
		return Envelope{}, store.ErrNodeState
	}
	return s.SignedIdentity(ctx, challenge)
}
