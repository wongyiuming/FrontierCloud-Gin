package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var publicHostname = regexp.MustCompile(`^[a-z0-9.-]+$`)

const nativeTransportReceiptKey = "_local_native_transport_receipt"

type nativeTransportReceipt struct {
	Transport string `json:"transport"`
	Revision  int64  `json:"revision"`
	Origin    string `json:"origin,omitempty"`
}

func validPublicOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Host != strings.ToLower(u.Host) || u.Port() != "" || strings.HasSuffix(u.Host, ":") || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(origin, "\\\r\n\t ") || u.String() != origin {
		return false
	}
	host := u.Hostname()
	if address, e := netip.ParseAddr(host); e == nil {
		address = address.Unmap()
		return address.Zone() == "" && address.IsValid() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() && !address.IsMulticast() && !address.IsUnspecified() && host == address.String()
	}
	return publicHostname.MatchString(host) && host != "localhost" && host != "metadata.google.internal" && !strings.HasSuffix(host, ".localhost")
}

// ConfigurePublicOrigin is startup-only configuration. It cannot rewrite an
// existing ingress record and is intentionally independent of node Endpoint.
func (r *Repository) ConfigurePublicOrigin(origin string) error {
	if !validPublicOrigin(origin) {
		return store.ErrNodeState
	}
	r.publicOriginMu.Lock()
	defer r.publicOriginMu.Unlock()
	if r.publicOrigin != "" && r.publicOrigin != origin {
		return store.ErrNodeState
	}
	r.publicOrigin = origin
	return nil
}

func (r *Repository) configuredPublicOrigin() string {
	r.publicOriginMu.RLock()
	defer r.publicOriginMu.RUnlock()
	return r.publicOrigin
}

// EnablePeerIngress is startup-only and must be called only after the runtime
// has verified all required storage, proxy and resource-serving prerequisites.
func (r *Repository) EnablePeerIngress() { r.peerIngressEnabled.Store(true) }

func validateActivePeerIngress(ctx context.Context, q queryer, peerID, origin string) error {
	var binding string
	if err := q.QueryRowContext(ctx, "SELECT peer_binding FROM public_ingress_config WHERE singleton=1 AND node_id=? AND public_origin=?", peerID, origin).Scan(&binding); err != nil || !nodeHashPattern.MatchString(binding) {
		return store.ErrNodeState
	}
	relation, err := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE peer_id=? AND direction='downstream' AND state='active'", peerID))
	if err != nil || relation.Summary["public_ingress_candidate_origin"] != origin {
		return store.ErrNodeState
	}
	evidence := store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt}
	if store.PeerIngressBinding(evidence) != binding {
		return store.ErrNodeState
	}
	features, err := protocol.ReadCapabilities(relation.Summary)
	if err != nil || !slices.Contains(features, protocol.PublicIngressProxyCapability) {
		return store.ErrNodeState
	}
	return nil
}

func (r *Repository) readPublicIngress(ctx context.Context) (result store.PublicIngress, err error) {
	var identityID, role string
	err = r.db.QueryRowContext(ctx, "SELECT c.node_id,c.public_origin,c.generation,n.node_id,n.`role` FROM public_ingress_config c JOIN node_identity n ON n.singleton=1 WHERE c.singleton=1").Scan(&result.NodeID, &result.PublicOrigin, &result.Generation, &identityID, &role)
	if err == nil {
		if role != "Master" || !nodeIDPattern.MatchString(identityID) || !nodeIDPattern.MatchString(result.NodeID) || !validPublicOrigin(result.PublicOrigin) || result.Generation < 1 || result.NodeID != identityID && !r.peerIngressEnabled.Load() {
			return store.PublicIngress{}, store.ErrNodeState
		}
	}
	return
}

// ExistingPublicIngress is read-only even when the default ingress has never
// been initialized. It must not call the lazy PublicIngress writer.
func (r *Repository) ExistingPublicIngress(ctx context.Context) (store.PublicIngress, error) {
	current, err := r.readPublicIngress(ctx)
	if err != nil || r.configuredPublicOrigin() == "" {
		return store.PublicIngress{}, store.ErrNodeState
	}
	var identityID string
	if err := r.db.QueryRowContext(ctx, "SELECT node_id FROM node_identity WHERE singleton=1").Scan(&identityID); err != nil || current.NodeID == identityID && current.PublicOrigin != r.configuredPublicOrigin() {
		return store.PublicIngress{}, store.ErrNodeState
	}
	return current, nil
}

// PublicIngress initializes only from an explicitly configured public origin.
// No non-Master candidate can be admitted until its full protocol exists.
func (r *Repository) PublicIngress(ctx context.Context) (result store.PublicIngress, err error) {
	result, err = r.readPublicIngress(ctx)
	if !errors.Is(err, sql.ErrNoRows) {
		if err == nil && r.configuredPublicOrigin() != "" {
			var identityID string
			if e := r.db.QueryRowContext(ctx, "SELECT node_id FROM node_identity WHERE singleton=1").Scan(&identityID); e != nil {
				return store.PublicIngress{}, e
			}
			if result.NodeID == identityID && result.PublicOrigin != r.configuredPublicOrigin() {
				return store.PublicIngress{}, store.ErrNodeState
			}
		}
		return result, err
	}
	origin := r.configuredPublicOrigin()
	if !validPublicOrigin(origin) {
		return store.PublicIngress{}, store.ErrNodeState
	}
	err = r.ingressWrite(ctx, func(q queryer) error {
		identity, err := readNode(ctx, q, r.lock())
		if err != nil {
			return err
		}
		if identity.Role != "Master" || !nodeIDPattern.MatchString(identity.ID) {
			return store.ErrNodeState
		}
		err = q.QueryRowContext(ctx, "SELECT node_id,public_origin,generation FROM public_ingress_config WHERE singleton=1"+r.lock()).Scan(&result.NodeID, &result.PublicOrigin, &result.Generation)
		if errors.Is(err, sql.ErrNoRows) {
			result = store.PublicIngress{NodeID: identity.ID, PublicOrigin: origin, Generation: 1}
			_, err = q.ExecContext(ctx, "INSERT INTO public_ingress_config(singleton,node_id,public_origin,generation,updated_at) VALUES (1,?,?,1,?)", result.NodeID, result.PublicOrigin, time.Now().Unix())
		}
		if err != nil {
			return err
		}
		// Until the peer ingress protocol exists, even a tampered DB cannot
		// silently switch the actual public serving authority.
		if result.NodeID != identity.ID || result.PublicOrigin != origin || !validPublicOrigin(result.PublicOrigin) || result.Generation < 1 {
			return store.ErrNodeState
		}
		return nil
	})
	return
}

// AcquireCurrentIngress holds a shared fence until admission is committed or
// abandoned. The caller must not expose its response before Commit succeeds.
func (r *Repository) AcquireCurrentIngress(ctx context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	if _, err := r.PublicIngress(ctx); err != nil {
		return store.PublicIngress{}, nil, err
	}
	return r.AcquireExistingIngress(ctx)
}

// AcquireExistingIngress cannot lazily initialize under another held fence.
func (r *Repository) AcquireExistingIngress(ctx context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	if r.backend == "mysql" {
		current, lease, err := r.acquireMySQLIngressLease(ctx)
		if err != nil {
			return store.PublicIngress{}, nil, err
		}
		return current, lease, nil
	}
	release, err := r.ingressLease(ctx, false)
	if err != nil {
		return store.PublicIngress{}, nil, err
	}
	current, err := r.readPublicIngress(ctx)
	if err == nil {
		validated, e := r.ExistingPublicIngress(ctx)
		if e != nil || validated != current || r.configuredPublicOrigin() == "" {
			err = store.ErrNodeState
		}
	}
	if err == nil {
		var identityID string
		if e := r.db.QueryRowContext(ctx, "SELECT node_id FROM node_identity WHERE singleton=1").Scan(&identityID); e != nil {
			err = e
		} else if current.NodeID != identityID && validateActivePeerIngress(ctx, r.db, current.NodeID, current.PublicOrigin) != nil {
			err = store.ErrNodeState
		}
	}
	if err != nil || ctx.Err() != nil {
		release()
		if err == nil {
			err = ctx.Err()
		}
		return store.PublicIngress{}, nil, err
	}
	return current, &sqliteIngressReadLease{release: release}, nil
}

// CommitMasterPublicIngress supplies the exclusive commit boundary and CAS for
// explicit Master selections only. No peer eligibility is inferred here.
func (r *Repository) CommitMasterPublicIngress(ctx context.Context, origin string, expected int64, audit store.NodeAudit) (result store.PublicIngress, err error) {
	if expected < 1 || expected == math.MaxInt64 || !validPublicOrigin(origin) || origin != r.configuredPublicOrigin() {
		return result, store.ErrNodeState
	}
	err = r.ingressWrite(ctx, func(q queryer) error {
		identity, err := readNode(ctx, q, r.lock())
		if err != nil || identity.Role != "Master" || !nodeIDPattern.MatchString(identity.ID) {
			return store.ErrNodeState
		}
		var current store.PublicIngress
		if err = q.QueryRowContext(ctx, "SELECT node_id,public_origin,generation FROM public_ingress_config WHERE singleton=1"+r.lock()).Scan(&current.NodeID, &current.PublicOrigin, &current.Generation); err != nil {
			return err
		}
		if current.NodeID != identity.ID && !r.peerIngressEnabled.Load() || !validPublicOrigin(current.PublicOrigin) || current.Generation != expected {
			return store.ErrNodeState
		}
		updated, err := q.ExecContext(ctx, "UPDATE public_ingress_config SET node_id=?,public_origin=?,peer_binding='',generation=generation+1,updated_at=? WHERE singleton=1 AND node_id=? AND generation=?", identity.ID, origin, time.Now().Unix(), current.NodeID, expected)
		if err != nil {
			return err
		}
		if n, err := updated.RowsAffected(); err != nil || n != 1 {
			return store.ErrNodeState
		}
		result = store.PublicIngress{NodeID: identity.ID, PublicOrigin: origin, Generation: expected + 1}
		return r.nodeAudit(ctx, q, "public-ingress-selected", "", map[string]any{"node_id": identity.ID, "public_origin": origin, "generation": result.Generation}, audit)
	})
	if err != nil {
		return store.PublicIngress{}, err
	}
	return result, nil
}

// CommitPeerPublicIngress rechecks all candidate evidence under the same
// exclusive fence and transaction as the generation CAS. It cannot be reached
// until the separate runtime prerequisite gate has been enabled.
func (r *Repository) CommitPeerPublicIngress(ctx context.Context, evidence store.PeerIngressEvidence, expected int64, audit store.NodeAudit) (result store.PublicIngress, err error) {
	if !r.peerIngressEnabled.Load() || expected < 1 || expected == math.MaxInt64 || !nodeIDPattern.MatchString(evidence.MemberID) || !nodeIDPattern.MatchString(evidence.RelationshipID) || !nodeHashPattern.MatchString(evidence.CredentialDigest) || !validPublicOrigin(evidence.PublicOrigin) || evidence.PublicKey == "" || evidence.ControlEndpoint == "" || evidence.CreatedAt < 1 || evidence.LastHeartbeat < 1 {
		return result, store.ErrNodeState
	}
	err = r.ingressWrite(ctx, func(q queryer) error {
		identity, err := readNode(ctx, q, r.lock())
		if err != nil || identity.Role != "Master" || identity.ID == evidence.MemberID {
			return store.ErrNodeState
		}
		var current store.PublicIngress
		var currentBinding string
		if err := q.QueryRowContext(ctx, "SELECT node_id,public_origin,generation,peer_binding FROM public_ingress_config WHERE singleton=1"+r.lock()).Scan(&current.NodeID, &current.PublicOrigin, &current.Generation, &currentBinding); err != nil {
			return err
		}
		if current.Generation != expected || !nodeIDPattern.MatchString(current.NodeID) || !validPublicOrigin(current.PublicOrigin) {
			return store.ErrNodeState
		}
		relation, err := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), evidence.RelationshipID))
		if err != nil || relation.PeerID != evidence.MemberID || relation.PublicKey != evidence.PublicKey || relation.Endpoint != evidence.ControlEndpoint || relation.CreatedAt != evidence.CreatedAt || store.PeerCredentialDigest(relation.Credential) != evidence.CredentialDigest || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version || relation.Status != "online" || relation.LastHeartbeat != evidence.LastHeartbeat || time.Now().Unix()-relation.LastHeartbeat < 0 || time.Now().Unix()-relation.LastHeartbeat >= 120 || relation.Summary["public_ingress_candidate_origin"] != evidence.PublicOrigin {
			return store.ErrNodeState
		}
		features, err := protocol.ReadCapabilities(relation.Summary)
		if err != nil || !slices.Contains(features, protocol.PublicIngressProxyCapability) {
			return store.ErrNodeState
		}
		var kind, health string
		var relationship sql.NullString
		if err := q.QueryRowContext(ctx, "SELECT member_kind,health,relationship_id FROM cluster_storage_members WHERE member_id=?"+r.lock(), evidence.MemberID).Scan(&kind, &health, &relationship); err != nil || kind != "Follower" || health != "online" || !relationship.Valid || relationship.String != relation.ID {
			return store.ErrNodeState
		}
		binding := store.PeerIngressBinding(evidence)
		if current.NodeID == evidence.MemberID && current.PublicOrigin == evidence.PublicOrigin && currentBinding == binding {
			result = current
			return nil
		}
		updated, err := q.ExecContext(ctx, "UPDATE public_ingress_config SET node_id=?,public_origin=?,peer_binding=?,generation=generation+1,updated_at=? WHERE singleton=1 AND node_id=? AND generation=?", evidence.MemberID, evidence.PublicOrigin, binding, time.Now().Unix(), current.NodeID, expected)
		if err != nil {
			return err
		}
		if n, err := updated.RowsAffected(); err != nil || n != 1 {
			return store.ErrNodeState
		}
		result = store.PublicIngress{NodeID: evidence.MemberID, PublicOrigin: evidence.PublicOrigin, Generation: expected + 1}
		return r.nodeAudit(ctx, q, "public-ingress-selected", relation.ID, map[string]any{"node_id": result.NodeID, "public_origin": result.PublicOrigin, "generation": result.Generation}, audit)
	})
	if err != nil {
		return store.PublicIngress{}, err
	}
	return result, nil
}

func (r *Repository) nativeTransport(ctx context.Context, q queryer, identity store.NodeIdentity, ingress store.PublicIngress, memberID, lock string) (result store.NativeTransportPolicy, err error) {
	result.MemberID = memberID
	inactive := false
	var appliedRevision int64
	var reported nativeTransportReceipt
	var reportedState string
	var advertisedOrigin string
	var directObservationFresh bool
	if !nodeIDPattern.MatchString(memberID) {
		return result, store.ErrNodeState
	}
	var kind string
	var relationship sql.NullString
	err = q.QueryRowContext(ctx, "SELECT member_kind,relationship_id FROM cluster_storage_members WHERE member_id=?"+lock, memberID).Scan(&kind, &relationship)
	if errors.Is(err, sql.ErrNoRows) {
		return result, store.ErrNodeState
	}
	if err != nil {
		return result, err
	}
	if memberID == identity.ID {
		if kind != "MasterLocal" || relationship.Valid {
			return result, store.ErrNodeState
		}
	} else {
		if kind != "Follower" || !relationship.Valid {
			return result, store.ErrNodeState
		}
		var peer, state, direction, status string
		var lastHeartbeat int64
		var summary string
		err = q.QueryRowContext(ctx, "SELECT peer_id,state,direction,mode,summary,status,last_heartbeat FROM node_relationships WHERE relationship_id=?"+lock, relationship.String).Scan(&peer, &state, &direction, &result.LegacyTransport, &summary, &status, &lastHeartbeat)
		if err != nil || peer != memberID || direction != "downstream" || (result.LegacyTransport != "Direct" && result.LegacyTransport != "Relay") {
			return result, store.ErrNodeState
		}
		inactive = state != "active"
		directObservationFresh = status == "online" && lastHeartbeat > 0 && time.Now().Unix()-lastHeartbeat >= 0 && time.Now().Unix()-lastHeartbeat < 120
		var parsed map[string]json.RawMessage
		if json.Unmarshal([]byte(summary), &parsed) != nil {
			return result, store.ErrNodeState
		}
		if raw := parsed[nativeTransportReceiptKey]; len(raw) != 0 {
			var receipt nativeTransportReceipt
			if json.Unmarshal(raw, &receipt) != nil || receipt.Revision < 1 || receipt.Transport != "Relay" && receipt.Transport != "Direct" || receipt.Transport == "Relay" && receipt.Origin != "" || receipt.Transport == "Direct" && !validPublicOrigin(receipt.Origin) {
				return result, store.ErrNodeState
			}
			result.AppliedTransport = receipt.Transport
			result.AppliedOrigin = receipt.Origin
			appliedRevision = receipt.Revision
		}
		_ = json.Unmarshal(parsed["native_resource_origin"], &advertisedOrigin)
		if raw := parsed["native_transport_result"]; len(raw) != 0 {
			var observation struct {
				Transport string `json:"transport"`
				Revision  int64  `json:"revision"`
				State     string `json:"state"`
			}
			if json.Unmarshal(raw, &observation) == nil {
				reported = nativeTransportReceipt{Transport: observation.Transport, Revision: observation.Revision}
				reportedState = observation.State
			}
		}
	}
	err = q.QueryRowContext(ctx, "SELECT configured_transport,revision FROM native_transport_policy WHERE member_id=?"+lock, memberID).Scan(&result.ConfiguredTransport, &result.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		result.ConfiguredTransport = result.LegacyTransport // preserve the Master-side legacy follower route
		result.State = "confirmation_required"
	} else if err != nil {
		return result, err
	} else if result.ConfiguredTransport != "Direct" && result.ConfiguredTransport != "Relay" || result.Revision < 1 {
		return result, store.ErrNodeState
	} else if memberID == ingress.NodeID {
		result.State = "retained"
	} else if result.AppliedTransport == result.ConfiguredTransport && appliedRevision == result.Revision && (result.AppliedTransport != "Direct" || directObservationFresh && result.AppliedOrigin == advertisedOrigin) {
		result.State = "applied"
	} else if result.AppliedTransport == "" && result.ConfiguredTransport == result.LegacyTransport {
		result.State = "legacy_confirmed"
	} else {
		result.State = "blocked"
	}
	if inactive {
		result.State = "inactive"
	}
	if result.Revision > 0 {
		result.PeerApplicationStatus = "pending"
		if result.State == "applied" {
			result.PeerApplicationStatus = "applied"
		}
		if result.State != "applied" && reported.Revision == result.Revision && reported.Transport == result.ConfiguredTransport && reportedState == "blocked" {
			result.PeerApplicationStatus = "failed"
		}
	}
	// While Master is ingress, the established route still uses relationship
	// mode. At a peer ingress, non-local native plans use only the explicitly
	// applied policy; a pending change cannot silently inherit the old route.
	if memberID == identity.ID && ingress.NodeID != identity.ID {
		// Master has no legacy non-ingress route. Its runtime verifier must
		// supply an applied policy; do not infer one from its former Local mode.
		result.EffectiveTransport = ""
		return result, nil
	}
	effective := result.LegacyTransport
	if ingress.NodeID != identity.ID && memberID != ingress.NodeID {
		if result.State != "applied" {
			result.EffectiveTransport = ""
			return result, nil
		}
		effective = result.AppliedTransport
	}
	result.EffectiveTransport, err = store.EffectiveNativeTransport(ingress.NodeID, memberID, effective)
	return result, err
}

// RecordNativeTransportApplication publishes an authenticated, readiness-checked
// peer acknowledgment. The caller must have verified the peer and the relay
// gateway; this method fences publication against both ingress and desired policy
// changes. Direct acknowledgments are deliberately unsupported pending proof of
// the independent public resource origin.
func (r *Repository) RecordNativeTransportApplication(ctx context.Context, relationshipID string, revision int64, transport string) error {
	if transport != "Relay" {
		return store.ErrNodeState
	}
	return r.recordNativeTransportApplication(ctx, relationshipID, revision, transport, "")
}

// RecordNativeDirectApplication binds the peer receipt to the independently
// verified resource origin as well as the desired policy revision.
func (r *Repository) RecordNativeDirectApplication(ctx context.Context, relationshipID string, revision int64, origin string) error {
	return r.recordNativeTransportApplication(ctx, relationshipID, revision, "Direct", origin)
}

func (r *Repository) recordNativeTransportApplication(ctx context.Context, relationshipID string, revision int64, transport, origin string) error {
	if revision < 1 || transport == "Relay" && origin != "" || transport == "Direct" && !validPublicOrigin(origin) || transport != "Relay" && transport != "Direct" {
		return store.ErrNodeState
	}
	return r.withRelationWrite(ctx, relationshipID, r.ingressWrite, func(q queryer, identity store.NodeIdentity, relation store.Relationship) error {
		if identity.Role != "Master" || relation.Direction != "downstream" || relation.State != "active" {
			return store.ErrNodeState
		}
		if transport == "Direct" && (relation.Status != "online" || relation.LastHeartbeat <= 0 || time.Now().Unix()-relation.LastHeartbeat < 0 || time.Now().Unix()-relation.LastHeartbeat >= 120 || relation.Summary["native_resource_origin"] != origin) {
			return store.ErrNodeState
		}
		var ingress store.PublicIngress
		if err := q.QueryRowContext(ctx, "SELECT node_id,public_origin,generation FROM public_ingress_config WHERE singleton=1"+r.shareLock()).Scan(&ingress.NodeID, &ingress.PublicOrigin, &ingress.Generation); err != nil {
			return err
		}
		policy, err := r.nativeTransport(ctx, q, identity, ingress, relation.PeerID, r.lock())
		if err != nil {
			return err
		}
		if policy.Revision != revision || policy.ConfiguredTransport != transport || ingress.NodeID == relation.PeerID {
			return store.ErrNodeState
		}
		if relation.Summary == nil {
			relation.Summary = map[string]any{}
		}
		relation.Summary[nativeTransportReceiptKey] = nativeTransportReceipt{Transport: transport, Revision: revision, Origin: origin}
		encoded, err := json.Marshal(relation.Summary)
		if err != nil {
			return err
		}
		if len(encoded) > MaxNodeSummaryBytes {
			return store.ErrNodeState
		}
		if _, err = q.ExecContext(ctx, "UPDATE node_relationships SET summary=? WHERE relationship_id=?", string(encoded), relationshipID); err != nil {
			return err
		}
		return r.nodeAudit(ctx, q, "native-transport-applied", relationshipID, map[string]any{"member_id": relation.PeerID, "transport": transport, "revision": revision}, store.NodeAudit{Actor: "peer-ack"})
	})
}

// AcceptNativeTransportApplication records a Follower's locally verified
// application monotonically, tied to its active upstream relationship.
func (r *Repository) AcceptNativeTransportApplication(ctx context.Context, relationshipID string, revision int64, transport string) error {
	if transport != "Relay" {
		return store.ErrNodeState
	}
	return r.acceptNativeTransportApplication(ctx, relationshipID, revision, transport, "")
}

func (r *Repository) AcceptNativeDirectApplication(ctx context.Context, relationshipID string, revision int64, origin string) error {
	return r.acceptNativeTransportApplication(ctx, relationshipID, revision, "Direct", origin)
}

func (r *Repository) acceptNativeTransportApplication(ctx context.Context, relationshipID string, revision int64, transport, origin string) error {
	if revision < 1 || transport == "Relay" && origin != "" || transport == "Direct" && !validPublicOrigin(origin) || transport != "Relay" && transport != "Direct" {
		return store.ErrNodeState
	}
	return r.withRelationWrite(ctx, relationshipID, r.ingressWrite, func(q queryer, identity store.NodeIdentity, relation store.Relationship) error {
		if identity.Role != "Follower" || relation.Direction != "upstream" || relation.State != "active" {
			return store.ErrNodeState
		}
		if old, ok := relation.Summary[nativeTransportReceiptKey]; ok {
			b, err := json.Marshal(old)
			if err != nil {
				return err
			}
			var prior nativeTransportReceipt
			if json.Unmarshal(b, &prior) != nil || prior.Revision < 1 || prior.Transport != "Relay" && prior.Transport != "Direct" || revision < prior.Revision {
				return store.ErrNodeState
			}
			if revision == prior.Revision {
				if prior.Transport != transport || prior.Origin != origin {
					return store.ErrNodeState
				}
				return nil
			}
		}
		if relation.Summary == nil {
			relation.Summary = map[string]any{}
		}
		relation.Summary[nativeTransportReceiptKey] = nativeTransportReceipt{Transport: transport, Revision: revision, Origin: origin}
		encoded, err := json.Marshal(relation.Summary)
		if err != nil {
			return err
		}
		if len(encoded) > MaxNodeSummaryBytes {
			return store.ErrNodeState
		}
		if _, err = q.ExecContext(ctx, "UPDATE node_relationships SET summary=? WHERE relationship_id=?", string(encoded), relationshipID); err != nil {
			return err
		}
		return r.nodeAudit(ctx, q, "native-transport-peer-applied", relationshipID, map[string]any{"transport": transport, "revision": revision}, store.NodeAudit{Actor: relation.PeerID})
	})
}

func (r *Repository) NativeTransport(ctx context.Context, memberID string) (store.NativeTransportPolicy, error) {
	ingress, err := r.PublicIngress(ctx)
	if err != nil {
		return store.NativeTransportPolicy{}, err
	}
	return r.nativeTransportForIngress(ctx, ingress, memberID)
}

// ExistingNativeTransport never creates an ingress row while another fence is
// held. Missing or inconsistent state remains unavailable.
func (r *Repository) ExistingNativeTransport(ctx context.Context, memberID string) (store.NativeTransportPolicy, error) {
	ingress, err := r.ExistingPublicIngress(ctx)
	if err != nil {
		return store.NativeTransportPolicy{}, err
	}
	return r.nativeTransportForIngress(ctx, ingress, memberID)
}

func (r *Repository) nativeTransportForIngress(ctx context.Context, ingress store.PublicIngress, memberID string) (store.NativeTransportPolicy, error) {
	identity, err := r.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	return r.nativeTransport(ctx, r.db, identity, ingress, memberID, "")
}

// ConfirmNativeTransport records an administrator's desired policy with CAS.
// A follower's existing route remains effective until a future versioned peer
// application protocol confirms the requested mode; saving is not application.
func (r *Repository) ConfirmNativeTransport(ctx context.Context, memberID, desired string, expected int64, audit store.NodeAudit) (store.NativeTransportPolicy, error) {
	if (desired != "Direct" && desired != "Relay") || expected < 0 || expected == math.MaxInt64 {
		return store.NativeTransportPolicy{}, store.ErrNodeState
	}
	ingress, err := r.PublicIngress(ctx)
	if err != nil {
		return store.NativeTransportPolicy{}, err
	}
	// A verifier may be holding the shared ingress lease while it reads this
	// desired policy and issues a capability. Serialize changes with that
	// admission so no grant is issued using a policy concurrently superseded
	// before the lease commits. This does not apply a pending peer policy.
	err = r.ingressWrite(ctx, func(q queryer) error {
		// ingressWrite took the exclusive gate before any node or policy rows.
		var persisted store.PublicIngress
		if err := q.QueryRowContext(ctx, "SELECT node_id,public_origin,generation FROM public_ingress_config WHERE singleton=1"+r.shareLock()).Scan(&persisted.NodeID, &persisted.PublicOrigin, &persisted.Generation); err != nil || persisted != ingress {
			return store.ErrNodeState
		}
		identity, err := readNode(ctx, q, r.lock())
		if err != nil || identity.Role != "Master" || identity.ID != ingress.NodeID && !r.peerIngressEnabled.Load() {
			return store.ErrNodeState
		}
		current, err := r.nativeTransport(ctx, q, identity, ingress, memberID, r.lock())
		if err != nil || current.Revision != expected || current.State == "inactive" {
			return store.ErrNodeState
		}
		if current.Revision > 0 && current.ConfiguredTransport == desired {
			return nil
		}
		now := time.Now().Unix()
		if current.Revision == 0 {
			_, err = q.ExecContext(ctx, "INSERT INTO native_transport_policy(member_id,configured_transport,revision,updated_at) VALUES (?,?,1,?)", memberID, desired, now)
		} else {
			var result sql.Result
			result, err = q.ExecContext(ctx, "UPDATE native_transport_policy SET configured_transport=?,revision=revision+1,updated_at=? WHERE member_id=? AND revision=?", desired, now, memberID, expected)
			if err == nil {
				var count int64
				count, err = result.RowsAffected()
				if err == nil && count != 1 {
					err = store.ErrNodeState
				}
			}
		}
		if err != nil {
			return err
		}
		return r.nodeAudit(ctx, q, "native-transport-configured", "", map[string]any{"member_id": memberID, "configured_transport": desired, "revision": expected + 1}, audit)
	})
	if err != nil {
		return store.NativeTransportPolicy{}, err
	}
	return r.NativeTransport(ctx, memberID)
}

var _ store.PublicRoutingRepository = (*Repository)(nil)
