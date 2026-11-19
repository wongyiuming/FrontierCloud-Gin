package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// PublicIngressLeaseSuffix names the local SQLite coordination inode.
const PublicIngressLeaseSuffix = ".public-ingress.lock"

// PublicIngress is independent of the Master identity and its control address.
// The first implementation admits only the Master; future activation requires
// the separately authenticated ingress protocol.
type PublicIngress struct {
	NodeID       string `json:"node_id"`
	PublicOrigin string `json:"public_origin"`
	Generation   int64  `json:"generation"`
}

// PublicIngressLease fences an admission against ingress and relationship
// changes. Commit orders admission before a later change; callers must not
// expose its response unless Commit succeeds. Release abandons the admission.
// Both operations end the lease, and Release is safe after either operation.
type PublicIngressLease interface {
	Commit() error
	Release()
}

// OwnerControlLease is a local filesystem fence, independent of SQL sessions.
// All node identity and relationship writers must use the same DATA_ROOT.
type OwnerControlLease interface {
	Check(context.Context) error
	Binding(context.Context) (string, error)
	Release()
}

// OwnerControlCoordinator orders local identity/relationship operations that
// also take the media-volume lock. It does not grant authorization.
type OwnerControlCoordinator interface {
	WithOwnerControlExclusive(context.Context, func(context.Context) error) error
}

// IngressPrerequisite is a process-local view of the authority held by an
// ingress lease. It is not itself an access grant and cannot release the lock.
type IngressPrerequisite interface {
	Check(context.Context) error
}

type ingressPrerequisiteKey struct{}
type opaqueControlAuthorityKey struct{}
type opaqueControlAuthority struct {
	binding string
	lease   IngressPrerequisite
}

// WithOpaqueControlAuthority is used only by the trusted Master coordinator
// after it acquires the relationship-instance fence for a persisted intent.
func WithOpaqueControlAuthority(ctx context.Context, binding string, lease IngressPrerequisite) context.Context {
	return context.WithValue(ctx, opaqueControlAuthorityKey{}, opaqueControlAuthority{binding: binding, lease: lease})
}

func OpaqueControlAuthorityFromContext(ctx context.Context, binding string) (IngressPrerequisite, bool) {
	if ctx == nil {
		return nil, false
	}
	authority, ok := ctx.Value(opaqueControlAuthorityKey{}).(opaqueControlAuthority)
	return authority.lease, ok && authority.binding == binding && authority.lease != nil
}

// WithIngressPrerequisite is for the trusted lease implementation only; no
// request header or peer-supplied value can install this context value.
func WithIngressPrerequisite(ctx context.Context, prerequisite IngressPrerequisite) context.Context {
	return context.WithValue(ctx, ingressPrerequisiteKey{}, prerequisite)
}

func IngressPrerequisiteFromContext(ctx context.Context) (IngressPrerequisite, bool) {
	if ctx == nil {
		return nil, false
	}
	v, ok := ctx.Value(ingressPrerequisiteKey{}).(IngressPrerequisite)
	return v, ok && v != nil
}

// BindIngressPrerequisite attaches an optional held prerequisite to a trusted
// handler context. Legacy leases contain no encrypted-tree authority.
func BindIngressPrerequisite(ctx context.Context, lease PublicIngressLease) (context.Context, error) {
	if binder, ok := lease.(interface {
		BindPrerequisite(context.Context) (context.Context, error)
	}); ok {
		return binder.BindPrerequisite(ctx)
	}
	return ctx, nil
}

// PeerIngressEvidence is captured after the authenticated candidate probe and
// rechecked atomically with selection. It contains no credential or media key.
type PeerIngressEvidence struct {
	MemberID, RelationshipID, PublicKey, ControlEndpoint, PublicOrigin string
	CredentialDigest                                                   string
	CreatedAt, LastHeartbeat                                           int64
}

// PeerCredentialDigest detects replacement without copying a sealed
// relationship credential into selection evidence or audit output.
func PeerCredentialDigest(sealed string) string {
	sum := sha256.Sum256([]byte(sealed))
	return hex.EncodeToString(sum[:])
}

// PeerIngressBinding identifies the exact paired relationship that was
// checked when the administrator selected an ingress. It is never a bearer.
func PeerIngressBinding(e PeerIngressEvidence) string {
	value, _ := json.Marshal([]any{e.MemberID, e.RelationshipID, e.PublicKey, e.ControlEndpoint, e.CredentialDigest, e.CreatedAt})
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// NativeResourceRevision binds the complete durable placement used by relay.
func NativeResourceRevision(row GlobalMedia) string {
	raw, _ := json.Marshal([]string{row.ID, row.MemberID, row.ObjectID, row.Path, row.Kind, row.ETag, strconv.FormatInt(row.Bytes, 10), strconv.FormatInt(row.UpdatedAt, 10)})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// PeerIngressRepository is deliberately separate from the default Master-only
// interface. Its runtime gate remains closed until all deployment prerequisites
// have been verified; no environment variable alone enables it.
type PeerIngressRepository interface {
	EnablePeerIngress()
	CommitPeerPublicIngress(context.Context, PeerIngressEvidence, int64, NodeAudit) (PublicIngress, error)
}

type NativeTransportPolicy struct {
	MemberID              string `json:"member_id"`
	ConfiguredTransport   string `json:"configured_transport"`
	AppliedTransport      string `json:"applied_transport"`
	AppliedOrigin         string `json:"applied_origin,omitempty"`
	LegacyTransport       string `json:"legacy_transport"`
	EffectiveTransport    string `json:"effective_transport"`
	State                 string `json:"state"`
	PeerApplicationStatus string `json:"peer_application_status"`
	Revision              int64  `json:"revision"`
}

// EffectiveNativeTransport treats Local as a relationship to the current
// ingress, not as a persistent choice or a synonym for Master storage.
func EffectiveNativeTransport(ingress, owner, applied string) (string, error) {
	if ingress == "" || owner == "" {
		return "", ErrNodeState
	}
	if ingress == owner {
		return "Local", nil
	}
	if applied != "Direct" && applied != "Relay" {
		return "", ErrNodeState
	}
	return applied, nil
}

type PublicRoutingRepository interface {
	// ConfigurePublicOrigin receives the validated public origin, not the control endpoint.
	ConfigurePublicOrigin(string) error
	AcquireCurrentIngress(context.Context) (PublicIngress, PublicIngressLease, error)
	CommitMasterPublicIngress(context.Context, string, int64, NodeAudit) (PublicIngress, error)
	PublicIngress(context.Context) (PublicIngress, error)
	NativeTransport(context.Context, string) (NativeTransportPolicy, error)
	ConfirmNativeTransport(context.Context, string, string, int64, NodeAudit) (NativeTransportPolicy, error)
}

// ExistingIngressRepository never initializes missing state. It is used when
// a caller may already hold the Owner fence and cannot enter a lazy writer.
type ExistingIngressRepository interface {
	ExistingPublicIngress(context.Context) (PublicIngress, error)
	AcquireExistingIngress(context.Context) (PublicIngress, PublicIngressLease, error)
}
