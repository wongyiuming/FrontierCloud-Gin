package store

import (
	"context"
	"encoding/json"
	"fmt"
)

const S3PartBytes int64 = 8 * 1024 * 1024
const S3MaxObjectBytes int64 = 10 * GiB
const S3IdleSeconds int64 = 1800
const S3AbsoluteSeconds int64 = 86400
const S3GrantSeconds int64 = 300

// S3 is a Master-owned adapter, never a relationship or a native storage peer.
// SealedCredentials is opaque vault output. Persistence never sees signing keys.
type S3Location struct {
	Endpoint string `json:"endpoint"`
	Bucket   string `json:"bucket"`
	Region   string `json:"region"`
	Prefix   string `json:"prefix"`
	Style    string `json:"style"`
}
type S3Member struct {
	StorageMember
	Name                string     `json:"name"`
	Location            S3Location `json:"location"`
	SealedCredentials   string     `json:"-"`
	CredentialExpiresAt int64      `json:"credential_expires_at"`
	CredentialRevision  int64      `json:"credential_revision"`
	CleanupOnly         bool       `json:"cleanup_only"`
	Revision            int64      `json:"revision"`
	ProbeRevision       int64      `json:"probe_revision"`
	ProbeState          string     `json:"probe_state"`
	ErrorCode           string     `json:"error_code"`
}
type S3MemberConfiguration struct {
	Name     string
	Location S3Location
	Quota    int64
	Enabled  bool
	// Nil preserves existing credentials; add requires a nonempty sealed value.
	SealedCredentials   *string `json:"-"`
	CredentialExpiresAt int64
}
type S3Part struct {
	Number     int    `json:"number"`
	Bytes      int64  `json:"size_bytes"`
	SHA256     string `json:"checksum_sha256"`
	ETag       string `json:"etag"`
	GrantUntil int64  `json:"grant_until"`
	Confirmed  bool   `json:"confirmed"`
}

// Proof contains only bounded provider metadata validated by the adapter.
// CompositeSHA256 is S3's base64 SHA256-of-part-digests with the -N suffix.
type S3ObjectProof struct {
	Key             string `json:"object_key"`
	SessionID       string `json:"session_id"`
	ObjectID        string `json:"object_id"`
	MemberID        string `json:"member_id"`
	MediaID         string `json:"media_id"`
	Bytes           int64  `json:"size_bytes"`
	ETag            string `json:"etag"`
	VersionID       string `json:"version_id"`
	CompositeSHA256 string `json:"composite_sha256"`
}
type S3Upload struct {
	Reservation        UploadReservation `json:"reservation"`
	Key                string            `json:"object_key"`
	ObjectID           string            `json:"object_id"`
	ProviderUploadID   string            `json:"-"`
	State              string            `json:"state"`
	Revision           int64             `json:"revision"`
	CredentialRevision int64             `json:"credential_revision"`
	CreateUncertain    bool              `json:"create_uncertain"`
	GrantUntil         int64             `json:"grant_until"`
	AbsoluteExpiresAt  int64             `json:"absolute_expires_at"`
	ConfirmedBytes     int64             `json:"confirmed_bytes"`
	ErrorCode          string            `json:"error_code"`
	Parts              []S3Part          `json:"parts"`
	Proof              S3ObjectProof     `json:"proof"`
}
type S3Object struct {
	Media      GlobalMedia   `json:"media"`
	Proof      S3ObjectProof `json:"proof"`
	State      string        `json:"state"`
	Revision   int64         `json:"revision"`
	GrantUntil int64         `json:"grant_until"`
	Encrypted  bool          `json:"content_encrypted"`
	ErrorCode  string        `json:"error_code"`
}

// Absence is supplied only after the service verifies the exact owned key and
// version. A timeout or empty multipart listing alone is not absence proof.
type S3AbsenceProof struct {
	Key, VersionID, ETag, ProviderUploadID, SessionID, ObjectID, MemberID, MediaID string
	ObjectAbsent, MultipartAbsent                                                  bool
}

// The intent exists before a provider probe can create any object or upload.
// Settled probe grants still participate in credential and backup fences.
type S3Probe struct {
	ID                 string `json:"probe_id"`
	MemberID           string `json:"member_id"`
	Revision           int64  `json:"revision"`
	CredentialRevision int64  `json:"credential_revision"`
	Key                string `json:"object_key"`
	ProviderUploadID   string `json:"-"`
	VersionID          string `json:"version_id"`
	ETag               string `json:"etag"`
	State              string `json:"state"`
	GrantUntil         int64  `json:"grant_until"`
	ErrorCode          string `json:"error_code"`
	CreatedAt          int64  `json:"created_at"`
	UpdatedAt          int64  `json:"updated_at"`
}

type S3ProbeResult struct {
	Key, ProviderUploadID, VersionID, ETag string
	ChecksPassed, CleanupSettled           bool
	// NoMutation is a deterministic provider rejection before any create; an
	// empty multipart listing is never this evidence.
	NoMutation bool
	ErrorCode  string
}

// S3Repository is optional: existing native pool consumers and test doubles do
// not gain S3 authority. No callback may perform network I/O inside SQL writes.
type S3Repository interface {
	S3Members(context.Context) ([]S3Member, error)
	S3Member(context.Context, string) (S3Member, error)
	S3AddMember(context.Context, S3MemberConfiguration, NodeAudit) (S3Member, error)
	S3ConfigureMember(context.Context, string, int64, S3MemberConfiguration, NodeAudit) (S3Member, error)
	S3ProbeMember(context.Context, string, int64, string, NodeAudit) (S3Member, error)
	S3StartProbe(context.Context, string, int64, NodeAudit) (S3Probe, error)
	S3CheckpointProbe(context.Context, string, int64, string) error
	S3FinishProbe(context.Context, string, int64, S3ProbeResult, NodeAudit) (S3Member, error)
	S3RecoveryProbes(context.Context, int) ([]S3Probe, error)
	S3RecoveryCredentials(context.Context, string, int64, string, int64, NodeAudit) (S3Member, error)
	S3RemoveMember(context.Context, string, int64, NodeAudit) error
	S3Upload(context.Context, string) (S3Upload, error)
	S3PendingUploads(context.Context, int) ([]S3Upload, error)
	S3StartCreate(context.Context, string, int64) (S3Upload, error)
	// outcome is created, rejected (proven no mutation), or unknown.
	S3FinishCreate(ctx context.Context, id string, revision int64, providerUploadID, outcome, code string) (S3Upload, error)
	S3IssuePart(context.Context, string, int, string, int64) (S3Part, error)
	S3ConfirmPart(context.Context, string, S3Part) (S3Upload, error)
	S3TouchUpload(context.Context, string) (S3Upload, error)
	S3StartComplete(context.Context, string, int64) (S3Upload, error)
	S3FinalizeUpload(context.Context, string, int64, S3ObjectProof, AdminAudit) (GlobalMedia, error)
	S3RequestAbort(context.Context, string, AdminAudit) (S3Upload, error)
	S3FinishAbort(context.Context, string, int64, S3AbsenceProof, AdminAudit) (S3Upload, error)
	S3RecoveryUploads(context.Context, int) ([]S3Upload, error)
	S3RecordUploadError(context.Context, string, int64, string) error
	S3Object(context.Context, string) (S3Object, error)
	S3IssueReadGrant(context.Context, string, int64) (S3Object, error)
	S3StartDelete(context.Context, string, AdminAudit) (S3Object, error)
	S3FinishDelete(context.Context, string, int64, S3AbsenceProof, AdminAudit) error
	S3PendingDeletes(context.Context, int) ([]S3Object, error)
}

func (v S3Member) String() string {
	return fmt.Sprintf("S3 member %s revision %d [credentials redacted]", v.ID, v.Revision)
}
func (v S3Member) GoString() string { return v.String() }

// StorageMember's custom marshaler must not hide this embedding's S3 fields.
// Credentials remain absent even when a caller marshals an internal record.
func (v S3Member) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(v.StorageMember)
	if err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	for key, value := range map[string]any{"name": v.Name, "location": v.Location,
		"credential_expires_at": v.CredentialExpiresAt, "credential_revision": v.CredentialRevision,
		"cleanup_only": v.CleanupOnly, "revision": v.Revision, "probe_revision": v.ProbeRevision,
		"probe_state": v.ProbeState, "error_code": v.ErrorCode} {
		result[key], err = json.Marshal(value)
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(result)
}

// An object store has no observed filesystem or native worker/backup plane.
// Keep native numeric DTO fields for callers, but serialize unknown facts as
// null rather than representing an unobserved provider capacity as zero.
func (v StorageMember) MarshalJSON() ([]byte, error) {
	type plain StorageMember
	data, err := json.Marshal(plain(v))
	if err != nil {
		return nil, err
	}
	// Native DTOs also occur inside hashed migration manifests. Preserve
	// their existing field order and bytes, not just the decoded JSON shape.
	if v.Kind != "S3" {
		return data, nil
	}
	var result map[string]json.RawMessage
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	if v.Kind == "S3" {
		result["physical_capacity_known"] = json.RawMessage("false")
		result["physical_free_bytes"], result["physical_total_bytes"] = json.RawMessage("null"), json.RawMessage("null")
		result["compute"], result["backup"] = json.RawMessage("null"), json.RawMessage("null")
		result["external_traffic_known"] = json.RawMessage("false")
	}
	return json.Marshal(result)
}
