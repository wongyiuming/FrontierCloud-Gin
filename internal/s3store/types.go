// Package s3store implements the bounded S3 control plane. Browser media bytes
// travel directly to the provider; this package never relays an uploaded file.
package s3store

import (
	"context"
	"errors"
	"time"
)

const PartSize int64 = 8 << 20
const MaxObjectSize int64 = 10 << 30

var (
	ErrConfig      = errors.New("s3_config")
	ErrCredentials = errors.New("s3_credentials")
	ErrEndpoint    = errors.New("s3_endpoint")
	ErrNetwork     = errors.New("s3_network")
	ErrNotFound    = errors.New("s3_not_found")
	ErrDenied      = errors.New("s3_denied")
	ErrConflict    = errors.New("s3_conflict")
	ErrResponse    = errors.New("s3_response")
	ErrChecksum    = errors.New("s3_checksum")
	ErrIncomplete  = errors.New("s3_incomplete")
	ErrCORS        = errors.New("s3_cors")
)

type Config struct {
	Endpoint     string `json:"endpoint"`
	Bucket       string `json:"bucket"`
	Region       string `json:"region"`
	Prefix       string `json:"prefix"`
	AddressStyle string `json:"address_style"`
}

// Credentials are supplied explicitly. No environment, instance-role, shared
// credential file or metadata endpoint participates in credential resolution.
type Credentials struct {
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	SessionToken string `json:"session_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
}

type Grant struct {
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	ExpiresAt int64             `json:"expires_at"`
}

func (Grant) String() string   { return "S3 grant [redacted]" }
func (Grant) GoString() string { return "s3store.Grant{[redacted]}" }

type Part struct {
	Number int32  `json:"part_number"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
	ETag   string `json:"etag"`
}

// S3's opaque ETag and composite checksum are provider observations, never the
// application's complete-file SHA256. VersionID binds versioned reads/deletes.
type Proof struct {
	Size           int64             `json:"size_bytes"`
	ETag           string            `json:"etag"`
	VersionID      string            `json:"version_id,omitempty"`
	ChecksumSHA256 string            `json:"checksum_sha256,omitempty"`
	ChecksumType   string            `json:"checksum_type,omitempty"`
	Metadata       map[string]string `json:"metadata"`
}

type TestReport struct {
	Read      bool   `json:"read"`
	Head      bool   `json:"head"`
	Write     bool   `json:"write"`
	Delete    bool   `json:"delete"`
	Multipart bool   `json:"multipart"`
	Range     bool   `json:"range"`
	CORS      bool   `json:"cors"`
	Cleanup   bool   `json:"cleanup"`
	Code      string `json:"code,omitempty"`
	// Only the internal recovery record receives these identifiers. Admin
	// responses must not serialize grants, credentials or provider diagnostics.
	ProbeKey         string `json:"probe_key,omitempty"`
	UploadID         string `json:"upload_id,omitempty"`
	VersionID        string `json:"version_id,omitempty"`
	ETag             string `json:"etag,omitempty"`
	CleanupUncertain bool   `json:"cleanup_uncertain,omitempty"`
	NoMutation       bool   `json:"no_mutation"`
}

// OperationError deliberately does not retain the SDK error: its text may
// contain a signed URL, credentials, provider response or request headers.
// Uncertain means the caller must reconcile durable intent with exact-key
// observations before deciding whether a mutation happened.
type OperationError struct {
	Code      error
	Uncertain bool
}

func (e *OperationError) Error() string { return e.Code.Error() }
func (e *OperationError) Unwrap() error { return e.Code }

func IsUncertain(err error) bool {
	var operation *OperationError
	return errors.As(err, &operation) && operation.Uncertain
}

// Provider is the exact integration boundary used by durable upload recovery.
// Keys are relative to Config.Prefix and must not contain traversal components.
type Provider interface {
	CreateMultipart(context.Context, string, map[string]string) (string, error)
	PresignPart(context.Context, string, string, int32, int64, string, time.Duration) (Grant, error)
	ListParts(context.Context, string, string) ([]Part, error)
	Complete(context.Context, string, string, []Part) (Proof, error)
	Head(context.Context, string, string) (Proof, error)
	Abort(context.Context, string, string) error
	Delete(context.Context, string, string, string) error
	PresignGet(context.Context, string, string, string, string, time.Duration) (Grant, error)
	Test(context.Context, string) (TestReport, error)
}

// KeyedProber is a planned-key fixture convenience. Production probes must use
// JournaledProber to checkpoint the Create identity before sending payloads.
type KeyedProber interface {
	TestKey(context.Context, string, string) (TestReport, error)
}

// JournaledProber persists the successful Create upload identity before any
// payload or completion request. The synchronous callback must durably commit
// the ID or return an error; a failure stops the probe and attempts cleanup.
type JournaledProber interface {
	TestKeyWithCheckpoint(context.Context, string, string, func(string) error) (TestReport, error)
}

type MultipartUpload struct {
	UploadID    string `json:"upload_id"`
	InitiatedAt int64  `json:"initiated_at"`
}

type UploadListing struct {
	Uploads  []MultipartUpload `json:"uploads"`
	Complete bool              `json:"complete"`
}

// Complete only describes whether this bounded enumeration ended normally.
// Even an empty complete listing is not proof that a timed-out Create did not
// happen: callers retain uncertain durable intent until recovery proves it.
type ExactUploadLister interface {
	ListUploads(context.Context, string) (UploadListing, error)
}

type HeadPresigner interface {
	PresignHead(context.Context, string, string, string, time.Duration) (Grant, error)
}
