// Package s3media coordinates durable Master intent with bounded S3 control
// requests. Ordinary media bytes travel between the browser and the provider.
package s3media

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

var ErrUnavailable = errors.New("s3_unavailable")
var ErrProof = errors.New("s3_identity_proof")
var ErrPending = errors.New("s3_cleanup_pending")

// Existing global catalogs bound ETags to 128 bytes. Recovery accepts the
// provider's wider bound so an unsupported response can still be cleaned.
const publishedETagBytes = 128

type Factory func(s3store.Config, s3store.Credentials) (s3store.Provider, func(), error)

type Service struct {
	repository store.S3Repository
	nodes      store.NodeRepository
	vault      *vault.Vault
	factory    Factory
	// Fixed stripes bound memory while serializing same-intent network work.
	// SQL revision checks and durable journals remain the authority after restart.
	stripes   [64]chan struct{}
	mutations atomic.Uint64
	sweeps    atomic.Uint64
}

func (s *Service) Generation() uint64 { return s.mutations.Load() }

func New(repository store.S3Repository, nodes store.NodeRepository, private *vault.Vault) *Service {
	return newService(repository, nodes, private, func(config s3store.Config, credentials s3store.Credentials) (s3store.Provider, func(), error) {
		client, err := s3store.New(config, credentials)
		if err != nil {
			return nil, nil, err
		}
		return client, client.Close, nil
	})
}

func newService(repository store.S3Repository, nodes store.NodeRepository, private *vault.Vault, factory Factory) *Service {
	s := &Service{repository: repository, nodes: nodes, vault: private, factory: factory}
	for i := range s.stripes {
		s.stripes[i] = make(chan struct{}, 1)
	}
	return s
}

func (s *Service) master(ctx context.Context) error {
	if s == nil || s.repository == nil || s.nodes == nil || s.vault == nil || s.factory == nil {
		return ErrUnavailable
	}
	node, err := s.nodes.ReadIdentity(ctx)
	if err != nil {
		return err
	}
	if node.Role != "Master" {
		return store.ErrNodeState
	}
	return nil
}

func (s *Service) lease(ctx context.Context, key string) (func(), error) {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(key))
	stripe := s.stripes[hash.Sum32()%uint32(len(s.stripes))]
	select {
	case stripe <- struct{}{}:
		return func() { <-stripe }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func config(location store.S3Location) s3store.Config {
	return s3store.Config{Endpoint: location.Endpoint, Bucket: location.Bucket, Region: location.Region, Prefix: location.Prefix, AddressStyle: location.Style}
}

func (s *Service) provider(member store.S3Member) (s3store.Provider, func(), error) {
	if member.SealedCredentials == "" || len(member.SealedCredentials) > 32768 {
		return nil, nil, s3store.ErrCredentials
	}
	plaintext, err := s.vault.Unseal(member.SealedCredentials)
	if err != nil || len(plaintext) > 16384 {
		return nil, nil, s3store.ErrCredentials
	}
	decoder := json.NewDecoder(strings.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	var credentials s3store.Credentials
	if decoder.Decode(&credentials) != nil || credentials.ExpiresAt != member.CredentialExpiresAt {
		return nil, nil, s3store.ErrCredentials
	}
	if err = credentials.Validate(time.Now()); err != nil {
		return nil, nil, s3store.ErrCredentials
	}
	return s.factory(config(member.Location), credentials)
}

type Configuration struct {
	Name        string               `json:"name"`
	Location    store.S3Location     `json:"location"`
	Quota       int64                `json:"allocated_bytes"`
	Enabled     bool                 `json:"enabled"`
	Credentials *s3store.Credentials `json:"credentials,omitempty"`
}

func (s *Service) configuration(input Configuration) (store.S3MemberConfiguration, error) {
	normalized, err := s3store.Normalize(config(input.Location))
	if err != nil {
		return store.S3MemberConfiguration{}, err
	}
	result := store.S3MemberConfiguration{Name: input.Name, Quota: input.Quota, Enabled: input.Enabled,
		Location: store.S3Location{Endpoint: normalized.Endpoint, Bucket: normalized.Bucket, Region: normalized.Region, Prefix: normalized.Prefix, Style: normalized.AddressStyle}}
	if input.Credentials != nil {
		if err := input.Credentials.Validate(time.Now()); err != nil {
			return result, err
		}
		encoded, err := json.Marshal(input.Credentials)
		if err != nil {
			return result, s3store.ErrCredentials
		}
		sealed, err := s.vault.Seal(string(encoded))
		if err != nil {
			return result, s3store.ErrCredentials
		}
		result.SealedCredentials, result.CredentialExpiresAt = &sealed, input.Credentials.ExpiresAt
	}
	return result, nil
}

func (s *Service) Members(ctx context.Context) ([]store.S3Member, error) {
	if err := s.master(ctx); err != nil {
		return nil, err
	}
	return s.repository.S3Members(ctx)
}

func (s *Service) Add(ctx context.Context, input Configuration, audit store.NodeAudit) (store.S3Member, error) {
	if err := s.master(ctx); err != nil {
		return store.S3Member{}, err
	}
	value, err := s.configuration(input)
	if err != nil {
		return store.S3Member{}, err
	}
	if value.SealedCredentials == nil || value.Enabled {
		return store.S3Member{}, s3store.ErrConfig
	}
	return s.repository.S3AddMember(ctx, value, audit)
}

func (s *Service) Configure(ctx context.Context, id string, revision int64, input Configuration, audit store.NodeAudit) (store.S3Member, error) {
	if err := s.master(ctx); err != nil {
		return store.S3Member{}, err
	}
	value, err := s.configuration(input)
	if err != nil {
		return store.S3Member{}, err
	}
	return s.repository.S3ConfigureMember(ctx, id, revision, value, audit)
}

func (s *Service) Remove(ctx context.Context, id string, revision int64, audit store.NodeAudit) error {
	if err := s.master(ctx); err != nil {
		return err
	}
	return s.repository.S3RemoveMember(ctx, id, revision, audit)
}

// Only closed error codes cross Admin/audit boundaries; raw provider errors,
// signed URLs and headers never become diagnostic strings.
func ErrorCode(err error) string {
	for _, code := range []error{s3store.ErrConfig, s3store.ErrCredentials, s3store.ErrEndpoint, s3store.ErrNetwork, s3store.ErrNotFound, s3store.ErrDenied, s3store.ErrConflict, s3store.ErrResponse, s3store.ErrChecksum, s3store.ErrIncomplete, s3store.ErrCORS, ErrProof, ErrPending, ErrUnavailable} {
		if errors.Is(err, code) {
			return code.Error()
		}
	}
	if err != nil {
		return "s3_control_failed"
	}
	return ""
}

// Finish only an already recorded intent after request cancellation. A process
// crash still leaves the pre-network durable state for subsequent recovery.
func finishContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
}

func (s *Service) Probe(ctx context.Context, id string, revision int64, origin string, audit store.NodeAudit) (store.S3Member, error) {
	if err := s.master(ctx); err != nil {
		return store.S3Member{}, err
	}
	release, err := s.lease(ctx, "member:"+id)
	if err != nil {
		return store.S3Member{}, err
	}
	defer release()
	member, err := s.repository.S3Member(ctx, id)
	if err != nil {
		return member, err
	}
	if member.Revision != revision {
		return member, store.ErrNodeState
	}
	provider, closeProvider, err := s.provider(member)
	if err != nil {
		return member, err
	}
	defer closeProvider()
	prober, ok := provider.(s3store.JournaledProber)
	if !ok {
		return member, ErrUnavailable
	}
	intent, err := s.repository.S3StartProbe(ctx, id, revision, audit)
	if err != nil {
		return member, err
	}
	var checkpointID string
	report, operationErr := prober.TestKeyWithCheckpoint(ctx, origin, intent.Key, func(providerID string) error {
		if providerID == "" || len(providerID) > 2048 || checkpointID != "" && checkpointID != providerID {
			return ErrProof
		}
		finish, cancel := finishContext(ctx)
		defer cancel()
		if err := s.repository.S3CheckpointProbe(finish, intent.ID, intent.Revision, providerID); err != nil {
			return err
		}
		checkpointID = providerID
		return nil
	})
	if operationErr == nil && (checkpointID == "" || report.UploadID != checkpointID || len(report.ETag) > publishedETagBytes) {
		operationErr = ErrProof
	}
	result := store.S3ProbeResult{Key: intent.Key, ProviderUploadID: report.UploadID, VersionID: report.VersionID, ETag: report.ETag,
		ChecksPassed:   operationErr == nil && report.Read && report.Head && report.Write && report.Delete && report.Multipart && report.Range && report.CORS,
		CleanupSettled: report.ProbeKey == intent.Key && (report.NoMutation || report.Cleanup && !report.CleanupUncertain), NoMutation: report.NoMutation && report.ProbeKey == intent.Key, ErrorCode: ErrorCode(operationErr)}
	if report.ProbeKey != intent.Key {
		result.ChecksPassed, result.CleanupSettled, result.ErrorCode = false, false, ErrProof.Error()
	}
	finish, cancel := finishContext(ctx)
	defer cancel()
	member, err = s.repository.S3FinishProbe(finish, intent.ID, intent.Revision, result, audit)
	if err != nil {
		return member, err
	}
	if operationErr != nil {
		return member, operationErr
	}
	if !result.ChecksPassed || !result.CleanupSettled {
		return member, ErrPending
	}
	return member, nil
}
