package s3media

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// WithSelectedProvider opens the existing Master-held credential adapter for
// a selected S3 operation. expected must come from the trusted coordinator's
// fenced durable intent; this method is not an HTTP authorization mechanism.
// Network I/O in fn must occur outside database transactions. The coordinator
// rechecks its intent and member binding before accepting the result.
func (s *Service) WithSelectedProvider(ctx context.Context, expected store.S3Member, fn func(context.Context, s3store.Provider) error) error {
	if ctx == nil || ctx.Err() != nil || fn == nil {
		return ErrUnavailable
	}
	if err := s.master(ctx); err != nil {
		return err
	}
	current, err := s.repository.S3Member(ctx, expected.ID)
	if err != nil || current.ID != expected.ID || current.Kind != "S3" || current.Transport != "S3" || current.RelationshipID != nil || current.Enabled == 0 || current.Writable == 0 || current.Health != "online" || current.Draining || current.CleanupOnly || current.Revision != expected.Revision || current.CredentialRevision != expected.CredentialRevision || current.SealedCredentials != expected.SealedCredentials || current.CredentialExpiresAt != expected.CredentialExpiresAt || current.Location != expected.Location || current.ProbeState != "ready" || current.ProbeRevision != current.Revision || current.CredentialExpiresAt != 0 && current.CredentialExpiresAt <= time.Now().Unix() {
		return ErrUnavailable
	}
	provider, closeProvider, err := s.provider(current)
	if err != nil {
		return err
	}
	defer closeProvider()
	return fn(ctx, provider)
}
