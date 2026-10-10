package media

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (s *Service) Encryption(ctx context.Context, mediaID string) (*mediacrypto.Metadata, error) {
	repository, ok := s.repository.(store.EncryptionRepository)
	if !ok {
		return nil, mediacrypto.ErrMetadata
	}
	return repository.Encryption(ctx, mediaID)
}

func (s *Service) HasEncryption(ctx context.Context) (bool, error) {
	repository, ok := s.repository.(store.EncryptionRepository)
	if !ok {
		return false, nil
	}
	return repository.HasEncryption(ctx)
}

func (s *Service) EncryptionKeyID(ctx context.Context) (string, error) {
	repository, ok := s.repository.(store.EncryptionRepository)
	if !ok {
		return "", mediacrypto.ErrPremaster
	}
	return repository.EncryptionKeyID(ctx)
}

func (s *Service) CheckEncryptionKey(ctx context.Context, keyID string) error {
	repository, ok := s.repository.(store.EncryptionRepository)
	if !ok {
		return mediacrypto.ErrPremaster
	}
	return repository.CheckEncryptionKey(ctx, keyID)
}

func (s *Service) lyricEncryption(ctx context.Context, name string) (bool, error) {
	// Older fake repositories only model plaintext. Real runtimes always supply
	// encryption support and cannot silently bypass a corrupt descriptor.
	if _, ok := s.repository.(store.EncryptionRepository); !ok {
		return false, nil
	}
	ids, err := s.repository.EnsureObjects(ctx, []store.MediaObject{{Path: name, Kind: "lyric"}})
	if err != nil {
		return false, err
	}
	meta, err := s.Encryption(ctx, ids[name])
	return meta != nil, err
}
