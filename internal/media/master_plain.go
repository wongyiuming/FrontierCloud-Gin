package media

import (
	"context"
	"os"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// MasterPlainIdentity is only a source-planning check; the actual reader
// repeats authorization and revision checks for every bounded read.
func (s *Service) MasterPlainIdentity(ctx context.Context, expected store.MediaObject, objectID string) (int64, string, string, error) {
	if _, ok := network.AuthenticatedIngressFromContext(ctx); !ok || !network.HasActivePublicAdmission(ctx) || expected.Encryption != nil || expected.ID == "" || objectID == "" || s.pool == nil {
		return 0, "", "", ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return 0, "", "", err
	}
	defer release()
	object, err := s.cryptoObject(ctx, expected.Path, expected.ID, false)
	if err != nil {
		return 0, "", "", err
	}
	if object.ID != expected.ID || object.Path != expected.Path || object.Kind != expected.Kind || !reflect.DeepEqual(object.Encryption, expected.Encryption) {
		return 0, "", "", store.ErrNodeState
	}
	row, stream, err := s.masterDirectOpen(ctx, expected.ID, objectID)
	if err != nil {
		return 0, "", "", err
	}
	defer stream.File.Close()
	if stream.Encryption != nil || row.Bytes <= 0 {
		return 0, "", "", ErrUnavailable
	}
	descriptor, err := protocol.IngressMediaDescriptor(stream.Info.Size(), nil)
	if err != nil {
		return 0, "", "", err
	}
	return stream.Info.Size(), masterDirectRevision(row, stream), descriptor, nil
}

// PlainLyricMetadata returns only an existing visible relationship and object
// descriptor. It never reads or returns the lyric body through business proxy.
func (s *Service) PlainLyricMetadata(ctx context.Context, name, resourceID string) (store.MediaObject, int64, error) {
	if _, ok := network.AuthenticatedIngressFromContext(ctx); !ok || !network.HasActivePublicAdmission(ctx) {
		return store.MediaObject{}, 0, ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return store.MediaObject{}, 0, err
	}
	defer release()
	ctx = context.WithValue(ctx, verifiedLyricReadKey{}, true)
	track, err := s.cryptoObject(ctx, name, resourceID, false)
	if err != nil || track.Kind != "audio" {
		return store.MediaObject{}, 0, ErrLyrics
	}
	lyric, err := s.repository.LyricPath(ctx, track.ID)
	if err != nil {
		return store.MediaObject{}, 0, err
	}
	if lyric == "" || !s.validLyric(lyric) {
		return store.MediaObject{}, 0, ErrLyrics
	}
	object, err := s.cryptoObject(ctx, lyric, "", false)
	if err != nil {
		return store.MediaObject{}, 0, err
	}
	if object.Kind != "lyric" || object.Encryption != nil {
		return store.MediaObject{}, 0, ErrUnavailable
	}
	info, err := s.safeInfo(object.Path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxLyricBytes {
		return store.MediaObject{}, 0, os.ErrNotExist
	}
	return object, info.Size(), nil
}

func (s *Service) MasterPlainLyricIdentity(ctx context.Context, expected store.MediaObject) (int64, string, string, error) {
	if _, ok := network.AuthenticatedIngressFromContext(ctx); !ok || !network.HasActivePublicAdmission(ctx) || expected.Kind != "lyric" || expected.Encryption != nil || expected.ID == "" {
		return 0, "", "", ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return 0, "", "", err
	}
	defer release()
	ctx = context.WithValue(ctx, verifiedLyricReadKey{}, true)
	stream, revision, err := s.masterLyricOpen(ctx, expected.ID)
	if err != nil {
		return 0, "", "", err
	}
	defer stream.File.Close()
	if stream.Path != expected.Path || stream.Encryption != nil || stream.Info.Size() < 1 || stream.Info.Size() > maxLyricBytes {
		return 0, "", "", ErrUnavailable
	}
	descriptor, err := protocol.IngressMediaDescriptor(stream.Info.Size(), nil)
	if err != nil {
		return 0, "", "", err
	}
	return stream.Info.Size(), revision, descriptor, nil
}
