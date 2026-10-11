package media

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path"
	"strings"
)

type KaraokeMedia struct {
	Kind, ID, Path, Type string
	HasLyrics            bool
}

func (s *Service) ResolveKaraoke(ctx context.Context, token string) (KaraokeMedia, error) {
	if s.identity == nil {
		return KaraokeMedia{}, os.ErrNotExist
	}
	kind, id, e := s.identity.ResolveKaraoke(token)
	if e != nil {
		return KaraokeMedia{}, os.ErrNotExist
	}
	role, e := s.role(ctx)
	if e != nil {
		return KaraokeMedia{}, e
	}
	if role == "Follower" || kind == "global" && role != "Master" {
		return KaraokeMedia{}, os.ErrNotExist
	}
	release, e := s.acquire(ctx, false)
	if e != nil {
		return KaraokeMedia{}, e
	}
	defer release()
	if e = s.ready(); e != nil {
		return KaraokeMedia{}, e
	}
	var name, typ string
	if kind == "global" {
		row, _, e := s.resolveGlobal(ctx, id, "")
		if e != nil {
			return KaraokeMedia{}, e
		}
		name, typ = row.Path, row.Kind
	} else {
		row, e := s.repository.ObjectByID(ctx, id)
		if e != nil {
			return KaraokeMedia{}, e
		}
		if row == nil {
			return KaraokeMedia{}, os.ErrNotExist
		}
		object, e := s.ValidateTrack(row.Path)
		if e != nil || object.Kind != row.Kind {
			return KaraokeMedia{}, os.ErrNotExist
		}
		name, typ = row.Path, row.Kind
	}
	if typ != "audio" && typ != "video" {
		return KaraokeMedia{}, os.ErrNotExist
	}
	result := KaraokeMedia{Kind: kind, ID: id, Path: name, Type: typ}
	if typ == "audio" {
		linked, e := s.repository.LyricPath(ctx, id)
		if e != nil {
			return KaraokeMedia{}, e
		}
		if !s.validLyric(linked) {
			if kind == "global" {
				if e = s.ensureDefaultLyric(); e == nil {
					e = s.pool.BindGlobalLyric(ctx, id, store.MediaObject{Kind: "lyric", Path: defaultLyric})
				}
				linked = defaultLyric
			} else {
				linked, e = s.lyricFor(ctx, store.MediaObject{ID: id, Path: name, Kind: typ})
			}
			if e != nil {
				return KaraokeMedia{}, e
			}
		}
		// Default lyrics are part of the original Karaoke contract. Resolving
		// the relation is sufficient; ciphertext is parsed only by browsers.
		result.HasLyrics = s.validLyric(linked)
	}
	return result, nil
}
func (s *Service) KaraokeLyrics(ctx context.Context, v KaraokeMedia) ([]LyricEntry, error) {
	if v.Kind == "global" {
		return s.LyricsResource(ctx, "", v.ID)
	}
	return s.Lyrics(ctx, v.Path)
}
func (s *Service) KaraokeMetadata(ctx context.Context, token string) (store.RecordingMetadata, error) {
	v, e := s.ResolveKaraoke(ctx, token)
	if e != nil {
		return store.RecordingMetadata{}, e
	}
	metadata := store.RecordingMetadata{Title: strings.TrimSuffix(path.Base(v.Path), path.Ext(v.Path)), Lyrics: []store.RecordingLyric{}}
	if v.HasLyrics {
		entries, e := s.KaraokeLyrics(ctx, v)
		if errors.Is(e, ErrEncryptedLyric) {
			linked, err := s.repository.LyricPath(ctx, v.ID)
			if err != nil {
				return metadata, err
			}
			metadata.EncryptedLyricPath = linked
			return metadata, nil
		}
		if e != nil {
			return metadata, e
		}
		for _, line := range entries {
			metadata.Lyrics = append(metadata.Lyrics, store.RecordingLyric{Time: line.Time, Text: line.Text})
		}
	}
	return metadata, nil
}
