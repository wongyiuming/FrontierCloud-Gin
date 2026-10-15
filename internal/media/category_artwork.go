package media

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

type CategoryArtwork struct {
	Category
	Cover          string  `json:"cover,omitempty"`
	MetadataTracks []Track `json:"metadata_tracks,omitempty"`
}

type directoryArtwork struct {
	Cover  string
	Tracks []Track
}

// Artwork is derived from visible, authorized tracks. Folder icons never
// require sidecar files or a second owner for the original media object.
func (s *Service) CategoryArtwork(ctx context.Context, kind string, entries []Category, include bool) []CategoryArtwork {
	result := make([]CategoryArtwork, 0, len(entries))
	for _, entry := range entries {
		row := CategoryArtwork{Category: entry}
		if kind == "music" {
			parsed, err := url.Parse(entry.URL)
			if err == nil {
				artwork := s.categoryArtwork(ctx, parsed.Query().Get("path"), include)
				row.Cover, row.MetadataTracks = artwork.Cover, artwork.Tracks
			}
		}
		result = append(result, row)
	}
	return result
}
func (s *Service) categoryArtwork(ctx context.Context, name string, include bool) directoryArtwork {
	if !categoryShape(name, "music") {
		return directoryArtwork{}
	}
	generation := uint64(0)
	reliable, cacheable := s.repository.(catalogGeneration)
	if cacheable {
		generation = reliable.CatalogGeneration()
	}
	key := name + ":" + strconv.FormatBool(include)
	if cacheable {
		s.tagsMu.Lock()
		if s.coverGeneration != generation {
			s.categoryCovers = nil
			s.coverGeneration = generation
		}
		cached, ok := s.categoryCovers[key]
		s.tagsMu.Unlock()
		if ok {
			return cached
		}
	}
	artwork := directoryArtwork{}
	tracks, err := s.Catalog(ctx, "music", name, "", include)
	if err == nil && len(tracks) > 0 {
		ids := make([]string, len(tracks))
		for i := range tracks {
			ids[i] = tracks[i].MediaID
		}
		metadata, e := s.Encryptions(ctx, ids)
		if e == nil {
			for i := range tracks {
				if metadata[tracks[i].MediaID] != nil {
					if len(artwork.Tracks) < 8 && strings.HasSuffix(strings.ToLower(tracks[i].MediaPath), ".mp3") {
						track := tracks[i]
						track.Encryption = metadata[track.MediaID]
						artwork.Tracks = append(artwork.Tracks, track)
					}
					continue
				}
				s.applyMusicTags(ctx, &tracks[i])
				if strings.HasPrefix(tracks[i].Cover, "/api/v1/media/cover?") {
					artwork.Cover = tracks[i].Cover
					artwork.Tracks = nil
					break
				}
			}
		}
	} else if err == nil && len(strings.Split(name, "/")) == 2 {
		children, e := s.Subcategories(ctx, "music", name, include)
		if e == nil {
			for _, child := range children {
				candidate := s.categoryArtwork(ctx, name+"/"+child.Name, include)
				if candidate.Cover != "" {
					artwork = candidate
					break
				}
				if remaining := 8 - len(artwork.Tracks); remaining > 0 {
					if len(candidate.Tracks) > remaining {
						candidate.Tracks = candidate.Tracks[:remaining]
					}
					artwork.Tracks = append(artwork.Tracks, candidate.Tracks...)
				}
			}
		}
	}
	if cacheable {
		s.tagsMu.Lock()
		if s.coverGeneration == generation {
			if len(s.categoryCovers) >= 256 {
				s.categoryCovers = nil
			}
			if s.categoryCovers == nil {
				s.categoryCovers = map[string]directoryArtwork{}
			}
			s.categoryCovers[key] = artwork
		}
		s.tagsMu.Unlock()
	}
	return artwork
}
