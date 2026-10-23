package media

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type CategoryArtwork struct {
	Category
	Cover          string  `json:"cover,omitempty"`
	MetadataTracks []Track `json:"metadata_tracks,omitempty"`
	ArtworkURL     string  `json:"artwork_url,omitempty"`
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
				values := url.Values{"path": {parsed.Query().Get("path")}}
				if include {
					values.Set("include_hidden", "true")
				}
				row.ArtworkURL = "/api/v1/media/catalog/artwork?" + values.Encode()
			}
		}
		result = append(result, row)
	}
	return result
}

func (s *Service) DirectoryArtwork(ctx context.Context, name string, include bool) (CategoryArtwork, error) {
	// Include category authorization/existence in the same lookup deadline;
	// candidate traversal must not receive a fresh budget after a slow query.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.CategoryExists(ctx, name, "music"); err != nil {
		return CategoryArtwork{}, err
	}
	artwork, err := s.categoryArtwork(ctx, name, include)
	if err != nil {
		return CategoryArtwork{}, err
	}
	return CategoryArtwork{Cover: artwork.Cover, MetadataTracks: artwork.Tracks}, nil
}
func (s *Service) categoryArtwork(ctx context.Context, name string, include bool) (directoryArtwork, error) {
	if !categoryShape(name, "music") {
		return directoryArtwork{}, ErrCategory
	}
	if err := ctx.Err(); err != nil {
		return directoryArtwork{}, err
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
			return cached, nil
		}
	}
	// One request-wide candidate/directory budget. This endpoint only returns
	// cheap candidates: selected/visible browser work loads tags later, never a
	// serial directory-wide media read on the catalog request path.
	artwork := directoryArtwork{}
	remaining := 8
	collect := func(directory string) (bool, error) {
		tracks, err := s.Catalog(ctx, "music", directory, "", include)
		if err != nil {
			return false, err
		}
		candidates := make([]Track, 0, min(len(tracks), remaining))
		for _, track := range tracks {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if len(candidates) == remaining {
				break
			}
			if strings.HasSuffix(strings.ToLower(track.MediaPath), ".mp3") {
				candidates = append(candidates, track)
			}
		}
		count := len(candidates)
		remaining -= count
		tracks = candidates
		ids := make([]string, len(tracks))
		for i := range tracks {
			ids[i] = tracks[i].MediaID
		}
		metadata, err := s.Encryptions(ctx, ids)
		if err != nil {
			return false, err
		}
		for i := range tracks {
			tracks[i].Encryption = metadata[tracks[i].MediaID]
			s.DecorateMusicTracks(ctx, tracks[i:i+1])
			artwork.Tracks = append(artwork.Tracks, tracks[i])
		}
		return count != 0, nil
	}
	found, err := collect(name)
	if err == nil && !found && len(strings.Split(name, "/")) == 2 {
		children, e := s.Subcategories(ctx, "music", name, include)
		err = e
		if e == nil {
			for _, child := range children[:min(len(children), 7)] {
				if remaining == 0 || ctx.Err() != nil {
					break
				}
				if _, err = collect(name + "/" + child.Name); err != nil {
					break
				}
			}
		}
	}
	if err != nil {
		return directoryArtwork{}, err
	}
	if err := ctx.Err(); err != nil {
		return directoryArtwork{}, err
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
	return artwork, nil
}
