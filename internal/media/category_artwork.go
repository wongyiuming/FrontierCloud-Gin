package media

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

type CategoryArtwork struct {
	Category
	Cover string `json:"cover,omitempty"`
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
				row.Cover = s.categoryArtwork(ctx, parsed.Query().Get("path"), include)
			}
		}
		result = append(result, row)
	}
	return result
}
func (s *Service) categoryArtwork(ctx context.Context, name string, include bool) string {
	if !categoryShape(name, "music") {
		return ""
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
	cover := ""
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
					continue
				}
				s.applyMusicTags(ctx, &tracks[i])
				if strings.HasPrefix(tracks[i].Cover, "/api/v1/media/cover?") {
					cover = tracks[i].Cover
					break
				}
			}
		}
	} else if err == nil && len(strings.Split(name, "/")) == 2 {
		children, e := s.Subcategories(ctx, "music", name, include)
		if e == nil {
			for _, child := range children {
				cover = s.categoryArtwork(ctx, name+"/"+child.Name, include)
				if cover != "" {
					break
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
				s.categoryCovers = map[string]string{}
			}
			s.categoryCovers[key] = cover
		}
		s.tagsMu.Unlock()
	}
	return cover
}
