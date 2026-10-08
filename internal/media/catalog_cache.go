package media

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"
)

const catalogMaxEntries = 64
const catalogMaxBytes = 8 << 20
const catalogMaxEntryBytes = 1 << 20

type catalogGeneration interface{ CatalogGeneration() uint64 }
type catalogEntry struct {
	categories []Category
	tracks     []Track
	generation uint64
	expires    time.Time
	bytes      int
}
type catalogCache struct {
	mu       sync.Mutex
	entries  map[string]catalogEntry
	building chan struct{}
	ttl      time.Duration
	bytes    int
}

// ConfigureCatalogCache is startup-only. Zero disables caching. Unknown stores
// bypass caching: a TTL cannot replace a reliable invalidation contract.
func (s *Service) ConfigureCatalogCache(ttl time.Duration) {
	if ttl <= 0 {
		s.catalog = nil
		return
	}
	s.catalog = &catalogCache{entries: map[string]catalogEntry{}, ttl: ttl}
}
func (s *Service) invalidateCatalog() {
	if c := s.catalog; c != nil {
		c.mu.Lock()
		c.entries, c.bytes = map[string]catalogEntry{}, 0
		c.mu.Unlock()
	}
}
func cloneTracks(items []Track) []Track {
	result := append([]Track{}, items...)
	for i := range result {
		if result[i].HasLyrics != nil {
			value := *result[i].HasLyrics
			result[i].HasLyrics = &value
		}
	}
	return result
}
func cloneCatalog(e catalogEntry) catalogEntry {
	e.categories = append([]Category{}, e.categories...)
	e.tracks = cloneTracks(e.tracks)
	return e
}
func catalogSize(e catalogEntry) int {
	n := 256
	for _, v := range e.categories {
		n += 128 + len(v.Name) + len(v.URL)
	}
	for _, v := range e.tracks {
		n += 512 + len(v.MediaPath) + len(v.Title) + len(v.Artist) + len(v.Type) + len(v.URL) + len(v.Cover) + len(v.MediaID) + len(v.ResourceID) + len(v.KaraokeID)
	}
	return n
}
func (s *Service) cachedCatalog(ctx context.Context, key string, build func() (catalogEntry, error)) (catalogEntry, error) {
	c := s.catalog
	g, reliable := s.repository.(catalogGeneration)
	if c == nil || !reliable {
		return build()
	}
	for {
		if err := ctx.Err(); err != nil {
			return catalogEntry{}, err
		}
		generation := g.CatalogGeneration()
		c.mu.Lock()
		if entry, ok := c.entries[key]; ok && entry.generation == generation && time.Now().Before(entry.expires) {
			result := cloneCatalog(entry)
			c.mu.Unlock()
			return result, nil
		}
		if wait := c.building; wait != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return catalogEntry{}, ctx.Err()
			case <-wait:
				continue
			}
		}
		c.building = make(chan struct{})
		c.mu.Unlock()
		entry, err := func() (catalogEntry, error) {
			completed := false
			defer func() {
				if !completed {
					c.mu.Lock()
					close(c.building)
					c.building = nil
					c.mu.Unlock()
				}
			}()
			entry, err := build()
			completed = true
			return entry, err
		}()
		entry.bytes = catalogSize(entry) + len(key)
		c.mu.Lock()
		// A writer racing the fill makes it uncacheable, including the first
		// scan that registers object IDs. The following stable read may fill.
		if err == nil && g.CatalogGeneration() == generation && entry.bytes <= catalogMaxEntryBytes {
			for k, v := range c.entries {
				if v.generation != generation || !time.Now().Before(v.expires) {
					delete(c.entries, k)
					c.bytes -= v.bytes
				}
			}
			if previous, ok := c.entries[key]; ok {
				delete(c.entries, key)
				c.bytes -= previous.bytes
			}
			for len(c.entries) >= catalogMaxEntries || c.bytes+entry.bytes > catalogMaxBytes {
				for k, v := range c.entries {
					delete(c.entries, k)
					c.bytes -= v.bytes
					break
				}
			}
			entry.generation, entry.expires = generation, time.Now().Add(c.ttl)
			c.entries[key] = cloneCatalog(entry)
			c.bytes += entry.bytes
		}
		close(c.building)
		c.building = nil
		c.mu.Unlock()
		return entry, err
	}
}
func (s *Service) cachedCategories(ctx context.Context, role, kind, parent string, include bool, build func() ([]Category, error)) ([]Category, error) {
	entry, err := s.cachedCatalog(ctx, "categories:"+role+":"+kind+":"+strconv.FormatBool(include)+":"+parent, func() (catalogEntry, error) {
		items, err := build()
		return catalogEntry{categories: items}, err
	})
	return entry.categories, err
}
func (s *Service) cachedTracks(ctx context.Context, role, kind, name, session string, include bool, build func() ([]Track, error)) ([]Track, error) {
	entry, err := s.cachedCatalog(ctx, "tracks:"+role+":"+kind+":"+strconv.FormatBool(include)+":"+name, func() (catalogEntry, error) {
		items, err := build()
		return catalogEntry{tracks: items}, err
	})
	if err == nil {
		sort.SliceStable(entry.tracks, func(i, j int) bool {
			if entry.tracks[i].Preference != entry.tracks[j].Preference {
				return entry.tracks[i].Preference > entry.tracks[j].Preference
			}
			return randomKey(session, entry.tracks[i].MediaID) < randomKey(session, entry.tracks[j].MediaID)
		})
	}
	return entry.tracks, err
}
