package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const (
	nativeLyricAutoEntries = 4096
	nativeLyricAutoTimeout = 8 * time.Second
)

// ErrNativeLyricAutoScopeLimit means the operator must narrow either scope.
// No association from the request was committed.
var ErrNativeLyricAutoScopeLimit = errors.New("same-name lyric association scope exceeds the operation limit")

// ApplyNativeLyricAuto examines both complete selected scopes in the same
// fenced transaction as the updates. The caller must hold its ingress and
// Owner fences and authenticate the administrator's explicit request.
func (s *SQLStore) ApplyNativeLyricAuto(ctx context.Context, trackScope, lyricScope string, audit store.AdminAudit) (store.AutoLyricResult, error) {
	var result store.AutoLyricResult
	if ctx == nil {
		return result, ErrInvalid
	}
	if trackScope == "" {
		trackScope = "music"
	}
	if lyricScope == "" {
		lyricScope = "lyrics"
	}
	if !validLyricAutoScope(trackScope, "music") || !validLyricAutoScope(lyricScope, "lyrics") {
		return result, ErrInvalid
	}
	requestCtx, cancel := context.WithTimeout(ctx, nativeLyricAutoTimeout)
	defer cancel()
	err := s.withNativeLyricWrite(requestCtx, func(tx treeQuery, operation string) error {
		budget := nativeLyricAutoEntries
		lyrics, err := s.readLyricAutoScope(requestCtx, tx, lyricScope, "lyrics", &budget)
		if err != nil {
			return err
		}
		tracks, err := s.readLyricAutoScope(requestCtx, tx, trackScope, "music", &budget)
		if err != nil {
			return err
		}
		changes, counts, err := planLyricAuto(tracks, lyrics)
		if err != nil {
			return err
		}
		cache, err := s.newLyricTxCache(requestCtx, tx)
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
		applied, err := cache.applyChanges(operation, now, changes, func(_ NativeLyricChange, facts Facts) error {
			if facts.Lyric != nil || facts.LyricResolution != nil && facts.LyricResolution.State == "explicit" {
				return ErrConflict
			}
			if facts.LyricResolution == nil || facts.LyricResolution.Origin != "native" && facts.LyricResolution.Origin != "local" {
				return ErrInvalid
			}
			return nil
		})
		if err != nil {
			return err
		}
		counts.Linked = len(applied)
		targets := []string{lyricScope}
		for _, item := range applied {
			targets = append(targets, item.Track)
		}
		audit = nativeLyricAudit(audit, "lyric_auto_relate", len(targets)+1)
		if err = s.appendEncryptedLyricAudit(requestCtx, tx, operation, lyricAuditPayload{Origin: trackScope, Targets: targets, Changes: applied, Relations: counts.Linked, At: now, Audit: audit}); err != nil {
			return err
		}
		result = counts
		return nil
	})
	if err != nil {
		if ctx.Err() == nil && errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
			err = ErrNativeLyricAutoScopeLimit
		}
		return store.AutoLyricResult{}, err
	}
	return result, nil
}

type lyricAutoEntry struct {
	path, id string
	revision int64
	explicit bool
}

func validLyricAutoScope(scope, root string) bool {
	parts := strings.Split(scope, "/")
	if len(parts) > 3 || parts[0] != root {
		return false
	}
	for _, part := range parts {
		if !validComponent(part) || strings.HasPrefix(part, ".") || strings.Contains(part, ":") {
			return false
		}
	}
	return true
}

func (s *SQLStore) readLyricAutoScope(ctx context.Context, tx treeQuery, scope, root string, budget *int) ([]lyricAutoEntry, error) {
	result := []lyricAutoEntry{}
	err := s.walkLyricScopeTx(ctx, tx, scope, root, budget, func(full string, item CatalogItem) error {
		explicit := item.Facts.Lyric != nil || item.Facts.LyricResolution != nil && item.Facts.LyricResolution.State == "explicit"
		result = append(result, lyricAutoEntry{path: full, id: item.Entry.ObjectID, revision: item.FactsRevision, explicit: explicit})
		return nil
	})
	if errors.Is(err, ErrLyricScopeLimit) {
		err = ErrNativeLyricAutoScopeLimit
	}
	return result, err
}

func (s *SQLStore) walkLyricScopeTx(ctx context.Context, tx treeQuery, scope, root string, budget *int, visit func(string, CatalogItem) error) error {
	start, _, err := s.pathEntryTx(ctx, tx, scope)
	if errors.Is(err, sql.ErrNoRows) && scope == root {
		return nil
	}
	if err != nil {
		return err
	}
	if start.Kind != "directory" {
		return ErrInvalid
	}
	var walk func(Entry, string, int) error
	walk = func(dir Entry, name string, depth int) error {
		state, err := s.catalogScope(ctx, tx, dir.ObjectID, true)
		if err != nil {
			return err
		}
		// Reject large groups before listCatalogPageTx verifies their SQL row
		// counts. Every count used here is authenticated by the tree key.
		left := *budget
		for _, count := range state.counts {
			if count > int64(left) {
				return ErrLyricScopeLimit
			}
			left -= int(count)
		}
		*budget = left
		cursor := ""
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			items, next, err := s.listCatalogPageTx(ctx, tx, dir.ObjectID, cursor, 128, true)
			if err != nil {
				return err
			}
			for _, item := range items {
				entry := item.Entry
				if strings.HasPrefix(entry.Name, ".") || strings.Contains(entry.Name, ":") {
					continue
				}
				full := name + "/" + entry.Name
				if entry.Kind == "directory" && depth < 3 {
					if err := walk(entry, full, depth+1); err != nil {
						return err
					}
					continue
				}
				if !eligibleLyricAutoEntry(root, full, entry.Kind, depth) {
					continue
				}
				if err := visit(full, item); err != nil {
					return err
				}
			}
			if next == "" {
				return nil
			}
			if next == cursor {
				return ErrInvalid
			}
			cursor = next
		}
	}
	return walk(start, scope, strings.Count(scope, "/")+1)
}

func eligibleLyricAutoEntry(root, name, kind string, depth int) bool {
	ext := strings.ToLower(path.Ext(name))
	if root == "lyrics" {
		return kind == "lyric" && ext == ".lrc" && name != "lyrics/default.lrc"
	}
	return kind == "audio" && depth >= 2 && (ext == ".mp3" || ext == ".m4a" || ext == ".flac" || ext == ".wav")
}

func planLyricAuto(tracks, lyrics []lyricAutoEntry) ([]NativeLyricChange, store.AutoLyricResult, error) {
	var result store.AutoLyricResult
	byRelative := make(map[string][]lyricAutoEntry, len(lyrics))
	byStem := make(map[string][]lyricAutoEntry, len(lyrics))
	for _, lyric := range lyrics {
		relative := strings.TrimSuffix(strings.TrimPrefix(lyric.path, "lyrics/"), path.Ext(lyric.path))
		byRelative[relative] = append(byRelative[relative], lyric)
		stem := path.Base(relative)
		byStem[stem] = append(byStem[stem], lyric)
	}
	changes := make([]NativeLyricChange, 0, min(len(tracks), MaxNativeLyricPatchTracks))
	for _, track := range tracks {
		if track.explicit {
			result.Preserved++
			continue
		}
		relative := strings.TrimSuffix(strings.TrimPrefix(track.path, "music/"), path.Ext(track.path))
		candidates := byRelative[relative]
		if len(candidates) == 0 {
			candidates = byStem[path.Base(relative)]
		}
		switch len(candidates) {
		case 0:
			result.Unmatched++
		case 1:
			if len(changes) == MaxNativeLyricPatchTracks {
				return nil, store.AutoLyricResult{}, ErrNativeLyricAutoScopeLimit
			}
			changes = append(changes, NativeLyricChange{TrackID: track.id, ExpectedFactsRevision: track.revision, LyricID: candidates[0].id})
		default:
			result.Ambiguous++
		}
	}
	return changes, result, nil
}
