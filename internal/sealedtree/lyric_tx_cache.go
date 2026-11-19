package sealedtree

import (
	"context"
	"strings"
	"unicode/utf8"
)

type lyricCachedEntry struct {
	index string
	entry Entry
}

// lyricTxCache exists only within one exclusive-fenced SQL transaction.
// This operation can mutate audio facts and listing group revisions only; it
// never changes name records, directory facts, lyric facts or placements.
// Consequently only those immutable records are cached, never audio facts.
type lyricTxCache struct {
	s        *SQLStore
	tx       treeQuery
	ctx      context.Context
	masterID string
	entries  map[string]lyricCachedEntry
	parents  map[string]string
	lyrics   map[string]string
}

func (c *lyricTxCache) entry(id string) (lyricCachedEntry, error) {
	if got, ok := c.entries[id]; ok {
		return got, nil
	}
	r, e, err := c.s.recordByID(c.ctx, c.tx, id)
	if err != nil {
		return lyricCachedEntry{}, err
	}
	got := lyricCachedEntry{index: r.ObjectIndex, entry: e}
	c.entries[id] = got
	return got, nil
}

func (c *lyricTxCache) path(entry Entry) (string, error) {
	parent, ok := c.parents[entry.ParentID]
	if !ok {
		if _, err := c.s.listingAncestorAnchor(c.ctx, c.tx, entry.ParentID, true); err != nil {
			return "", err
		}
		if entry.ParentID != c.s.rootID {
			ancestor, err := c.entry(entry.ParentID)
			if err != nil || ancestor.entry.Kind != "directory" {
				return "", ErrInvalid
			}
			parent, err = c.s.pathInTransaction(c.ctx, c.tx, ancestor.entry)
			if err != nil {
				return "", err
			}
		}
		c.parents[entry.ParentID] = parent
	}
	value := entry.Name
	if parent != "" {
		value = parent + "/" + entry.Name
	}
	if len(value) > 4096 || utf8.RuneCountInString(value) > 1024 {
		return "", ErrInvalid
	}
	return value, nil
}

func (c *lyricTxCache) lyric(id string) (string, error) {
	if path, ok := c.lyrics[id]; ok {
		return path, nil
	}
	item, err := c.entry(id)
	if err != nil || item.entry.Kind != "lyric" {
		return "", ErrInvalid
	}
	path, err := c.path(item.entry)
	if err != nil || !strings.HasPrefix(path, "lyrics/") || path == "lyrics/default.lrc" {
		return "", ErrInvalid
	}
	facts, _, err := c.s.factsFor(c.ctx, c.tx, item.entry, item.index)
	if err != nil || facts.Revocation != nil || facts.InternalPlaceholder {
		return "", ErrInvalid
	}
	if err = noPendingLyricRevocation(c.ctx, c.tx, item.index); err != nil {
		return "", err
	}
	placement, err := c.s.placementFor(c.ctx, c.tx, item.entry, item.index)
	if err != nil || placement.State != "active" || placement.OwnerID != c.masterID || placement.NativeObjectID != id {
		return "", ErrInvalid
	}
	c.lyrics[id] = path
	return path, nil
}
