package sealedtree

import (
	"context"
	"database/sql"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ValidatePendingSourceLyricsTx checks authenticated pending tree facts against
// the private, signed-source-derived lyric decisions in the caller's SQL
// transaction. This read-only primitive does not authorize publication, prove
// source/owner/vault fencing, validate object bytes or commit the transaction.
// The real consumer must hold all those fences and call batch.CheckForCommit
// with freshly read evidence immediately before the same atomic COMMIT.
func (s *SQLStore) ValidatePendingSourceLyricsTx(ctx context.Context, tx *sql.Tx, batch *sourceauth.DecisionBatch, pin sourceauth.AuthorityPin, envelope store.EncryptedMediaSourceSnapshot, version int64, operations []string) error {
	if !s.valid() || ctx == nil || tx == nil || batch == nil || len(operations) == 0 || len(operations) > 25000 || batch.CheckForCommit(pin, envelope, version) != nil {
		return ErrInvalid
	}
	digest, generation, err := batch.SourceReference()
	if err != nil || !hexID(digest) || !hexID(generation) || s.verifyRoot(ctx, tx) != nil {
		return ErrInvalid
	}
	seenOps, seenTracks := make(map[string]bool, len(operations)), make(map[string]bool, len(operations))
	for _, operation := range operations {
		if !hexID(operation) || seenOps[operation] {
			return ErrInvalid
		}
		seenOps[operation] = true
		pending, entry, _, err := s.pending(ctx, tx, operation)
		if err != nil || pending.facts == nil || entry.Kind != "audio" || seenTracks[entry.ObjectID] {
			return ErrInvalid
		}
		seenTracks[entry.ObjectID] = true
		path, err := s.pathInTransaction(ctx, tx, entry)
		if err != nil || batch.MatchesMediaPath(entry.ObjectID, path) != nil {
			return ErrInvalid
		}
		facts, err := s.tree.OpenFacts(*pending.facts)
		if err != nil || !validFacts(facts) || !factsCompatiblePending(entry, facts) {
			return ErrInvalid
		}
		resolution := facts.LyricResolution
		if resolution == nil || resolution.Origin != "" || resolution.SourceDigest != digest || resolution.SourceGeneration != generation {
			return ErrInvalid
		}
		state, lyricID, err := batch.Decision(entry.ObjectID)
		if err != nil || state != resolution.State {
			return ErrInvalid
		}
		var relation sourceauth.SourceLyricLinkFact
		switch state {
		case "none":
			if lyricID != "" || facts.Lyric != nil || facts.InternalDefaultLyric != nil {
				return ErrInvalid
			}
		case "explicit":
			lyric := facts.Lyric
			if lyric == nil || lyric.LyricID != lyricID || facts.InternalDefaultLyric != nil {
				return ErrInvalid
			}
			relation = sourceauth.SourceLyricLinkFact{MediaID: entry.ObjectID, MediaPath: lyric.LegacyMediaPath, LyricID: lyric.LyricID, LyricPath: lyric.LegacyLyricPath, CreatedAt: lyric.CreatedAt, UpdatedAt: lyric.UpdatedAt}
		case "default":
			lyric := facts.InternalDefaultLyric
			if lyric == nil || lyric.DefaultLyricID != lyricID || facts.Lyric != nil {
				return ErrInvalid
			}
			relation = sourceauth.SourceLyricLinkFact{MediaID: entry.ObjectID, MediaPath: lyric.LegacyMediaPath, LyricID: lyric.DefaultLyricID, LyricPath: "lyrics/default.lrc", CreatedAt: lyric.CreatedAt, UpdatedAt: lyric.UpdatedAt}
		default:
			return ErrInvalid
		}
		if batch.MatchesRelation(entry.ObjectID, relation) != nil {
			return ErrInvalid
		}
	}
	if batch.CheckForCommit(pin, envelope, version) != nil {
		return ErrInvalid
	}
	return nil
}
