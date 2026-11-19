package sealedtree

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const playbackTimeFormat = "2006-01-02 15:04:05.000000"
const playbackEventTTL = 7 * 24 * time.Hour

var errNativePlaybackAlreadyCounted = errors.New("sealed playback event already counted")

// RecordNativePlayback counts one qualified report for an exact media object.
// The caller admits the report at the current public ingress first.
// The existing event journal has a separate non-UUID namespace for sealed
// rows; neither a logical path nor a raw session or object ID is stored there.
func (s *SQLStore) RecordNativePlayback(ctx context.Context, path, objectID, session string) (store.PlaybackResult, error) {
	return s.recordNativePlayback(ctx, path, objectID, session, time.Now().UTC())
}

func (s *SQLStore) recordNativePlayback(ctx context.Context, path, objectID, session string, now time.Time) (store.PlaybackResult, error) {
	if !hexID(objectID) || len(session) != 36 || (!strings.HasPrefix(path, "music/") && !strings.HasPrefix(path, "vido/")) {
		return store.PlaybackResult{}, ErrInvalid
	}
	var result store.PlaybackResult
	err := s.withPriorityTx(ctx, func(tx *sql.Tx) error {
		entry, index, err := s.pathEntryTx(ctx, tx, path)
		if err != nil {
			return err
		}
		if entry.ObjectID != objectID || entry.Kind != "audio" && entry.Kind != "video" {
			return ErrInvalid
		}
		if _, err = s.listingAncestorAnchor(ctx, tx, entry.ParentID, true); err != nil {
			return err
		}
		facts, revision, err := s.factsFor(ctx, tx, entry, index)
		if err != nil {
			return err
		}
		var pending bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sealed_tree_revocations WHERE object_index=?)`, index).Scan(&pending); err != nil {
			return err
		}
		if pending || facts.Revocation != nil || facts.S3Deletion != nil {
			return ErrRevocationPending
		}
		s3, err := s.checkIndexedS3(ctx, tx, entry, index)
		if err != nil {
			return err
		}
		if !s3 {
			placement, err := s.placementFor(ctx, tx, entry, index)
			if err != nil {
				return err
			}
			if placement.State != "active" {
				return ErrInvalid
			}
		}
		result.MediaID = entry.ObjectID
		if facts.Playback != nil {
			result.Preference = int(facts.Playback.Preference)
			result.PlayScore = facts.Playback.PlayScore
		}
		stamp := now.Format(playbackTimeFormat)
		counted, err := s.claimNativePlaybackEvent(ctx, tx, objectID, session, stamp, now.Add(playbackEventTTL).Format(playbackTimeFormat))
		if err != nil {
			return err
		}
		if !counted {
			// Roll back the indexed writer's generation change on a retry.
			return errNativePlaybackAlreadyCounted
		}
		if revision < 1 || revision == math.MaxInt64 || result.PlayScore == math.MaxInt64 {
			return ErrConflict
		}
		if facts.Playback == nil {
			facts.Playback = &PlaybackFact{CreatedAt: stamp}
		}
		facts.Playback.PlayScore++
		facts.Playback.UpdatedAt = stamp
		if err = s.replaceListingFactsTx(ctx, tx, entry, index, facts, revision); err != nil {
			return err
		}
		if err = s.pruneNativePlaybackEvents(ctx, tx, stamp); err != nil {
			return err
		}
		result.PlayScore, result.Counted = facts.Playback.PlayScore, true
		return nil
	})
	if err == errNativePlaybackAlreadyCounted {
		return result, nil
	}
	if err != nil {
		return store.PlaybackResult{}, err
	}
	return result, nil
}

func (s *SQLStore) claimNativePlaybackEvent(ctx context.Context, tx treeQuery, objectID, session, stamp, expiry string) (bool, error) {
	lookup := "s1-" + s.listingMAC("playback-event-key", objectID, session)[:33]
	var count int
	var receipt, countedAt, expiresAt string
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MIN(media_id),''),COALESCE(MIN(CAST(counted_at AS TEXT)),''),COALESCE(MIN(CAST(expires_at AS TEXT)),'') FROM media_playback_events WHERE playback_session_id=?`, lookup).Scan(&count, &receipt, &countedAt, &expiresAt)
	if err != nil {
		return false, err
	}
	if count != 0 {
		if count != 1 || !hmac.Equal([]byte(receipt), []byte(s.nativePlaybackReceipt(lookup, countedAt, expiresAt))) {
			return false, ErrInvalid
		}
		if expiresAt > stamp {
			return false, nil
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM media_playback_events WHERE playback_session_id=? AND media_id=?`, lookup, receipt); err != nil {
			return false, err
		}
	}
	receipt = s.nativePlaybackReceipt(lookup, stamp, expiry)
	_, err = tx.ExecContext(ctx, `INSERT INTO media_playback_events (playback_session_id,media_id,counted_at,expires_at) VALUES (?,?,?,?)`, lookup, receipt, stamp, expiry)
	return err == nil, err
}

func (s *SQLStore) nativePlaybackReceipt(lookup, countedAt, expiresAt string) string {
	return s.listingMAC("playback-event-receipt", lookup, countedAt, expiresAt)
}

func (s *SQLStore) pruneNativePlaybackEvents(ctx context.Context, tx treeQuery, stamp string) error {
	// Visit only a small indexed batch. Legacy events and malformed receipts
	// are outside this writer's authority.
	rows, err := tx.QueryContext(ctx, `SELECT playback_session_id,media_id,CAST(counted_at AS TEXT),CAST(expires_at AS TEXT)
		FROM media_playback_events WHERE expires_at<=? ORDER BY expires_at LIMIT 8`, stamp)
	if err != nil {
		return err
	}
	defer rows.Close()
	var expired [][2]string
	for rows.Next() {
		var lookup, receipt, countedAt, expiresAt string
		if err = rows.Scan(&lookup, &receipt, &countedAt, &expiresAt); err != nil {
			return err
		}
		if strings.HasPrefix(lookup, "s1-") && hmac.Equal([]byte(receipt), []byte(s.nativePlaybackReceipt(lookup, countedAt, expiresAt))) {
			expired = append(expired, [2]string{lookup, receipt})
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, key := range expired {
		if _, err = tx.ExecContext(ctx, `DELETE FROM media_playback_events WHERE playback_session_id=? AND media_id=?`, key[0], key[1]); err != nil {
			return err
		}
	}
	return nil
}
