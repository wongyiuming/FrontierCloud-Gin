package sealedtree

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
)

// LyricSelection is sensitive Master-only metadata, not a read grant. A
// fallback returns no ordinary lyric ID; an explicit ID must pass its own
// current user, visibility, session and owner authorization before any read.
type LyricSelection struct {
	BuiltinFallback  bool
	ExplicitLyricID  string
	Evidence         string
	Origin           string
	SourceDigest     string
	SourceGeneration string
}

func (s *SQLStore) nativeLyricEvidence(f Facts) (string, error) {
	r := f.LyricResolution
	if r == nil || r.Origin != "native" {
		return "", ErrInvalid
	}
	value, err := json.Marshal(f.Lyric)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(value)
	clear(value)
	return s.listingMAC("native-lyric-operation", f.ObjectID, r.State, r.OperationID, r.PreviousEvidence, strconv.FormatInt(r.PreviousRevision, 10), r.RelationCreatedAt, r.RelationUpdatedAt, hex.EncodeToString(digest[:])), nil
}

// VerifyNativeLinkedLyricFacts verifies the Master-authenticated new-tree
// association on already authenticated visible objects. Callers must hold
// the tree admission/read lease and must separately authorize the user.
func (s *SQLStore) VerifyNativeLinkedLyricFacts(track Entry, facts Facts, lyric Entry) error {
	if !s.valid() || track.Kind != "audio" || lyric.Kind != "lyric" || !factsCompatible(track, facts) || !validFacts(facts) || facts.Lyric == nil || facts.Lyric.LyricID != lyric.ObjectID || facts.LyricResolution == nil || facts.LyricResolution.Origin != "native" || facts.LyricResolution.State != "explicit" {
		return ErrInvalid
	}
	evidence, err := s.nativeLyricEvidence(facts)
	if err != nil || !hmac.Equal([]byte(evidence), []byte(facts.LyricResolution.Evidence)) {
		return ErrInvalid
	}
	return nil
}

// LyricResolutionEvidence binds one decision to the digest of an independently
// authenticated complete source snapshot and its projected generation. This
// digest is not a signature: callers must retain and verify the source proof.
// A future native write needs its own authenticated operation evidence.
func LyricResolutionEvidence(sourceDigest, generation, trackID, state, lyricID string) (string, error) {
	if !hexID(sourceDigest) || !hexID(generation) || !hexID(trackID) || (state != "none" && state != "default" && state != "explicit") || (state == "none" && lyricID != "") || (state != "none" && !hexID(lyricID)) {
		return "", ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:tree:lyric-resolution:v1\x00"))
	for _, value := range []string{sourceDigest, generation, trackID, state, lyricID} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SelectLyricForDisplayWithLease determines only which lyric mode applies.
// A proven-unlinked track or historical default association selects the
// internal fixed fallback; an absent resolution is an error, not proof. The
// evidence reference must be checked against separately authenticated source,
// local-import or native-operation evidence before activation. Hidden tracks can select
// that display mode as
// in the legacy API; this does not authorize access to track or custom lyric
// bytes. The caller retains the real tree lease through its admission commit.
func (s *SQLStore) SelectLyricForDisplayWithLease(ctx context.Context, lease *TreeLease, trackID string) (LyricSelection, error) {
	track, err := s.ReadListingObjectWithLease(ctx, lease, trackID, true)
	entry, facts := track.Entry, track.Facts
	if errors.Is(err, ErrInvalid) {
		// S3 uses a different authenticated placement envelope. It has no
		// native blob locator, but its lyric relationship is still Master-owned.
		providerTrack, e := s.ReadS3ListingObjectWithLease(ctx, lease, trackID, true)
		if e != nil {
			return LyricSelection{}, ErrInvalid
		}
		entry, facts = providerTrack.Entry, providerTrack.Facts
	} else if err != nil || track.Placement.State != "active" {
		return LyricSelection{}, ErrInvalid
	}
	if entry.Kind != "audio" {
		return LyricSelection{}, ErrInvalid
	}
	resolution := facts.LyricResolution
	if resolution == nil {
		return LyricSelection{}, ErrInvalid
	}
	if resolution.Origin == "native" {
		evidence, e := s.nativeLyricEvidence(facts)
		if e != nil || !hmac.Equal([]byte(evidence), []byte(resolution.Evidence)) {
			return LyricSelection{}, ErrInvalid
		}
	} else if resolution.Origin == "local" {
		evidence, e := s.localLyricEvidence(facts)
		if e != nil || !hmac.Equal([]byte(evidence), []byte(resolution.Evidence)) {
			return LyricSelection{}, ErrInvalid
		}
	}
	if resolution.State == "explicit" && facts.Lyric != nil {
		return LyricSelection{ExplicitLyricID: facts.Lyric.LyricID, Evidence: resolution.Evidence, Origin: resolution.Origin, SourceDigest: resolution.SourceDigest, SourceGeneration: resolution.SourceGeneration}, nil
	}
	if resolution.State == "none" || resolution.State == "default" && (facts.InternalDefaultLyric != nil || resolution.Origin == "native") {
		return LyricSelection{BuiltinFallback: true, Evidence: resolution.Evidence, Origin: resolution.Origin, SourceDigest: resolution.SourceDigest, SourceGeneration: resolution.SourceGeneration}, nil
	}
	return LyricSelection{}, ErrInvalid
}
