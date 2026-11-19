package sourceauth

import (
	"crypto/ecdh"
	"encoding/json"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// CompleteVerified is a process-local proof of source signature AND complete
// projection consistency. It does not authenticate the caller-supplied pin,
// source database inode/version, target transaction or any owner receipt.
type CompleteVerified struct {
	snapshot  *Verified
	pin       AuthorityPin
	decisions map[string]lyricDecision
	challenge string
	version   int64
}

type lyricDecision struct {
	state, lyricID, mediaPath string
	relation                  SourceLyricLinkFact
}

// indexLyricDecisions runs only after the complete projection has passed its
// structural and source checks. It constructs private, immutable lookup
// state; it is not itself evidence of source authorization.
func indexLyricDecisions(complete CompleteSnapshot) (map[string]lyricDecision, error) {
	decisions := make(map[string]lyricDecision, len(complete.Projection.Media))
	seen := make(map[string]bool, len(complete.Projection.Media))
	for _, track := range complete.Projection.Media {
		if seen[track.MediaID] {
			return nil, ErrInvalid
		}
		seen[track.MediaID] = true
		if track.Kind == "audio" {
			decisions[track.MediaID] = lyricDecision{state: "none", mediaPath: track.Path}
		}
	}
	builtin := make(map[string]bool, len(complete.Projection.Lyrics))
	for _, lyric := range complete.Projection.Lyrics {
		if lyric.Builtin {
			builtin[lyric.ID] = true
		}
	}
	linked := make(map[string]bool, len(complete.Facts.LyricLinks))
	for _, link := range complete.Facts.LyricLinks {
		if linked[link.MediaID] || link.LyricID == "" {
			return nil, ErrInvalid
		}
		linked[link.MediaID] = true
		decision, ok := decisions[link.MediaID]
		if !ok {
			return nil, ErrInvalid
		}
		state := "explicit"
		if builtin[link.LyricID] {
			if link.LyricPath != "lyrics/default.lrc" {
				return nil, ErrInvalid
			}
			state = "default"
		}
		decision.state, decision.lyricID, decision.relation = state, link.LyricID, link
		decisions[link.MediaID] = decision
	}
	return decisions, nil
}

func sourcePin(p AuthorityPin) Pin {
	return Pin{SourceNode: p.SourceNode, TargetNode: p.TargetNode, SourceKeyID: p.SourceKeyID, HostKeyDigest: p.SourceSSHHostKeySHA256, AuthorityKind: p.AuthorityKind, SourcePublic: p.SourcePublic, TargetReceiver: p.TargetX25519, Generation: p.Generation}
}

// VerifyComplete has no caller-supplied clock or assertion of verification.
// Full source and target projection comparisons use the same implementation as
// the legacy importer. The bounded copy prevents post-verification mutation.
func VerifyComplete(envelope store.EncryptedMediaSourceSnapshot, receiver *ecdh.PrivateKey, pin AuthorityPin, challenge string, complete CompleteSnapshot, version int64) (*CompleteVerified, error) {
	if receiver == nil || !boundedEnvelope(envelope) {
		return nil, ErrInvalid
	}
	budget := 4 * 1024 * 1024
	if !boundCapabilityInput(reflect.ValueOf(pin), &budget, 0) || !boundCapabilityInput(reflect.ValueOf(complete), &budget, 0) {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(struct {
		Pin      AuthorityPin     `json:"pin"`
		Complete CompleteSnapshot `json:"complete"`
	}{pin, complete})
	if err != nil || len(encoded) > 4*1024*1024 {
		return nil, ErrInvalid
	}
	defer clear(encoded)
	var copied struct {
		Pin      AuthorityPin     `json:"pin"`
		Complete CompleteSnapshot `json:"complete"`
	}
	if json.Unmarshal(encoded, &copied) != nil || !ValidSourceAuthority(copied.Pin) || copied.Pin.AuthorityKind != "ssh-collector-v1" {
		return nil, ErrInvalid
	}
	generation, err := CompleteSnapshotDigest(copied.Complete)
	if err != nil || generation != copied.Pin.Generation || copied.Complete.Projection.PremasterKeyID != copied.Pin.SourceKeyID || !SourceScopeMatches(copied.Pin.ImportScope, copied.Complete.Projection) {
		return nil, ErrInvalid
	}
	master, target := "", ""
	for _, mapping := range copied.Complete.Projection.Mappings {
		if mapping.Role == "master" {
			master, target = mapping.SourceID, mapping.TargetID
		}
	}
	if master != copied.Pin.SourceNode || target != copied.Pin.TargetNode {
		return nil, ErrInvalid
	}
	owners := map[string]bool{}
	for _, owner := range copied.Pin.SourceOwners {
		owners[owner.NodeID] = true
	}
	for _, mapping := range copied.Complete.Projection.Mappings {
		if !owners[mapping.SourceID] {
			return nil, ErrInvalid
		}
	}
	verified, err := Verify(envelope, receiver, sourcePin(copied.Pin), challenge, version)
	if err != nil {
		return nil, ErrInvalid
	}
	signed, err := snapshotcrypt.Open(envelope, receiver)
	if err != nil || CompareCompleteSourceFacts(signed.Snapshot, copied.Complete) != nil || verified.Check(sourcePin(copied.Pin), challenge, envelope, version) != nil {
		return nil, ErrInvalid
	}
	decisions, err := indexLyricDecisions(copied.Complete)
	if err != nil || verified.Check(sourcePin(copied.Pin), challenge, envelope, version) != nil {
		return nil, ErrInvalid
	}
	return &CompleteVerified{snapshot: verified, pin: copied.Pin, decisions: decisions, challenge: challenge, version: version}, nil
}

func (v *CompleteVerified) Digest() string {
	if v == nil || v.snapshot == nil {
		return ""
	}
	return v.snapshot.Digest()
}

// CheckDecision rechecks the current pin/envelope/version/deadline and the
// exact source lyric decision. The caller must authenticate the pin and bind
// the actual source row, tree/owner revisions and commit under real fences.
func (v *CompleteVerified) CheckDecision(pin AuthorityPin, envelope store.EncryptedMediaSourceSnapshot, version int64, trackID, state, lyricID string) error {
	if v == nil || v.snapshot == nil || !reflect.DeepEqual(v.pin, pin) || version != v.version || v.snapshot.Check(sourcePin(pin), v.challenge, envelope, version) != nil {
		return ErrInvalid
	}
	actualState, actualLyric, err := v.Decision(trackID)
	if err != nil || state != actualState || lyricID != actualLyric || v.snapshot.Check(sourcePin(pin), v.challenge, envelope, version) != nil {
		return ErrInvalid
	}
	return nil
}

// Decision returns sensitive Master-only facts from the verified projection;
// callers must still invoke CheckDecision under their real final fence.
func (v *CompleteVerified) Decision(trackID string) (string, string, error) {
	if v == nil || v.snapshot == nil {
		return "", "", ErrInvalid
	}
	decision, ok := v.decisions[trackID]
	if !ok {
		return "", "", ErrInvalid
	}
	return decision.state, decision.lyricID, nil
}
