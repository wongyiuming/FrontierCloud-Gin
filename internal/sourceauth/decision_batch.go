package sourceauth

import (
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// DecisionBatch is a process-local immutable view of a verified set of lyric
// decisions. It is not an authorization to commit, a trusted clock, an owner
// receipt, or a source/target transaction fence. A batch may be used only by a
// single atomic consumer which verifies its own source, tree and owner fences
// and calls CheckForCommit with the currently read pin/envelope/version
// immediately before committing that same transaction.
type DecisionBatch struct {
	verified  *CompleteVerified
	decisions map[string]lyricDecision
}

// PrepareDecisionBatch validates the complete current ciphertext and copies
// decisions into a private bounded map. Duplicate or unknown IDs fail closed.
// No caller-provided decision, verification time or authority is trusted.
func (v *CompleteVerified) PrepareDecisionBatch(pin AuthorityPin, envelope store.EncryptedMediaSourceSnapshot, version int64, trackIDs []string) (*DecisionBatch, error) {
	if v == nil || v.snapshot == nil || len(trackIDs) == 0 || len(trackIDs) > 25000 || !reflect.DeepEqual(v.pin, pin) || version != v.version || v.snapshot.Check(sourcePin(pin), v.challenge, envelope, version) != nil {
		return nil, ErrInvalid
	}
	decisions := make(map[string]lyricDecision, len(trackIDs))
	for _, id := range trackIDs {
		if id == "" || len(id) > 128 {
			return nil, ErrInvalid
		}
		decision, ok := v.decisions[id]
		if !ok {
			return nil, ErrInvalid
		}
		if _, exists := decisions[id]; exists {
			return nil, ErrInvalid
		}
		decisions[id] = decision
	}
	batch := &DecisionBatch{verified: v, decisions: decisions}
	if err := batch.CheckForCommit(pin, envelope, version); err != nil {
		return nil, err
	}
	return batch, nil
}

// Decision is inspection only: it does not revalidate current source evidence.
func (b *DecisionBatch) Decision(trackID string) (string, string, error) {
	if b == nil || b.verified == nil {
		return "", "", ErrInvalid
	}
	decision, ok := b.decisions[trackID]
	if !ok {
		return "", "", ErrInvalid
	}
	return decision.state, decision.lyricID, nil
}

// MatchesRelation checks every preserved historical lyric-relation field
// against the verified immutable source copy. The value comparison does not
// establish a source/owner/tree fence or authorize the caller's transaction.
// For state "none" the relation must be the zero value.
func (b *DecisionBatch) MatchesRelation(trackID string, relation SourceLyricLinkFact) error {
	if b == nil || b.verified == nil {
		return ErrInvalid
	}
	decision, ok := b.decisions[trackID]
	if !ok || decision.relation != relation {
		return ErrInvalid
	}
	return nil
}

// MatchesMediaPath compares the authenticated complete projection's exact
// historical path with the path reconstructed in the target transaction.
func (b *DecisionBatch) MatchesMediaPath(trackID, path string) error {
	if b == nil || b.verified == nil || path == "" {
		return ErrInvalid
	}
	decision, ok := b.decisions[trackID]
	if !ok || decision.mediaPath != path {
		return ErrInvalid
	}
	return nil
}

// SourceReference returns inspection values only. CheckForCommit remains
// mandatory, and the consuming transaction must authenticate the target pin.
func (b *DecisionBatch) SourceReference() (string, string, error) {
	if b == nil || b.verified == nil || b.verified.snapshot == nil || len(b.decisions) == 0 {
		return "", "", ErrInvalid
	}
	return b.verified.snapshot.Digest(), b.verified.pin.Generation, nil
}

// CheckForCommit rehashes the actual currently supplied ciphertext, checks the
// complete pin, version and deadline, and must run under the consumer's real
// transaction/fences immediately before one atomic commit. It cannot itself
// authenticate a caller-provided pin or stop an unfenced database writer.
func (b *DecisionBatch) CheckForCommit(pin AuthorityPin, envelope store.EncryptedMediaSourceSnapshot, version int64) error {
	if b == nil || b.verified == nil || b.verified.snapshot == nil || len(b.decisions) == 0 || !reflect.DeepEqual(b.verified.pin, pin) || version != b.verified.version || b.verified.snapshot.Check(sourcePin(pin), b.verified.challenge, envelope, version) != nil {
		return ErrInvalid
	}
	return nil
}
