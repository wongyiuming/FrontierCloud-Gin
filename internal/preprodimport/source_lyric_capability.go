package preprodimport

// The shared capability is unregistered and does not prove target commit,
// source vault inode, cross-database fencing or anti-rollback.
import (
	"crypto/ecdh"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type verifiedCompleteSourceLyric struct{ verified *sourceauth.CompleteVerified }

func prepareCompleteSourceLyric(envelope store.EncryptedMediaSourceSnapshot, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, challenge string, complete completeSnapshot, version int64) (*verifiedCompleteSourceLyric, error) {
	verified, err := sourceauth.VerifyComplete(envelope, receiver, pin, challenge, complete, version)
	if err != nil {
		return nil, invalid("source capability")
	}
	return &verifiedCompleteSourceLyric{verified: verified}, nil
}

func (v *verifiedCompleteSourceLyric) check(pin sourceAuthorityPin, envelope store.EncryptedMediaSourceSnapshot, version int64, trackID string, selected sealedtree.LyricSelection) error {
	if v == nil || v.verified == nil || selected.Origin != "" || selected.SourceDigest != v.verified.Digest() || selected.SourceGeneration != pin.Generation {
		return invalid("source capability changed")
	}
	state, lyricID, err := v.verified.Decision(trackID)
	if err != nil || v.verified.CheckDecision(pin, envelope, version, trackID, state, lyricID) != nil {
		return invalid("source capability decision")
	}
	evidence, err := sealedtree.LyricResolutionEvidence(selected.SourceDigest, selected.SourceGeneration, trackID, state, lyricID)
	if err != nil || evidence != selected.Evidence {
		return invalid("source capability resolution")
	}
	if state == "explicit" {
		if selected.BuiltinFallback || selected.ExplicitLyricID != lyricID {
			return invalid("source capability lyric")
		}
	} else if !selected.BuiltinFallback || selected.ExplicitLyricID != "" {
		return invalid("source capability fallback")
	}
	return nil
}
