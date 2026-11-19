package preprodimport

import "github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"

type sourceObjectFact = sourceauth.SourceObjectFact
type sourcePlacementFact = sourceauth.SourcePlacementFact
type sourceVisibilityFact = sourceauth.SourceVisibilityFact
type sourcePlaybackFact = sourceauth.SourcePlaybackFact
type sourceLyricLinkFact = sourceauth.SourceLyricLinkFact
type sourceEncryptionFact = sourceauth.SourceEncryptionFact
type sourceCompleteFacts = sourceauth.SourceCompleteFacts
type completeSnapshot = sourceauth.CompleteSnapshot

func sourceFactText(v string, max int) bool { return sourceauth.SourceFactText(v, max) }
func sourceFactPath(v string) bool          { return sourceauth.SourceFactPath(v) }
func containsNUL(v string) bool             { return sourceauth.ContainsNUL(v) }
func completeSnapshotDigest(s completeSnapshot) (string, error) {
	return sourceauth.CompleteSnapshotDigest(s)
}
