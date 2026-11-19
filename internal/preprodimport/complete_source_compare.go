package preprodimport

// This comparison runs only in trusted Master memory after the enclosing SSH
// collector signature and receiver have been authenticated. It does not
// authorize publication or establish a simultaneous cross-node snapshot.
import (
	"crypto/ecdh"

	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// authenticateCompleteSource is an observation gate, not a publication
// permit. The caller must still reconcile owner bytes, rights and recovery.
func authenticateCompleteSource(envelope store.EncryptedMediaSourceSnapshot, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, challenge string, now time.Time, complete completeSnapshot) (store.SignedMediaSourceSnapshot, string, error) {
	var empty store.SignedMediaSourceSnapshot
	if pin.AuthorityKind != "ssh-collector-v1" {
		return empty, "", invalid("complete source collector required")
	}
	signed, digest, err := openMediaSourceSnapshot(envelope, receiver, pin, challenge, now)
	if err != nil {
		return empty, "", err
	}
	generation, err := completeSnapshotDigest(complete)
	if err != nil || generation != pin.Generation || complete.Projection.PremasterKeyID != pin.SourceKeyID || !sourceScopeMatches(pin.ImportScope, complete.Projection) {
		return empty, "", invalid("complete source generation")
	}
	master, masterTarget := "", ""
	for _, mapping := range complete.Projection.Mappings {
		if mapping.Role == "master" {
			master = mapping.SourceID
			masterTarget = mapping.TargetID
		}
	}
	if master != signed.Snapshot.SourceNode || masterTarget != pin.TargetNode {
		return empty, "", invalid("complete source master")
	}
	if pin.AuthorityKind == "ssh-collector-v1" {
		owners := map[string]bool{}
		for _, owner := range pin.SourceOwners {
			owners[owner.NodeID] = true
		}
		for _, mapping := range complete.Projection.Mappings {
			if !owners[mapping.SourceID] {
				return empty, "", invalid("complete source owner pin")
			}
		}
	}
	if err = compareCompleteSourceFacts(signed.Snapshot, complete); err != nil {
		return empty, "", err
	}
	return signed, digest, nil
}

func compareCompleteSourceFacts(source store.MediaSourceSnapshot, complete completeSnapshot) error {
	return sourceauth.CompareCompleteSourceFacts(source, complete)
}
