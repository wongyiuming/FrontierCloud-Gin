package preprodimport

// Isolated observation only: plaintext media and user lyrics keep their
// existing content semantics. Built-in fallback has a distinct lifecycle and
// remains closed until its internal, non-user-visible mapping is implemented.
import (
	"context"
	"crypto/ecdh"
	"path"
	"strconv"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func reconcilePlainOrLyric(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, sourceEnvelope, objectProof store.EncryptedMediaSourceSnapshot, sourceChallenge string, complete completeSnapshot, objectID string, scope objectProofScope, now time.Time) (pendingObservation, error) {
	var empty pendingObservation
	if ctx == nil || tree == nil || lease == nil || receiver == nil || !id64.MatchString(objectID) || lease.Check(ctx) != nil || pin.AuthorityKind != "ssh-collector-v1" {
		return empty, invalid("plain object input")
	}
	signed, sourceDigest, err := authenticateCompleteSource(sourceEnvelope, receiver, pin, sourceChallenge, now, complete)
	if err != nil {
		return empty, err
	}
	generation, err := completeSnapshotDigest(complete)
	if err != nil || generation != pin.Generation {
		return empty, invalid("plain object generation")
	}
	var media Media
	found := false
	for _, m := range complete.Projection.Media {
		if m.MediaID == objectID {
			if found || m.Encryption != nil {
				return empty, invalid("plain object kind")
			}
			media, found = m, true
		}
	}
	for _, lyric := range complete.Projection.Lyrics {
		if lyric.ID == objectID {
			if found || lyric.Encryption != nil || lyric.Builtin {
				return empty, invalid("plain lyric kind")
			}
			var sourceID string
			for _, mapping := range complete.Projection.Mappings {
				if mapping.Role == "master" {
					sourceID = mapping.SourceID
				}
			}
			media = Media{MediaID: lyric.ID, ObjectID: lyric.ID, SourceID: sourceID, Path: lyric.Path, Kind: "lyric", Size: lyric.Size, SHA256: lyric.SHA256}
			found = true
		}
	}
	if !found || !validPath(media.Path, media.Kind) {
		return empty, invalid("plain object absent")
	}
	var mapping Mapping
	for _, candidate := range complete.Projection.Mappings {
		if candidate.SourceID == media.SourceID {
			if mapping.SourceID != "" {
				return empty, invalid("plain owner mapping")
			}
			mapping = candidate
		}
	}
	if mapping.SourceID == "" || mapping.TargetID != scope.TargetOwnerID || media.Kind == "lyric" && (mapping.Role != "master" || media.SourceID != pin.SourceNode) {
		return empty, invalid("plain owner mapping")
	}
	if _, err = sourceObjectFactsDigest(signed.Snapshot, media); err != nil {
		return empty, err
	}
	var sourceETag string
	if media.Kind != "lyric" {
		matched := false
		for _, section := range signed.Snapshot.Sections {
			if section.Name == "placements" {
				for _, row := range section.Rows {
					if len(row) != 10 || row[0] == nil {
						return empty, invalid("plain placement")
					}
					if *row[0] != media.MediaID {
						continue
					}
					if matched {
						return empty, invalid("plain placement")
					}
					matched = true
					for _, cell := range row {
						if cell == nil {
							return empty, invalid("plain placement")
						}
					}
					size, e := strconv.ParseInt(*row[5], 10, 64)
					if e != nil || *row[1] != media.SourceID || *row[2] != media.ObjectID || *row[3] != media.Path || *row[4] != media.Kind || size != media.Size || *row[7] != "active" {
						return empty, invalid("plain placement")
					}
					sourceETag = *row[6]
				}
			}
		}
		if !matched {
			return empty, invalid("plain placement absent")
		}
	}
	var placementFact *sourcePlacementFact
	if media.Kind != "lyric" {
		for i := range complete.Facts.Placements {
			if complete.Facts.Placements[i].MediaID == media.MediaID {
				placementFact = &complete.Facts.Placements[i]
				break
			}
		}
		if placementFact == nil || placementFact.ETag != sourceETag || placementFact.State != "active" {
			return empty, invalid("plain placement facts")
		}
	}
	if err = verifySSHObjectProof(objectProof, receiver, pin, signed.Snapshot, sourceDigest, media, scope, now); err != nil {
		return empty, err
	}
	pending, found, err := tree.FindPendingObjectWithLease(ctx, lease, media.MediaID)
	if err != nil || !found {
		return empty, invalid("plain pending absent")
	}
	parent, err := tree.ResolveDirectoryForRecoveryWithLease(ctx, lease, pending.Entry.ParentID)
	if err != nil || pending.Entry.ObjectID != media.MediaID || pending.Entry.Kind != media.Kind || path.Join(parent, pending.Entry.Name) != media.Path || pending.Placement.ObjectID != media.MediaID || pending.Placement.NativeObjectID != media.ObjectID || pending.Placement.OwnerID != scope.TargetOwnerID || pending.Placement.BlobID != scope.TargetBlobID || pending.Placement.ReadAlias != scope.TargetReadAlias || pending.Placement.Bytes != media.Size || pending.Placement.SHA256 != media.SHA256 || pending.Placement.Encryption != nil || media.Kind != "lyric" && (pending.Placement.ETag != sourceETag || pending.Placement.State != "active") || lease.Check(ctx) != nil {
		return empty, invalid("plain pending mismatch")
	}
	if placementFact != nil && (pending.Placement.CreatedAt != placementFact.CreatedAt || pending.Placement.UpdatedAt != placementFact.UpdatedAt) {
		return empty, invalid("plain placement times")
	}
	resolution, err := sourceLyricResolution(complete, media, sourceDigest, generation)
	if err != nil {
		return empty, err
	}
	if err = reconcileSourceObjectFacts(complete, media, pending.Facts, resolution); err != nil {
		return empty, err
	}
	if err = lease.Check(ctx); err != nil {
		return empty, err
	}
	return pendingObservation{OperationID: pending.OperationID, BlobID: pending.Placement.BlobID, ReadAlias: pending.Placement.ReadAlias}, nil
}
