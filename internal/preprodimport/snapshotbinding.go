package preprodimport

// These internal checks relate a typed media-only projection to the synthetic
// signed key plan. They are not a source snapshot reader, a tree transaction,
// an owner receipt, or an enabled import route.

import (
	"context"
	"crypto/ecdh"

	"database/sql"

	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
)

type pendingLocatorBinding struct{ BlobID, ReadAlias string }

// snapshotProjectionDigest binds all typed sections, including visibility,
// lyrics, owner mapping and tombstones. A signature over this digest is still
// a claim, not proof that a real source snapshot was acquired consistently.
func snapshotProjectionDigest(s Snapshot) (string, Report, error) {
	return sourceauth.SnapshotProjectionDigest(s)
}
func validateProjectionTree(s Snapshot) error { return sourceauth.ValidateProjectionTree(s) }

// verifySnapshotKeyPlanBinding requires every encrypted media object exactly
// once and no extra objects. locators must come from separately authenticated
// durable target-tree pending records; this function does not acquire a lease
// or establish their provenance. Encrypted lyrics are rejected until their
// source and tree contracts are explicitly connected, never treated as plain.
func verifySnapshotKeyPlanBinding(s Snapshot, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, locators map[string]pendingLocatorBinding, now time.Time) (Report, error) {
	var empty Report
	generation, report, err := snapshotProjectionDigest(s)
	if err != nil {
		return empty, err
	}
	return verifySnapshotKeyPlanAtGeneration(s, generation, report, trust, plan, batches, locators, now)
}

// A real-source caller must use this stronger binding after independently
// authenticating a complete, consistent source transaction. This method does
// not itself establish that the declared rows exhaust the source database.
func verifyCompleteSnapshotKeyPlanBinding(s completeSnapshot, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, locators map[string]pendingLocatorBinding, now time.Time) (Report, error) {
	var empty Report
	generation, err := completeSnapshotDigest(s)
	if err != nil {
		return empty, err
	}
	for _, placement := range s.Facts.Placements {
		if placement.State != "active" {
			return empty, invalid("source placement not settled")
		}
	}
	_, report, err := snapshotProjectionDigest(s.Projection)
	if err != nil {
		return empty, err
	}
	return verifySnapshotKeyPlanAtGeneration(s.Projection, generation, report, trust, plan, batches, locators, now)
}

func verifySnapshotKeyPlanAtGeneration(s Snapshot, generation string, report Report, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, locators map[string]pendingLocatorBinding, now time.Time) (Report, error) {
	var empty Report
	if generation != trust.Generation {
		return empty, invalid("snapshot generation binding")
	}
	if err := verifyPinnedSnapshotPlan(trust, plan, batches, now); err != nil {
		return empty, err
	}
	bySource := make(map[string]Mapping, len(s.Mappings))
	for _, mapping := range s.Mappings {
		bySource[mapping.SourceID] = mapping
	}
	var master Mapping
	for _, m := range s.Mappings {
		if m.Role == "master" {
			master = m
			break
		}
	}
	if master.SourceID != trust.SourceNode || master.TargetID != trust.TargetNode || s.PremasterKeyID != trust.SourceKeyID {
		return empty, invalid("snapshot master identity")
	}
	historical := map[string]bool{}
	for _, m := range s.Media {
		historical[m.MediaID] = true
		historical[m.ObjectID] = true
	}
	for _, l := range s.Lyrics {
		historical[l.ID] = true
		if l.Encryption != nil {
			return empty, invalid("encrypted lyric key plan unsupported")
		}
	}
	for _, d := range s.Directories {
		historical[d.ID] = true
	}
	for _, n := range s.RetiredNonces {
		historical[n.ObjectID] = true
	}
	expected := map[string]Media{}
	for _, m := range s.Media {
		if m.Encryption != nil {
			expected[m.MediaID] = m
		}
	}
	if len(expected) == 0 || len(locators) != len(expected) {
		return empty, invalid("encrypted snapshot coverage")
	}
	seen := map[string]bool{}
	count := 0
	for _, batch := range batches {
		for _, entry := range batch.Body.Entries {
			media, ok := expected[entry.MediaID]
			if !ok || seen[entry.MediaID] {
				return empty, invalid("unexpected encrypted object")
			}
			mapping, ok := bySource[media.SourceID]
			if !ok {
				return empty, invalid("encrypted owner")
			}
			loc, ok := locators[entry.MediaID]
			if !ok || !id64.MatchString(loc.BlobID) || !id64.MatchString(loc.ReadAlias) || historical[loc.BlobID] || historical[loc.ReadAlias] || entry.TargetOwnerID != mapping.TargetID || entry.TargetBlobID != loc.BlobID || entry.TargetReadAlias != loc.ReadAlias || entry.SourceObjectID != media.ObjectID || entry.ContentSHA256 != media.SHA256 || entry.StoredBytes != media.Size || entry.Descriptor != *media.Encryption {
				return empty, invalid("encrypted snapshot object binding")
			}
			seen[entry.MediaID] = true
			count++
		}
	}
	if count != len(expected) {
		return empty, invalid("encrypted snapshot omission")
	}
	// The caller may not infer source authentication, cross-node consistency or
	// runtime readiness solely from this structural binding.
	return report, nil
}

// importProjectionBoundFileKeyGrant is a synthetic composition only. The
// locator argument is not yet read from a held tree lease and no owner receipt
// or source authority has been authenticated; real import remains disabled.
func importProjectionBoundFileKeyGrant(ctx context.Context, db *sql.DB, root []byte, s Snapshot, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, locators map[string]pendingLocatorBinding, snapshot signedSnapshotGrant, scope keyScope, target *ecdh.PrivateKey, grant keyGrant, now time.Time) (bool, error) {
	if _, err := verifySnapshotKeyPlanBinding(s, trust, plan, batches, locators, now); err != nil {
		return false, err
	}
	return importSnapshotAuthorizedFileKeyGrant(ctx, db, root, trust, plan, batches, snapshot, scope, target, grant, now)
}
