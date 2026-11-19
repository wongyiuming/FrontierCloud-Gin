package preprodimport

// Read-only reconciliation for a pending Master tree intent. No function in
// this file publishes bytes or authorizes activation.
import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"path"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

type pendingObservation struct {
	OperationID         string
	BlobID              string
	ReadAlias           string
	SourceAuthenticated bool
	SnapshotConsistent  bool
	VaultAuthenticated  bool
	OwnerFinalPublished bool
	RuntimeReady        bool
}

// reconcilePendingEncryptedMediaAndVault composes two independently committed
// observations while retaining the tree lease. VaultAuthenticated describes a
// point-in-time verification only; it is not an atomic commit or a permit.
func reconcilePendingEncryptedMediaAndVault(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, vault *sql.DB, vaultRoot []byte, s completeSnapshot, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, locators map[string]pendingLocatorBinding, stages map[string]string, challenges map[string]string, receipts map[string]signedStageReceipt, pins map[string]ed25519.PublicKey, scope keyScope, now time.Time) (pendingObservation, error) {
	var empty pendingObservation
	obs, err := reconcilePendingMedia(ctx, tree, lease, s, trust, plan, batches, locators, stages, challenges, receipts, pins, scope.MediaID, now)
	if err != nil {
		return empty, err
	}
	if err = verifyInstalledKeyPlan(ctx, vault, vaultRoot, trust, plan, batches, scope, now); err != nil {
		return empty, err
	}
	if err = lease.Check(ctx); err != nil {
		return empty, err
	}
	obs.VaultAuthenticated = true
	return obs, nil
}

// reconcilePendingMedia reads the actual durable tree pending under the same
// caller-held shared lease used to resolve its parent. It compares every
// represented source fact and pinned, fresh staged-owner receipt in memory.
// Source snapshot authority, all directory/visibility facts, quota, key vault,
// final-owner publication, long-running receipt renewal and rollback anchoring
// remain separate gates. A successful observation must never be used as a
// publication permit.
func reconcilePendingMedia(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, s completeSnapshot, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, locators map[string]pendingLocatorBinding, stages map[string]string, challenges map[string]string, receipts map[string]signedStageReceipt, pins map[string]ed25519.PublicKey, mediaID string, now time.Time) (pendingObservation, error) {
	var out pendingObservation
	if ctx == nil || tree == nil || lease == nil || !id64.MatchString(mediaID) {
		return out, invalid("pending reconcile input")
	}
	requests, err := buildCompleteStageReceiptRequests(s, trust, plan, batches, locators, stages, challenges, now)
	if err != nil {
		return out, err
	}
	if err = verifyCompleteStageReceipts(requests, receipts, pins, now); err != nil {
		return out, err
	}
	var media Media
	found := false
	for _, m := range s.Projection.Media {
		if m.MediaID == mediaID {
			media = m
			found = true
			break
		}
	}
	if !found {
		return out, invalid("pending source object")
	}
	var owner Mapping
	for _, m := range s.Projection.Mappings {
		if m.SourceID == media.SourceID {
			owner = m
			break
		}
	}
	if owner.TargetID == "" {
		return out, invalid("pending owner")
	}
	p, found, err := tree.FindPendingObjectWithLease(ctx, lease, media.MediaID)
	if err != nil {
		return out, err
	}
	if !found || !id64.MatchString(p.OperationID) {
		return out, invalid("pending absent")
	}
	parent, err := tree.ResolveDirectoryForRecoveryWithLease(ctx, lease, p.Entry.ParentID)
	if err != nil {
		return out, err
	}
	loc, ok := locators[mediaID]
	if !ok || p.Entry.ObjectID != media.MediaID || p.Entry.Kind != media.Kind || path.Join(parent, p.Entry.Name) != media.Path || p.Placement.ObjectID != media.MediaID || p.Placement.NativeObjectID != media.ObjectID || p.Placement.OwnerID != owner.TargetID || p.Placement.BlobID != loc.BlobID || p.Placement.ReadAlias != loc.ReadAlias || p.Placement.Bytes != media.Size || p.Placement.SHA256 != media.SHA256 || !reflect.DeepEqual(p.Placement.Encryption, media.Encryption) {
		return out, invalid("pending source mismatch")
	}
	var placement *sourcePlacementFact
	for i := range s.Facts.Placements {
		if s.Facts.Placements[i].MediaID == mediaID {
			placement = &s.Facts.Placements[i]
			break
		}
	}
	if placement == nil || p.Placement.ETag != placement.ETag || p.Placement.State != placement.State || p.Placement.CreatedAt != placement.CreatedAt || p.Placement.UpdatedAt != placement.UpdatedAt {
		return out, invalid("pending placement facts")
	}
	if err = reconcileSourceObjectFacts(s, media, p.Facts, nil); err != nil {
		return out, err
	}
	if err = lease.Check(ctx); err != nil {
		return out, err
	}
	return pendingObservation{OperationID: p.OperationID, BlobID: loc.BlobID, ReadAlias: loc.ReadAlias}, nil
}
