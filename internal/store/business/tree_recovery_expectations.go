package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

const (
	recoveryExpectationLimit   = 25000
	recoveryS3ExpectationLimit = 1024
)

// RecoveryOwnerExpectation contains private Master placement metadata. The
// native records have opaque locators. S3 records include exact provider keys
// and must be used only by trusted recovery code, never logged or serialized.
type RecoveryOwnerExpectation struct {
	RecoveryOwnerAccounting
	Media      []sealedtree.RecoveryMediaPlacement `json:"-"`
	Recordings []sealedtree.RecoveryMediaPlacement `json:"-"`
	S3         []sealedtree.S3Placement            `json:"-"`
}

// RecoveryExpectations is a provisional Master view under the caller's Owner
// and tree leases. Keep both leases through the dependent physical checks.
type RecoveryExpectations struct {
	Accounting RecoveryAccounting
	Owners     []RecoveryOwnerExpectation
}

// BuildRecoveryExpectations collects the native and versioned S3 placements
// while reconciling their accounting. No bytes or provider credentials are
// read. A later verifier must establish physical evidence before using them.
func (r *Repository) BuildRecoveryExpectations(ctx context.Context, owner store.OwnerControlLease, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, key []byte, nodeVault *vault.Vault) (RecoveryExpectations, error) {
	var empty RecoveryExpectations
	collector := recoveryExpectationCollector{
		owners:   make(map[string]*RecoveryOwnerExpectation),
		locators: make(map[string]struct{}),
	}
	accounting, err := r.verifyRecoveryAccounting(ctx, owner, tree, lease, key, nodeVault, collector.addMedia, collector.addRecording)
	if err != nil {
		return empty, err
	}
	// Tree visitors must not reenter the tree lease. Only these bounded S3
	// point reads are needed after the single accounting traversal.
	s3Locations := make(map[recoveryS3ObjectIdentity]struct{}, len(collector.s3))
	for _, expected := range collector.s3 {
		view, err := tree.ReadS3ListingObjectWithLease(ctx, lease, expected.ObjectID, true)
		if err != nil {
			return empty, err
		}
		placement := view.Placement
		identity, err := matchRecoveryS3Placement(expected, view)
		if err != nil {
			return empty, err
		}
		if _, exists := s3Locations[identity]; exists {
			return empty, errRecoveryAccounting
		}
		s3Locations[identity] = struct{}{}
		group := collector.owner(expected.OwnerID)
		group.S3 = append(group.S3, placement)
	}
	result := RecoveryExpectations{Accounting: accounting, Owners: make([]RecoveryOwnerExpectation, 0, len(accounting.Owners))}
	for _, charge := range accounting.Owners {
		group := collector.owner(charge.ID)
		if int64(len(group.Media)+len(group.Recordings)+len(group.S3)) != charge.Objects {
			return empty, errRecoveryAccounting
		}
		group.RecoveryOwnerAccounting = charge
		result.Owners = append(result.Owners, *group)
	}
	if err = lease.Check(ctx); err != nil {
		return empty, err
	}
	if err = owner.Check(ctx); err != nil {
		return empty, err
	}
	return result, nil
}

type recoveryExpectationCollector struct {
	owners   map[string]*RecoveryOwnerExpectation
	locators map[string]struct{}
	s3       []sealedtree.RecoveryMediaPlacement
	count    int
}

func (c *recoveryExpectationCollector) owner(id string) *RecoveryOwnerExpectation {
	group := c.owners[id]
	if group == nil {
		group = &RecoveryOwnerExpectation{}
		c.owners[id] = group
	}
	return group
}

func (c *recoveryExpectationCollector) addMedia(item sealedtree.RecoveryMediaPlacement) error {
	if item.S3VersionID == "" {
		return c.addNative(item)
	}
	if c.count >= recoveryExpectationLimit || len(c.s3) >= recoveryS3ExpectationLimit {
		return store.ErrSealedTreeInventoryLimit
	}
	c.count++
	c.s3 = append(c.s3, item)
	return nil
}

func (c *recoveryExpectationCollector) addRecording(item RecoveryRecordingPlacement) error {
	return c.addNative(sealedtree.RecoveryMediaPlacement{
		ObjectID: item.RecordingID, Kind: "recording", OwnerID: item.OwnerID, BlobID: item.BlobID, Bytes: item.Bytes,
		NativeSHA256: item.SHA256, ReadAlias: item.ReadAlias, AliasRevision: item.AliasRevision, Descriptor: item.Descriptor,
	})
}

func (c *recoveryExpectationCollector) addNative(item sealedtree.RecoveryMediaPlacement) error {
	if c.count >= recoveryExpectationLimit {
		return store.ErrSealedTreeInventoryLimit
	}
	if item.BlobID == "" || item.ReadAlias == "" || item.BlobID == item.ReadAlias {
		return errRecoveryAccounting
	}
	for _, locator := range []string{item.BlobID, item.ReadAlias} {
		if _, exists := c.locators[locator]; exists {
			return errRecoveryAccounting
		}
	}
	c.locators[item.BlobID] = struct{}{}
	c.locators[item.ReadAlias] = struct{}{}
	c.count++
	group := c.owner(item.OwnerID)
	if item.Kind == "recording" {
		group.Recordings = append(group.Recordings, item)
	} else {
		group.Media = append(group.Media, item)
	}
	return nil
}

type recoveryS3ObjectIdentity struct {
	origin, bucket, key, version string
}

func matchRecoveryS3Placement(expected sealedtree.RecoveryMediaPlacement, view sealedtree.S3ListingObject) (recoveryS3ObjectIdentity, error) {
	var empty recoveryS3ObjectIdentity
	placement, proof := view.Placement, view.Placement.Proof
	current := sealedtree.RecoveryMediaPlacement{
		ObjectID: view.Entry.ObjectID, Kind: view.Entry.Kind, OwnerID: placement.MemberID, BlobID: proof.ObjectID, Bytes: proof.Bytes,
		S3CompositeSHA256: proof.CompositeSHA256, S3ETag: proof.ETag, S3VersionID: proof.VersionID, S3ObjectRevision: placement.ObjectRevision,
	}
	if current != expected || placement.ObjectID != expected.ObjectID || proof.MediaID != expected.ObjectID || proof.MemberID != expected.OwnerID ||
		proof.VersionID == "" || proof.VersionID == "null" || proof.MetadataFormat != store.S3OpaqueMetadata || placement.Encryption == nil {
		return empty, errRecoveryAccounting
	}
	namespace, err := placement.Location.Namespace()
	if err != nil {
		return empty, errRecoveryAccounting
	}
	key, err := placement.Location.ProviderKey(proof.Key)
	if err != nil {
		return empty, errRecoveryAccounting
	}
	return recoveryS3ObjectIdentity{namespace.Origin, namespace.Bucket, key, proof.VersionID}, nil
}
