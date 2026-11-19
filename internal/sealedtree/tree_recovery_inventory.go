package sealedtree

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

// RecoveryMediaPlacement is an expected physical object derived from the
// authenticated Master tree. It contains no logical path, provider key, vault
// reference, or read grant. Keep this projection in trusted recovery code.
type RecoveryMediaPlacement struct {
	ObjectID string
	Kind     string
	OwnerID  string
	BlobID   string
	Bytes    int64

	// NativeSHA256 hashes the complete stored blob. A revoked alias on a
	// hidden file still has a physical blob that must be accounted for.
	NativeSHA256               string
	ReadAlias                  string
	AliasRevision              string
	Descriptor                 string
	AliasRevoked               bool
	AliasRevocationOperationID string

	// S3CompositeSHA256 is a provider multipart checksum, not a full-file
	// SHA-256. For S3, BlobID is the opaque provider object identity.
	S3CompositeSHA256 string
	S3ETag            string
	S3VersionID       string
	S3ObjectRevision  int64
}

// RecoveryMediaInventory describes a successful scan of one fenced generation.
type RecoveryMediaInventory struct {
	TreeGeneration int64
	Objects        int64
}

// VisitRecoveryMedia walks all settled file placements, including hidden files,
// in the same bounded SQL traversal as Check. The caller owns a shared tree
// lease and must keep it until the dependent proof has been checked. The
// visitor must not reenter the store or lease. Its records are provisional
// until this method succeeds. This does not observe Owner or provider bytes.
func (s *SQLStore) VisitRecoveryMedia(ctx context.Context, lease *TreeLease, visit func(RecoveryMediaPlacement) error) (RecoveryMediaInventory, error) {
	var result RecoveryMediaInventory
	if !s.valid() || ctx == nil || lease == nil || visit == nil {
		return result, ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return result, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return result, err
	}

	var objects int64
	if _, err := s.check(ctx, func(placement RecoveryMediaPlacement) error {
		if err := visit(placement); err != nil {
			return err
		}
		objects++
		return nil
	}); err != nil {
		return result, err
	}
	if err := lease.checkLocked(ctx); err != nil {
		return result, err
	}
	return RecoveryMediaInventory{TreeGeneration: lease.generation, Objects: objects}, nil
}

func (s *SQLStore) recoveryNativeMedia(ctx context.Context, tx treeQuery, entry Entry, placement Placement, facts Facts) (RecoveryMediaPlacement, error) {
	var result RecoveryMediaPlacement
	if placement.State != "active" {
		return result, ErrInvalid
	}
	descriptor, err := protocol.IngressMediaDescriptor(placement.Bytes, placement.Encryption)
	if err != nil {
		return result, ErrInvalid
	}
	revision, err := protocol.OpaquePlacementRevisionFromDescriptor(placement.ReadAlias, placement.BlobID, placement.SHA256, descriptor, placement.Bytes)
	if err != nil {
		return result, ErrInvalid
	}
	proof := facts.HiddenProof
	var revocationOperation string
	if proof != nil {
		if proof.OwnerID != placement.OwnerID || proof.Alias != placement.ReadAlias || proof.BlobID != placement.BlobID || proof.Revision != revision {
			return result, ErrInvalid
		}
		reservation, err := s.revocationReservation(proof.OperationID)
		if err != nil {
			return result, ErrInvalid
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, reservation).Scan(&count); err != nil || count != 1 {
			return result, ErrInvalid
		}
		key, relationship, master, err := pairedOwnerKey(ctx, tx, *proof)
		if err != nil || key != proof.OwnerPublicKey || relationship != proof.RelationshipBinding || master != proof.MasterBinding {
			return result, ErrInvalid
		}
		revocationOperation = proof.OperationID
	}
	return RecoveryMediaPlacement{
		ObjectID: entry.ObjectID, Kind: entry.Kind, OwnerID: placement.OwnerID, BlobID: placement.BlobID,
		Bytes: placement.Bytes, NativeSHA256: placement.SHA256, ReadAlias: placement.ReadAlias,
		AliasRevision: revision, Descriptor: descriptor, AliasRevoked: proof != nil, AliasRevocationOperationID: revocationOperation,
	}, nil
}

func (s *SQLStore) recoveryS3Media(ctx context.Context, tx treeQuery, entry Entry, index string, facts Facts) (RecoveryMediaPlacement, error) {
	var result RecoveryMediaPlacement
	if entry.Kind != "audio" && entry.Kind != "video" || facts.HiddenProof != nil {
		return result, ErrInvalid
	}
	// Check has already authenticated the indexed S3 envelope, encryption
	// ID, and reservation in this same read transaction.
	var slot string
	var revision int64
	var sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT blob_index,revision,sealed FROM sealed_tree_placements WHERE object_index=?`, index).Scan(&slot, &revision, &sealed); err != nil {
		return result, err
	}
	placement, err := s.openIndexedS3Placement(ctx, tx, entry.ObjectID, slot, index, revision, sealed)
	if err != nil {
		return result, err
	}
	return RecoveryMediaPlacement{
		ObjectID: entry.ObjectID, Kind: entry.Kind, OwnerID: placement.MemberID, BlobID: placement.Proof.ObjectID,
		Bytes: placement.Proof.Bytes, S3CompositeSHA256: placement.Proof.CompositeSHA256,
		S3ETag: placement.Proof.ETag, S3VersionID: placement.Proof.VersionID, S3ObjectRevision: placement.ObjectRevision,
	}, nil
}
