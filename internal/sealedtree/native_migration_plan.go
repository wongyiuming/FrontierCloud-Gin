package sealedtree

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

const nativeMigrationUnitTimeout = 30 * time.Second

// NativeMigrationUnit is a read-only snapshot for trusted Master code. It
// contains sensitive identity and locator information and is not a wire or
// plaintext persistence format. Digest binds the complete file roster and
// its authenticated versions, independently of unrelated tree generations.
type NativeMigrationUnit struct {
	ParentID, SourceOwnerID string
	TreeGeneration          int64
	Digest                  string
	ObjectCount             int64
}

// NativeMigrationObject identifies existing ciphertext without carrying
// logical names, key material, or a storage read grant.
type NativeMigrationObject struct {
	ObjectID, NativeObjectID, Kind string
	BlobID, ReadAlias, SHA256      string
	Descriptor, SourceRevision     string
	Bytes                          int64
}

type nativeMigrationPlacement struct {
	object    NativeMigrationObject
	placement Placement
	index     string
	revision  int64
	class     int
}

// VisitNativeMigrationUnitWithLease observes all native audio or video files
// directly under one authenticated parent, including display-hidden files.
// Child directories have independent ownership units. The scan refuses an
// incomplete, empty, mixed, or unsettled roster. Visits are provisional until
// the complete digest is returned. The caller must discard the staged roster
// on error. The visitor must honor the bounded context and must not reenter
// the tree or its lease. A timeout does not authorize a partial unit.
// The coordinator must separately verify paired peers, storage bytes, capacity,
// and the current roster before admitting a task.
func (s *SQLStore) VisitNativeMigrationUnitWithLease(ctx context.Context, lease *TreeLease, parentID, sourceOwnerID string, visit func(context.Context, NativeMigrationObject) error) (NativeMigrationUnit, error) {
	if !s.valid() || ctx == nil || visit == nil || !hexID(parentID) || parentID == s.rootID || !lowerHex(sourceOwnerID, 32) {
		return NativeMigrationUnit{}, ErrInvalid
	}
	if lease == nil {
		return NativeMigrationUnit{}, ErrFenceRequired
	}
	ctx, cancel := context.WithTimeout(ctx, nativeMigrationUnitTimeout)
	defer cancel()
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return NativeMigrationUnit{}, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return NativeMigrationUnit{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return NativeMigrationUnit{}, err
	}
	defer tx.Rollback()
	unit, err := s.visitNativeMigrationUnitTx(ctx, tx, parentID, sourceOwnerID, func(c context.Context, current nativeMigrationPlacement) error {
		return visit(c, current.object)
	})
	if err != nil {
		if ctx.Err() != nil {
			return NativeMigrationUnit{}, ctx.Err()
		}
		return NativeMigrationUnit{}, err
	}
	if err = tx.Commit(); err != nil {
		return NativeMigrationUnit{}, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return NativeMigrationUnit{}, err
	}
	unit.TreeGeneration = lease.generation
	return unit, nil
}

func (s *SQLStore) visitNativeMigrationUnitTx(ctx context.Context, tx treeQuery, parentID, sourceOwnerID string, visit func(context.Context, nativeMigrationPlacement) error) (NativeMigrationUnit, error) {
	if err := s.verifyRoot(ctx, tx); err != nil {
		return NativeMigrationUnit{}, err
	}
	if err := s.requireListingReady(ctx, tx); err != nil {
		return NativeMigrationUnit{}, err
	}
	anchor, err := s.listingAncestorAnchor(ctx, tx, parentID, true)
	if err != nil {
		return NativeMigrationUnit{}, err
	}
	_, parent, err := s.recordByID(ctx, tx, parentID)
	if err != nil || parent.Kind != "directory" {
		return NativeMigrationUnit{}, ErrInvalid
	}
	parentPath, err := s.pathInTransaction(ctx, tx, parent)
	depth := strings.Count(parentPath, "/")
	if err != nil || depth < 1 || depth > 2 ||
		(!strings.HasPrefix(parentPath, "music/") && !strings.HasPrefix(parentPath, "vido/")) {
		return NativeMigrationUnit{}, ErrInvalid
	}
	unit := NativeMigrationUnit{ParentID: parentID, SourceOwnerID: sourceOwnerID}
	digest := s.listingMAC("native-migration-unit-scope", parentID, sourceOwnerID, anchor)
	err = s.scanDirectEntriesTx(ctx, tx, parentID, func(entry Entry, index string, pending *Placement) error {
		if pending != nil {
			return ErrRevocationPending
		}
		if entry.Kind == "directory" {
			return nil
		}
		if selectedMediaDeletionKind(parentPath+"/"+entry.Name) != entry.Kind {
			return ErrInvalid
		}
		facts, _, err := s.factsFor(ctx, tx, entry, index)
		if err != nil {
			return err
		}
		class := listingClass(&facts)
		if facts.Revocation != nil || class == listingInternal {
			return ErrRevocationPending
		}
		// A historical signed hide binds the original Owner and alias. It
		// needs an explicit rebind protocol before this unit can move.
		if facts.HiddenProof != nil {
			return ErrConflict
		}
		var entryRevision, placementRevision int64
		var revocations int
		if err = tx.QueryRowContext(ctx, `SELECT r.revision,p.revision,(SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=r.object_index)
			FROM sealed_tree_records r JOIN sealed_tree_placements p ON p.object_index=r.object_index WHERE r.object_index=?`, index).
			Scan(&entryRevision, &placementRevision, &revocations); err != nil || entryRevision <= 0 || placementRevision <= 0 {
			return ErrInvalid
		}
		if revocations != 0 {
			return ErrRevocationPending
		}
		placement, err := s.placementFor(ctx, tx, entry, index)
		// The canonical empty blob has no payload and no encryption descriptor.
		if err != nil || placement.State != "active" || placement.Encryption == nil && placement.Bytes != 0 {
			return ErrInvalid
		}
		if placement.OwnerID != sourceOwnerID {
			return ErrConflict
		}
		descriptor, err := protocol.IngressMediaDescriptor(placement.Bytes, placement.Encryption)
		if err != nil {
			return err
		}
		revision, err := protocol.OpaquePlacementRevisionFromDescriptor(placement.ReadAlias, placement.BlobID, placement.SHA256, descriptor, placement.Bytes)
		if err != nil {
			return err
		}
		object := NativeMigrationObject{
			ObjectID: entry.ObjectID, NativeObjectID: placement.NativeObjectID, Kind: entry.Kind,
			BlobID: placement.BlobID, ReadAlias: placement.ReadAlias, SHA256: placement.SHA256,
			Descriptor: descriptor, SourceRevision: revision, Bytes: placement.Bytes,
		}
		current := nativeMigrationPlacement{object: object, placement: placement, index: index, revision: placementRevision, class: class}
		if err := visit(ctx, current); err != nil {
			return err
		}
		unit.ObjectCount++
		// Playback, lyric, and display visibility updates can continue. The
		// coordinator must preserve the current facts at the ownership commit.
		digest = s.listingMAC("native-migration-unit-object", digest, entry.ObjectID, placement.NativeObjectID, entry.Kind, revision,
			strconv.FormatInt(entryRevision, 10), strconv.FormatInt(placementRevision, 10))
		return nil
	})
	if err != nil {
		return NativeMigrationUnit{}, err
	}
	if unit.ObjectCount == 0 {
		return NativeMigrationUnit{}, ErrConflict
	}
	unit.Digest = s.listingMAC("native-migration-unit-complete", digest, strconv.FormatInt(unit.ObjectCount, 10))
	return unit, nil
}
