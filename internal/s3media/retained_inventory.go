package s3media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RetainedS3InventoryObservation commits to the complete observed version set
// in the configured objects/ prefix. It contains no provider paths or secrets.
type RetainedS3InventoryObservation struct {
	MemberID           string
	MemberRevision     int64
	CredentialRevision int64
	Objects            int
	StoredBytes        int64
	SetCommitment      string
}

// VerifyRetainedS3Inventory requires the complete set of authenticated HEAD
// observations for one member, obtained under the same continuously held
// recovery and configuration fences. check must also revalidate the caller's
// independent authority for provider writer and lifecycle stability. The scan
// does not freeze S3 or prove pending multipart/probe journals settled.
// Empty sets lack versioning evidence and are deliberately refused.
func (s *Service) VerifyRetainedS3Inventory(ctx context.Context, member store.S3Member, expected []RetainedS3ObjectObservation, check func(context.Context) error) (RetainedS3InventoryObservation, error) {
	var empty RetainedS3InventoryObservation
	if len(expected) == 0 || len(expected) > s3store.MaxManagedObjectVersions {
		return empty, ErrProof
	}
	if ctx == nil || ctx.Err() != nil || check == nil || s.master(ctx) != nil {
		return empty, ErrUnavailable
	}
	current, err := s.selectedReadMember(ctx, member)
	if err != nil {
		return empty, ErrUnavailable
	}
	guard := func(c context.Context) error {
		return s.checkRetainedS3Member(c, member, check)
	}
	if err = guard(ctx); err != nil {
		return empty, err
	}
	byKey := make(map[string]RetainedS3ObjectObservation, len(expected))
	objects := make(map[string]struct{}, len(expected))
	for _, item := range expected {
		if item.MemberID != current.ID || item.MemberRevision != current.Revision || item.CredentialRevision != current.CredentialRevision ||
			item.ObjectRevision < 1 || len(item.ObjectID) != 64 || len(item.PhysicalObjectID) != 64 || item.StoredBytes < 1 || item.StoredBytes > store.S3MaxObjectBytes ||
			item.VersionID == "" || item.VersionID == "null" || item.ETag == "" || item.ChecksumType != "COMPOSITE" || item.CompositeSHA256 == "" {
			return empty, ErrProof
		}
		id := item.PhysicalObjectID
		key := "objects/" + id[:2] + "/" + id[2:4] + "/" + id + ".blob"
		if _, opaque := store.S3OpaqueOwner(key); !opaque {
			return empty, ErrProof
		}
		if _, duplicate := byKey[key]; duplicate {
			return empty, ErrProof
		}
		if _, duplicate := objects[item.ObjectID]; duplicate {
			return empty, ErrProof
		}
		byKey[key] = item
		objects[item.ObjectID] = struct{}{}
	}
	provider, closeProvider, err := s.provider(current)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer closeProvider()
	lister, ok := provider.(s3store.ManagedObjectVersionLister)
	if !ok {
		return empty, ErrUnavailable
	}
	return verifyRetainedS3VersionSet(ctx, lister, current, byKey, guard)
}

func (s *Service) checkRetainedS3Member(ctx context.Context, member store.S3Member, check func(context.Context) error) error {
	if ctx.Err() != nil || check(ctx) != nil {
		return ErrUnavailable
	}
	if _, err := s.selectedReadMember(ctx, member); err != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

func verifyRetainedS3VersionSet(ctx context.Context, lister s3store.ManagedObjectVersionLister, current store.S3Member, byKey map[string]RetainedS3ObjectObservation, guard func(context.Context) error) (RetainedS3InventoryObservation, error) {
	var empty RetainedS3InventoryObservation
	count := len(byKey)
	hash := sha256.New()
	hash.Write([]byte("frontiercloud:retained-s3-version-inventory:v1\x00"))
	var bytes int64
	lastKey := ""
	err := lister.VisitManagedObjectVersions(ctx, count, guard, func(version s3store.ManagedObjectVersion) error {
		item, found := byKey[version.Key]
		if !found || version.Key <= lastKey || item.VersionID != version.VersionID || item.ETag != version.ETag || item.StoredBytes != version.Size {
			return ErrProof
		}
		fmt.Fprintf(hash, "%s\x00%s\x00%s\x00%d\x00", item.PhysicalObjectID, version.VersionID, version.ETag, version.Size)
		lastKey = version.Key
		bytes += version.Size
		delete(byKey, version.Key)
		return nil
	})
	if errors.Is(err, ErrProof) || errors.Is(err, s3store.ErrResponse) || errors.Is(err, s3store.ErrIncomplete) {
		return empty, ErrProof
	}
	if err != nil || guard(ctx) != nil {
		return empty, ErrUnavailable
	}
	if len(byKey) != 0 {
		return empty, ErrProof
	}
	return RetainedS3InventoryObservation{
		MemberID: current.ID, MemberRevision: current.Revision, CredentialRevision: current.CredentialRevision,
		Objects: count, StoredBytes: bytes, SetCommitment: hex.EncodeToString(hash.Sum(nil)),
	}, nil
}
