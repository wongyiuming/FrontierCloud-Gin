package s3media

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// VerifyRetainedS3Member proves both exact-version HEAD metadata and reverse
// inventory using one credential-bound client. expected is the complete
// authenticated placement set for one member. The caller must continuously
// hold the recovery and configuration fences, prove pending provider work
// settled, and use check to revalidate independent provider writer stability.
// A successful result does not attest to a full plaintext or ciphertext hash.
func (s *Service) VerifyRetainedS3Member(ctx context.Context, member store.S3Member, expected []sealedtree.S3Placement, check func(context.Context) error) (RetainedS3InventoryObservation, error) {
	var empty RetainedS3InventoryObservation
	if len(expected) == 0 || len(expected) > s3store.MaxManagedObjectVersions {
		return empty, ErrProof
	}
	if ctx == nil || ctx.Err() != nil || check == nil {
		return empty, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if s.master(ctx) != nil {
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
	for _, placement := range expected {
		if ctx.Err() != nil {
			return empty, ErrUnavailable
		}
		id, valid := retainedS3PlacementID(current, placement)
		if !valid {
			return empty, ErrProof
		}
		if _, duplicate := byKey[placement.Proof.Key]; duplicate {
			return empty, ErrProof
		}
		if _, duplicate := objects[placement.ObjectID]; duplicate {
			return empty, ErrProof
		}
		byKey[placement.Proof.Key] = RetainedS3ObjectObservation{PhysicalObjectID: id}
		objects[placement.ObjectID] = struct{}{}
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
	for _, placement := range expected {
		if err = guard(ctx); err != nil {
			return empty, err
		}
		key := placement.Proof.Key
		observed, err := observeRetainedS3Object(ctx, provider, current, placement, byKey[key].PhysicalObjectID)
		if err != nil {
			return empty, err
		}
		byKey[key] = observed
	}
	if err = guard(ctx); err != nil {
		return empty, err
	}
	return verifyRetainedS3VersionSet(ctx, lister, current, byKey, guard)
}
