package media

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func opaqueAdminS3DownloadEntry(resourceID, name, kind string, p sealedtree.S3Placement, revision int64) (OpaqueAdminDownloadEntry, error) {
	if (kind != "audio" && kind != "video") || !managedObject(name, false) || p.ObjectID != resourceID || revision < 1 ||
		p.Encryption == nil || p.Encryption.Validate() != nil || p.Encryption.CiphertextSize != p.Proof.Bytes {
		return OpaqueAdminDownloadEntry{}, sealedtree.ErrConflict
	}
	// Keep provider keys and location private. Only the digest of the complete
	// authenticated placement and revision leaves Master in the Admin plan.
	value, err := json.Marshal([]any{revision, p})
	if err != nil {
		return OpaqueAdminDownloadEntry{}, sealedtree.ErrConflict
	}
	defer clear(value)
	return OpaqueAdminDownloadEntry{Path: name, ResourceID: resourceID, Filename: DownloadFilename(name),
		Snapshot: downloadSnapshot(resourceID, name, p.Proof.Bytes, string(value)), Encryption: *p.Encryption,
		Transport: "S3", ObjectID: p.Proof.ObjectID, s3: &p}, nil
}

// OpaqueAdminS3ReadSource requires the dedicated Admin CORS proof under the
// existing S3 recovery/configuration gate and authenticated Admin read fence.
// Browser bytes go directly to the provider.
func (s *Service) OpaqueAdminS3ReadSource(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, item OpaqueAdminDownloadEntry, origin string, deadline int64) (s3media.SourceGrant, error) {
	var empty s3media.SourceGrant
	if s == nil || tree == nil || lease == nil || item.s3 == nil || s.opaqueS3ReadTree != tree || s.opaqueS3ReadGate == nil || lease.Check(ctx) != nil ||
		deadline <= time.Now().Unix() || deadline > time.Now().Unix()+store.S3GrantSeconds {
		return empty, ErrUnavailable
	}
	gate, ok := s.opaqueS3ReadGate.(interface {
		CheckSelectedS3AdminOrigin(context.Context, *sealedtree.SQLStore, store.S3Member, string) error
	})
	repo, hasRepo := s.pool.(interface {
		S3Member(context.Context, string) (store.S3Member, error)
	})
	signer, hasSigner := s.s3.(interface {
		SelectedReadSource(context.Context, store.S3Member, store.S3ObjectProof, int64, func(context.Context) error) (s3media.SourceGrant, error)
	})
	if !ok || !hasRepo || !hasSigner {
		return empty, ErrUnavailable
	}
	placement := *item.s3
	member, err := repo.S3Member(ctx, placement.MemberID)
	location := s3store.Config{Endpoint: member.Location.Endpoint, Bucket: member.Location.Bucket, Region: member.Location.Region, Prefix: member.Location.Prefix, AddressStyle: member.Location.Style}
	if err != nil || !placement.MatchesCurrentMember(member.ID, location) || gate.CheckSelectedS3AdminOrigin(ctx, tree, member, origin) != nil ||
		s.opaqueS3ReadGate.AuthorizeSelectedS3Read(ctx, tree, member, deadline) != nil {
		return empty, ErrUnavailable
	}
	check := func(c context.Context) error {
		current, e := repo.S3Member(c, member.ID)
		if e != nil || !reflect.DeepEqual(current, member) || lease.Check(c) != nil ||
			gate.CheckSelectedS3AdminOrigin(c, tree, member, origin) != nil || s.opaqueS3ReadGate.CheckSelectedS3Read(c, tree, member, deadline) != nil {
			return ErrUnavailable
		}
		return nil
	}
	signCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	grant, err := signer.SelectedReadSource(signCtx, member, placement.Proof, deadline, check)
	if err != nil || grant.ObjectID != placement.Proof.ObjectID || grant.SizeBytes != placement.Proof.Bytes || check(ctx) != nil {
		return empty, ErrUnavailable
	}
	return grant, nil
}
