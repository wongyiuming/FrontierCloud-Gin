package node

import (
	"bytes"
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

// VerifyLegacyOwnerImportReceipt verifies only the exact Owner signature and
// previously authenticated pairing scope. It does not establish current Owner
// fence state. The caller must consume a durable Master intent and freshly
// reconcile Owner state under its real fences before publishing placement.
func (s *Service) VerifyLegacyOwnerImportReceipt(ctx context.Context, plan protocol.LegacyOwnerImportPlan, enrollment protocol.LegacyReadEnrollmentReceipt, enrollmentSigned, receipt Envelope, expectedMasterRelationshipBinding string) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.VerifyLegacyReadEnrollment(ctx, enrollment, enrollmentSigned) != nil || enrollment.MasterID != plan.MasterID || enrollment.OwnerID != plan.OwnerID || enrollment.RelationshipID != plan.RelationshipID || enrollment.RelationshipBinding != plan.RelationshipBinding || enrollment.OwnerBinding != plan.OwnerBinding || enrollment.FenceBinding != plan.FenceBinding {
		return ErrCapability
	}
	expected, err := plan.PublishedReceipt()
	if err != nil {
		return ErrCapability
	}
	got, err := protocol.Canonical(receipt.Payload)
	if err != nil {
		return ErrCapability
	}
	want, err := protocol.Canonical(expected)
	if err != nil || !bytes.Equal(got, want) {
		return ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, plan.RelationshipID)
	if err != nil || !resourceIdentifier.MatchString(expectedMasterRelationshipBinding) || opaqueRelationshipBinding(relation) != expectedMasterRelationshipBinding || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version || relation.PeerID != plan.OwnerID || protocol.Verify(relation.PublicKey, receipt.Payload, receipt.Signature) != nil || ctx.Err() != nil {
		return ErrCapability
	}
	return nil
}
