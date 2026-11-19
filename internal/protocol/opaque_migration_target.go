package protocol

import "errors"

var errOpaqueMigrationTargetReceipt = errors.New("invalid opaque migration target receipt")

// OpaqueMigrationTargetReceipt attests durable ciphertext and an installed
// read binding on the target. It carries no logical path, media ID, or key.
// Anchor retirement and Master ownership commit require separate evidence.
type OpaqueMigrationTargetReceipt struct {
	TaskID                    string             `json:"task_id"`
	UnitID                    string             `json:"unit_id"`
	PublicationOperation      string             `json:"publication_operation"`
	Challenge                 string             `json:"challenge"`
	SourceRelationshipBinding string             `json:"source_relationship_binding"`
	TargetRelationshipBinding string             `json:"target_relationship_binding"`
	Source                    OpaqueOwnerBinding `json:"source"`
	Target                    OpaqueOwnerBinding `json:"target"`
}

// Payload is the domain-separated input signed by the target after its
// publication and local registry are durable for the exact target binding.
func (r OpaqueMigrationTargetReceipt) Payload() (map[string]any, error) {
	source, target := r.Source, r.Target
	if !identifier.MatchString(r.TaskID) || !objectID.MatchString(r.UnitID) ||
		!objectID.MatchString(r.PublicationOperation) || !objectID.MatchString(r.Challenge) ||
		!objectID.MatchString(r.SourceRelationshipBinding) || !objectID.MatchString(r.TargetRelationshipBinding) ||
		r.SourceRelationshipBinding == r.TargetRelationshipBinding || !source.Valid() || !target.Valid() ||
		source.MasterID != target.MasterID || source.OwnerID == source.MasterID || target.OwnerID == target.MasterID ||
		source.OwnerID == target.OwnerID || source.RelationshipID == target.RelationshipID ||
		source.Size != target.Size || source.Digest != target.Digest || source.Descriptor != target.Descriptor {
		return nil, errOpaqueMigrationTargetReceipt
	}
	if source.Size > 0 {
		plain, err := IngressMediaDescriptor(source.Size, nil)
		if err != nil || source.Descriptor == plain {
			return nil, errOpaqueMigrationTargetReceipt
		}
	}
	seen := make(map[string]bool, 7)
	for _, id := range []string{r.UnitID, r.PublicationOperation, r.Challenge, source.Alias, source.Blob, target.Alias, target.Blob} {
		if seen[id] {
			return nil, errOpaqueMigrationTargetReceipt
		}
		seen[id] = true
	}
	return map[string]any{
		"kind": "opaque-migration-target-published-v1", "task_id": r.TaskID, "unit_id": r.UnitID,
		"publication_operation": r.PublicationOperation, "challenge": r.Challenge,
		"source_relationship_binding": r.SourceRelationshipBinding, "target_relationship_binding": r.TargetRelationshipBinding,
		"source": opaqueMigrationOwnerPayload(source), "target": opaqueMigrationOwnerPayload(target),
	}, nil
}

func opaqueMigrationOwnerPayload(b OpaqueOwnerBinding) map[string]any {
	return map[string]any{
		"master_id": b.MasterID, "owner_id": b.OwnerID, "relationship_id": b.RelationshipID,
		"alias": b.Alias, "blob": b.Blob, "revision": b.Revision, "digest": b.Digest,
		"descriptor": b.Descriptor, "size": b.Size,
	}
}

// VerifyOpaqueMigrationTargetReceipt checks a receipt against the complete
// expected binding and the independently pinned target public key. The
// caller authenticates both current relationships and owns persistence,
// expiry and one-time consumption of the expected challenge.
func VerifyOpaqueMigrationTargetReceipt(targetPublic string, expected, actual OpaqueMigrationTargetReceipt, signature string) error {
	if actual != expected {
		return errOpaqueMigrationTargetReceipt
	}
	payload, err := actual.Payload()
	if err != nil || Verify(targetPublic, payload, signature) != nil {
		return errOpaqueMigrationTargetReceipt
	}
	return nil
}
