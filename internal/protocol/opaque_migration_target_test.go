package protocol

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func opaqueMigrationTargetFixture(t *testing.T, plaintextSize int64) OpaqueMigrationTargetReceipt {
	t.Helper()
	size, digest := int64(0), emptyOpaqueSHA256
	var meta *mediacrypto.Metadata
	if plaintextSize != 0 {
		value, err := mediacrypto.NewMetadata(plaintextSize)
		if err != nil {
			t.Fatal(err)
		}
		meta, size, digest = &value, value.CiphertextSize, strings.Repeat("a", 64)
	}
	descriptor, err := IngressMediaDescriptor(size, meta)
	if err != nil {
		t.Fatal(err)
	}
	owner := func(id, relationship, alias, blob string) OpaqueOwnerBinding {
		return OpaqueOwnerBinding{
			MasterID: strings.Repeat("1", 32), OwnerID: strings.Repeat(id, 32), RelationshipID: strings.Repeat(relationship, 32),
			Alias: strings.Repeat(alias, 64), Blob: strings.Repeat(blob, 64), Size: size, Descriptor: descriptor, Digest: digest,
		}
	}
	receipt := OpaqueMigrationTargetReceipt{
		TaskID: strings.Repeat("6", 32), UnitID: strings.Repeat("1", 64), PublicationOperation: strings.Repeat("2", 64), Challenge: strings.Repeat("3", 64),
		SourceRelationshipBinding: strings.Repeat("4", 64), TargetRelationshipBinding: strings.Repeat("5", 64),
		Source: owner("2", "4", "6", "7"), Target: owner("3", "5", "8", "9"),
	}
	refreshMigrationFixtureRevisions(t, &receipt)
	return receipt
}

func refreshMigrationFixtureRevisions(t *testing.T, receipt *OpaqueMigrationTargetReceipt) {
	t.Helper()
	for _, binding := range []*OpaqueOwnerBinding{&receipt.Source, &receipt.Target} {
		revision, err := OpaquePlacementRevisionFromDescriptor(binding.Alias, binding.Blob, binding.Digest, binding.Descriptor, binding.Size)
		if err != nil {
			t.Fatal(err)
		}
		binding.Revision = revision
	}
}

func TestOpaqueMigrationTargetReceiptAuthenticatesExactTargetAndChallenge(t *testing.T) {
	receipt := opaqueMigrationTargetFixture(t, 17)
	private := Encode(bytes.Repeat([]byte{7}, 32))
	public, err := PublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	sourcePublic, err := PublicKey(Encode(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	sign := func(value OpaqueMigrationTargetReceipt) string {
		t.Helper()
		payload, err := value.Payload()
		if err != nil {
			t.Fatal(err)
		}
		signature, err := Sign(private, payload)
		if err != nil {
			t.Fatal(err)
		}
		return signature
	}
	signature := sign(receipt)
	if VerifyOpaqueMigrationTargetReceipt(public, receipt, receipt, signature) != nil {
		t.Fatal("valid target receipt rejected")
	}
	if VerifyOpaqueMigrationTargetReceipt(sourcePublic, receipt, receipt, signature) == nil {
		t.Fatal("different owner's key accepted")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*OpaqueMigrationTargetReceipt)
	}{
		{"task", func(r *OpaqueMigrationTargetReceipt) { r.TaskID = strings.Repeat("e", 32) }},
		{"unit", func(r *OpaqueMigrationTargetReceipt) { r.UnitID = strings.Repeat("e", 64) }},
		{"publication", func(r *OpaqueMigrationTargetReceipt) { r.PublicationOperation = strings.Repeat("e", 64) }},
		{"challenge", func(r *OpaqueMigrationTargetReceipt) { r.Challenge = strings.Repeat("e", 64) }},
		{"source relationship", func(r *OpaqueMigrationTargetReceipt) { r.Source.RelationshipID = strings.Repeat("e", 32) }},
		{"target relationship", func(r *OpaqueMigrationTargetReceipt) { r.Target.RelationshipID = strings.Repeat("e", 32) }},
		{"source relationship binding", func(r *OpaqueMigrationTargetReceipt) { r.SourceRelationshipBinding = strings.Repeat("e", 64) }},
		{"target relationship binding", func(r *OpaqueMigrationTargetReceipt) { r.TargetRelationshipBinding = strings.Repeat("e", 64) }},
		{"source locator", func(r *OpaqueMigrationTargetReceipt) { r.Source.Alias = strings.Repeat("e", 64) }},
		{"target locator", func(r *OpaqueMigrationTargetReceipt) { r.Target.Blob = strings.Repeat("e", 64) }},
		{"digest", func(r *OpaqueMigrationTargetReceipt) {
			r.Source.Digest, r.Target.Digest = strings.Repeat("e", 64), strings.Repeat("e", 64)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := receipt
			tc.mutate(&changed)
			refreshMigrationFixtureRevisions(t, &changed)
			if VerifyOpaqueMigrationTargetReceipt(public, changed, changed, signature) == nil {
				t.Fatal("the old signature authenticated changed facts")
			}
			if VerifyOpaqueMigrationTargetReceipt(public, receipt, changed, sign(changed)) == nil {
				t.Fatal("a valid signature on another receipt bypassed the expected binding")
			}
		})
	}
}

func TestOpaqueMigrationTargetReceiptRejectsInvalidBindings(t *testing.T) {
	fixture := opaqueMigrationTargetFixture(t, 17)
	plain, err := IngressMediaDescriptor(fixture.Source.Size, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*OpaqueMigrationTargetReceipt)
	}{
		{"source Master", func(r *OpaqueMigrationTargetReceipt) { r.Source.OwnerID = r.Source.MasterID }},
		{"target Master", func(r *OpaqueMigrationTargetReceipt) { r.Target.OwnerID = r.Target.MasterID }},
		{"different Masters", func(r *OpaqueMigrationTargetReceipt) { r.Target.MasterID = strings.Repeat("e", 32) }},
		{"same owners", func(r *OpaqueMigrationTargetReceipt) { r.Target.OwnerID = r.Source.OwnerID }},
		{"same relationship", func(r *OpaqueMigrationTargetReceipt) { r.Target.RelationshipID = r.Source.RelationshipID }},
		{"same relationship binding", func(r *OpaqueMigrationTargetReceipt) { r.TargetRelationshipBinding = r.SourceRelationshipBinding }},
		{"same alias", func(r *OpaqueMigrationTargetReceipt) { r.Target.Alias = r.Source.Alias }},
		{"same blob", func(r *OpaqueMigrationTargetReceipt) { r.Target.Blob = r.Source.Blob }},
		{"cross locator collision", func(r *OpaqueMigrationTargetReceipt) { r.Target.Blob = r.Source.Alias }},
		{"operation collision", func(r *OpaqueMigrationTargetReceipt) { r.PublicationOperation = r.Target.Blob }},
		{"challenge collision", func(r *OpaqueMigrationTargetReceipt) { r.Challenge = r.UnitID }},
		{"invalid challenge", func(r *OpaqueMigrationTargetReceipt) { r.Challenge = "" }},
		{"different digest", func(r *OpaqueMigrationTargetReceipt) { r.Target.Digest = strings.Repeat("e", 64) }},
		{"different size", func(r *OpaqueMigrationTargetReceipt) { r.Target.Size++ }},
		{"different descriptor", func(r *OpaqueMigrationTargetReceipt) { r.Target.Descriptor = strings.Repeat("e", 64) }},
		{"plaintext", func(r *OpaqueMigrationTargetReceipt) { r.Source.Descriptor, r.Target.Descriptor = plain, plain }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt := fixture
			tc.mutate(&receipt)
			refreshMigrationFixtureRevisions(t, &receipt)
			if _, err := receipt.Payload(); err == nil {
				t.Fatal("invalid target receipt accepted")
			}
		})
	}
}

func TestOpaqueMigrationTargetReceiptAdmitsCanonicalEmptyBinding(t *testing.T) {
	receipt := opaqueMigrationTargetFixture(t, 0)
	if _, err := receipt.Payload(); err != nil {
		t.Fatal("canonical empty target receipt rejected", err)
	}
	receipt.Source.Digest, receipt.Target.Digest = strings.Repeat("e", 64), strings.Repeat("e", 64)
	if _, err := receipt.Payload(); err == nil {
		t.Fatal("noncanonical empty target receipt accepted")
	}
}
