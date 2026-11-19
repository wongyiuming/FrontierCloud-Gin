//go:build linux

package sealedtree

import (
	"context"
	"strings"
	"testing"
)

// This isolates only the tree-keyed read check; it does not attest that the
// synthetic input was accepted by a real import transaction.
func TestSourceCatalogAttestationRequiresRealTreeFence(t *testing.T) {
	ctx := context.Background()
	_, tree, _, _, _ := fencedFixture(t)
	id, source, generation := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	evidence, err := LyricResolutionEvidence(source, generation, id, "none", "")
	if err != nil {
		t.Fatal(err)
	}
	facts := Facts{ObjectID: id, LyricResolution: &LyricResolutionFact{State: "none", Evidence: evidence, SourceDigest: source, SourceGeneration: generation}}
	entry := Entry{ParentID: tree.rootID, ObjectID: id, Kind: "audio", Name: "a.mp3"}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	page := []CatalogItem{{Entry: entry, Facts: facts}}
	if tree.VerifyCatalogLyricFactsWithLease(ctx, lease, page) == nil {
		t.Fatal("unattested source accepted")
	}
	unattestedRecord, err := tree.tree.SealFacts(facts, 1)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tree.sourceLyricAttestation(facts)
	if err != nil {
		t.Fatal(err)
	}
	facts.LyricResolution.SourceProof = proof
	attestedRecord, err := tree.tree.SealFacts(facts, 1)
	if err != nil || len(attestedRecord.Sealed) != len(unattestedRecord.Sealed) {
		t.Fatal("source proof changed fixed facts record size", err)
	}
	page[0].Facts = facts
	if err := tree.VerifyCatalogLyricFactsWithLease(ctx, lease, page); err != nil {
		t.Fatal("valid tree-keyed test proof", err)
	}
	if tree.VerifyNativeCatalogLyricFactsWithLease(ctx, lease, page) == nil {
		t.Fatal("source classified as native")
	}
	altered := *facts.LyricResolution
	altered.SourceProof = strings.Repeat("0", 64)
	page[0].Facts.LyricResolution = &altered
	if tree.VerifyCatalogLyricFactsWithLease(ctx, lease, page) == nil {
		t.Fatal("forged source attestation accepted")
	}
	lease.Release()
	page[0].Facts = facts
	if tree.VerifyCatalogLyricFactsWithLease(ctx, lease, page) == nil {
		t.Fatal("released tree fence accepted")
	}
}
