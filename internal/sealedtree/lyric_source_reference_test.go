package sealedtree

import (
	"bytes"
	"strings"
	"testing"
)

func TestSourceLyricReferenceIsSealedAndBindsDecision(t *testing.T) {
	tree := fixture(t)
	id, source, generation := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	evidence, err := LyricResolutionEvidence(source, generation, id, "none", "")
	if err != nil {
		t.Fatal(err)
	}
	facts := Facts{ObjectID: id, LyricResolution: &LyricResolutionFact{State: "none", Evidence: evidence, SourceDigest: source, SourceGeneration: generation}}
	record, err := tree.SealFacts(facts, 1)
	if err != nil || bytes.Contains(record.Sealed, []byte(source)) || bytes.Contains(record.Sealed, []byte(generation)) {
		t.Fatal("source reference not sealed", err)
	}
	opened, err := tree.OpenFacts(record)
	if err != nil || opened.LyricResolution.SourceDigest != source || opened.LyricResolution.SourceGeneration != generation {
		t.Fatal("source reference lost", err)
	}
	for _, change := range []func(*LyricResolutionFact){func(r *LyricResolutionFact) { r.SourceDigest = strings.Repeat("d", 64) }, func(r *LyricResolutionFact) { r.SourceGeneration = strings.Repeat("e", 64) }, func(r *LyricResolutionFact) { r.SourceGeneration = "" }, func(r *LyricResolutionFact) { r.Evidence = strings.Repeat("f", 64) }} {
		altered := *facts.LyricResolution
		change(&altered)
		if _, err = tree.SealFacts(Facts{ObjectID: id, LyricResolution: &altered}, 1); err == nil {
			t.Fatal("unbound source reference accepted")
		}
	}
	// Existing records without source references remain readable, but their
	// evidence digest alone remains insufficient for runtime authorization.
	legacy := *facts.LyricResolution
	legacy.SourceDigest, legacy.SourceGeneration = "", ""
	if _, err = tree.SealFacts(Facts{ObjectID: id, LyricResolution: &legacy}, 1); err != nil {
		t.Fatal("legacy facts rejected", err)
	}
}
