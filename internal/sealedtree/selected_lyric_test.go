package sealedtree

import (
	"strings"
	"testing"
)

func TestSelectedLyricPendingFactsRemainSealedUntilFinalize(t *testing.T) {
	id := strings.Repeat("a", 64)
	facts := Facts{ObjectID: id, PendingSelectedUpload: &SelectedUploadFact{UploadID: strings.Repeat("b", 32), AdminBinding: strings.Repeat("c", 64), Policy: "Local", Revision: 1}}
	lyric := Entry{ObjectID: id, Kind: "lyric"}
	if !factsCompatiblePending(lyric, facts) || factsCompatible(lyric, facts) {
		t.Fatal("lyric pending state escaped finalize")
	}
	if factsCompatiblePending(Entry{ObjectID: id, Kind: "directory"}, facts) {
		t.Fatal("directory accepted file pending state")
	}
	tree := fixture(t)
	record, err := tree.SealFacts(facts, 1)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := tree.OpenFacts(record)
	if err != nil || opened.PendingSelectedUpload == nil || *opened.PendingSelectedUpload != *facts.PendingSelectedUpload {
		t.Fatal("pending facts did not survive authenticated sealing", err)
	}
}
