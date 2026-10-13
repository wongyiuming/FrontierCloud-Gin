package store_test

import (
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
)

func TestMigrationSequenceMatchesExistingReceiptsAndRejectsReorderedPages(t *testing.T) {
	var sequence store.MigrationSequence
	empty, e := store.MigrationUnitObjectsSHA(nil)
	if e != nil || empty != sequence.Sum() {
		t.Fatal("empty wire compatibility", e)
	}
	objects := []store.MigrationPeerObject{}
	for i := range 3 {
		id := fmt.Sprintf("%064x", i+1)
		o := store.MigrationPeerObject{Object: store.MigrationObject{ID: id, Resource: "media", Bytes: 1}, Proof: store.MigrationDiskProof{ID: id, Bytes: 1}}
		objects = append(objects, o)
		if e = sequence.Add(id, o); e != nil {
			t.Fatal(e)
		}
		if sequence.Sum() != sequence.Sum() {
			t.Fatal("Sum mutated state")
		}
	}
	expected, e := store.MigrationUnitObjectsSHA(objects)
	if e != nil || expected != sequence.Sum() {
		t.Fatal("existing peer grant digest changed", expected, sequence.Sum(), e)
	}
	before := sequence.Sum()
	if e = sequence.Add(objects[2].Object.ID, objects[2]); e == nil || sequence.Sum() != before {
		t.Fatal("duplicate/reordered page accepted")
	}
}

func TestMigrationSequenceStreamsBeyondLegacyJSONLimit(t *testing.T) {
	var sequence store.MigrationSequence
	const count = 18000
	for i := range count {
		id := fmt.Sprintf("%064x", i+1)
		if e := sequence.Add(id, store.MigrationObject{ID: id, Path: strings.Repeat("x", 1024), TargetPath: strings.Repeat("x", 1024), Bytes: 1}); e != nil {
			t.Fatal(i, e)
		}
	}
	if sequence.Count() != count || len(sequence.Sum()) != 64 {
		t.Fatal("large streaming manifest", sequence.Count())
	}
}
