package merkleindex

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestBindingCoversIdentityVersionAndContent(t *testing.T) {
	b := Binding{
		MasterID: strings.Repeat("1", 32), OwnerID: strings.Repeat("2", 32), RelationshipID: strings.Repeat("3", 32),
		Alias: strings.Repeat("4", 64), Blob: strings.Repeat("5", 64), BasePlacementRevision: strings.Repeat("6", 64),
		Manifest: Manifest{Size: 1, ContentSHA256: sha256.Sum256([]byte("a")), Root: sha256.Sum256([]byte("root")), Version: sha256.Sum256([]byte("version"))},
	}
	baseline, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// Independently computed using Node's crypto and Buffer big-endian encoding.
	if got := fmt.Sprintf("%x", baseline); got != "8fb148e79435a2725766791c8d4353e7662f6da65174b37dfd648780f1a3172f" {
		t.Fatal("binding interoperability vector", got)
	}
	revision, err := b.AuthorizationRevision()
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Binding){
		func(v *Binding) { v.MasterID = strings.Repeat("7", 32) },
		func(v *Binding) { v.OwnerID = strings.Repeat("7", 32) },
		func(v *Binding) { v.RelationshipID = strings.Repeat("7", 32) },
		func(v *Binding) { v.Alias = strings.Repeat("7", 64) },
		func(v *Binding) { v.Blob = strings.Repeat("7", 64) },
		func(v *Binding) { v.BasePlacementRevision = strings.Repeat("7", 64) },
		func(v *Binding) { v.Manifest.Size++ },
		func(v *Binding) { v.Manifest.ContentSHA256[0] ^= 1 },
		func(v *Binding) { v.Manifest.Root[0] ^= 1 },
		func(v *Binding) { v.Manifest.Version[0] ^= 1 },
	}
	for i, mutate := range mutations {
		other := b
		mutate(&other)
		got, err := other.Digest()
		if err != nil || got == baseline {
			t.Fatalf("binding %d not covered: %v", i, err)
		}
		otherRevision, err := other.AuthorizationRevision()
		if err != nil || otherRevision == revision {
			t.Fatalf("revision %d not covered: %v", i, err)
		}
	}
	self := b
	self.OwnerID, self.RelationshipID = self.MasterID, ""
	if _, err := self.Digest(); err != nil {
		t.Fatal("Master local", err)
	}
	self.RelationshipID = b.RelationshipID
	if _, err := self.Digest(); err == nil {
		t.Fatal("fictitious local relationship accepted")
	}
	b.RelationshipID = ""
	if _, err := b.Digest(); err == nil {
		t.Fatal("missing follower relationship accepted")
	}
}
