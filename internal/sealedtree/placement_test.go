package sealedtree

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestPlacementProtectsOpaqueLocationAndContentSemantics(t *testing.T) {
	tree := fixture(t)
	metadata, err := mediacrypto.NewMetadata(1234)
	if err != nil {
		t.Fatal(err)
	}
	base := Placement{ObjectID: strings.Repeat("a", 64), NativeObjectID: strings.Repeat("e", 64), OwnerID: strings.Repeat("b", 32), BlobID: strings.Repeat("c", 64), ReadAlias: strings.Repeat("f", 64), Bytes: 1234, SHA256: strings.Repeat("d", 64)}
	for _, encrypted := range []bool{false, true} {
		p := base
		if encrypted {
			p.Encryption = &metadata
			p.Bytes = metadata.CiphertextSize
		}
		r, err := tree.SealPlacement(p, 1)
		if err != nil {
			t.Fatal(err)
		}
		got, err := tree.OpenPlacement(r)
		if err != nil || !reflect.DeepEqual(got, p) {
			t.Fatalf("placement round trip: %v", err)
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{p.ObjectID, p.NativeObjectID, p.OwnerID, p.BlobID, p.ReadAlias, p.SHA256} {
			if bytes.Contains(encoded, []byte(secret)) || bytes.Contains(r.Sealed, []byte(secret)) {
				t.Fatal("plaintext placement field persisted")
			}
		}
		if encrypted && bytes.Contains(encoded, []byte(metadata.FileID)) {
			t.Fatal("encryption descriptor leaked")
		}
		second, err := tree.SealPlacement(p, 1)
		if err != nil || bytes.Equal(r.Sealed, second.Sealed) || r.ObjectIndex != second.ObjectIndex || r.BlobIndex != second.BlobIndex {
			t.Fatal("placement ciphertext not randomized or indexes unstable")
		}
		firstID, _ := PlacementEncryptionID(r)
		secondID, _ := PlacementEncryptionID(second)
		if firstID == secondID {
			t.Fatal("placement reused encryption identity")
		}
	}
}

func TestPlacementRejectsCorruptionAndInvalidDescriptor(t *testing.T) {
	tree := fixture(t)
	p := Placement{ObjectID: strings.Repeat("a", 64), NativeObjectID: strings.Repeat("e", 64), OwnerID: strings.Repeat("b", 32), BlobID: strings.Repeat("c", 64), ReadAlias: strings.Repeat("f", 64), Bytes: 7, SHA256: strings.Repeat("d", 64)}
	r, err := tree.SealPlacement(p, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*PlacementRecord)
	}{
		{"object", func(v *PlacementRecord) { v.ObjectIndex = strings.Repeat("e", 64) }},
		{"blob", func(v *PlacementRecord) { v.BlobIndex = strings.Repeat("f", 64) }},
		{"revision", func(v *PlacementRecord) { v.Revision++ }},
		{"salt", func(v *PlacementRecord) { v.Sealed[1] ^= 1 }},
		{"nonce", func(v *PlacementRecord) { v.Sealed[1+recordSaltBytes] ^= 1 }},
		{"payload", func(v *PlacementRecord) { v.Sealed[len(v.Sealed)-1] ^= 1 }},
		{"truncated", func(v *PlacementRecord) { v.Sealed = v.Sealed[:2] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := r
			changed.Sealed = append([]byte(nil), r.Sealed...)
			tc.edit(&changed)
			if _, err := tree.OpenPlacement(changed); !errors.Is(err, ErrInvalid) {
				t.Fatal("tampered placement accepted")
			}
		})
	}
	metadata, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Placement{
		{ObjectID: p.ObjectID, NativeObjectID: p.NativeObjectID, OwnerID: p.OwnerID, BlobID: p.ObjectID, ReadAlias: p.ReadAlias, Bytes: 7, SHA256: p.SHA256},
		{ObjectID: p.ObjectID, NativeObjectID: p.NativeObjectID, OwnerID: p.OwnerID, BlobID: p.NativeObjectID, ReadAlias: p.ReadAlias, Bytes: 7, SHA256: p.SHA256},
		{ObjectID: p.ObjectID, NativeObjectID: p.NativeObjectID, OwnerID: p.OwnerID, BlobID: p.BlobID, ReadAlias: p.BlobID, Bytes: 7, SHA256: p.SHA256},
		{ObjectID: p.ObjectID, NativeObjectID: p.NativeObjectID, OwnerID: p.OwnerID, BlobID: p.BlobID, ReadAlias: p.ObjectID, Bytes: 7, SHA256: p.SHA256},
		{ObjectID: p.ObjectID, NativeObjectID: p.NativeObjectID, OwnerID: p.OwnerID, BlobID: p.BlobID, ReadAlias: p.NativeObjectID, Bytes: 7, SHA256: p.SHA256},
		{ObjectID: p.ObjectID, NativeObjectID: p.NativeObjectID, OwnerID: "bad", BlobID: p.BlobID, ReadAlias: p.ReadAlias, Bytes: 7, SHA256: p.SHA256},
		{ObjectID: p.ObjectID, NativeObjectID: p.NativeObjectID, OwnerID: p.OwnerID, BlobID: p.BlobID, ReadAlias: p.ReadAlias, Bytes: -1, SHA256: p.SHA256},
		{ObjectID: p.ObjectID, NativeObjectID: p.NativeObjectID, OwnerID: p.OwnerID, BlobID: p.BlobID, ReadAlias: p.ReadAlias, Bytes: 7, SHA256: p.SHA256, Encryption: &metadata},
	} {
		if _, err := tree.SealPlacement(bad, 1); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid placement accepted")
		}
	}
}
