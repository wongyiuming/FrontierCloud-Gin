package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestOpaqueCapacityReceiptBindsOwnerOperationAndCleanup(t *testing.T) {
	r := OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: strings.Repeat("1", 32), OwnerID: strings.Repeat("2", 32), RelationshipID: strings.Repeat("3", 32), RelationshipBinding: strings.Repeat("4", 64), Generation: strings.Repeat("5", 64), OperationID: strings.Repeat("6", 64), StageID: strings.Repeat("7", 64), BlobID: strings.Repeat("8", 64), Digest: strings.Repeat("9", 64), Challenge: strings.Repeat("a", 64), Bytes: 123, State: "published"}
	payload, err := r.Payload()
	if err != nil {
		t.Fatal(err)
	}
	private := Encode(bytes.Repeat([]byte{7}, 32))
	public, err := PublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := Sign(private, payload)
	if err != nil || Verify(public, payload, signature) != nil {
		t.Fatal("receipt signature", err)
	}
	for _, mutate := range []func(*OpaqueCapacityReceipt){
		func(v *OpaqueCapacityReceipt) { v.OwnerID = strings.Repeat("b", 32) },
		func(v *OpaqueCapacityReceipt) { v.RelationshipBinding = strings.Repeat("b", 64) },
		func(v *OpaqueCapacityReceipt) { v.Generation = strings.Repeat("b", 64) },
		func(v *OpaqueCapacityReceipt) { v.OperationID = strings.Repeat("b", 64) },
		func(v *OpaqueCapacityReceipt) { v.StageID = strings.Repeat("b", 64) },
		func(v *OpaqueCapacityReceipt) { v.BlobID = strings.Repeat("b", 64) },
		func(v *OpaqueCapacityReceipt) { v.Digest = strings.Repeat("b", 64) },
		func(v *OpaqueCapacityReceipt) { v.Challenge = strings.Repeat("b", 64) },
		func(v *OpaqueCapacityReceipt) { v.Bytes++ },
		func(v *OpaqueCapacityReceipt) { v.Kind = "opaque-capacity-cleaned-v1"; v.State = "cleaned" },
	} {
		changed := r
		mutate(&changed)
		p, err := changed.Payload()
		if err != nil || Verify(public, p, signature) == nil {
			t.Fatal("modified receipt reused signature", err)
		}
	}
	bad := r
	bad.StageID = bad.BlobID
	if _, err := bad.Payload(); err == nil {
		t.Fatal("aliased stage and blob accepted")
	}
	bad = r
	bad.OwnerID = bad.MasterID
	if _, err := bad.Payload(); err == nil {
		t.Fatal("local owner accepted peer relationship")
	}
	bad.RelationshipID, bad.RelationshipBinding = "", ""
	if _, err := bad.Payload(); err != nil {
		t.Fatal("correct local owner rejected", err)
	}
	bad = r
	bad.Kind = "opaque-capacity-cleaned-v1"
	if _, err := bad.Payload(); err == nil {
		t.Fatal("cleaned kind with published state accepted")
	}
}

func TestOpaqueCapacityReceiptZeroRequiresEmptyDigest(t *testing.T) {
	empty := sha256.Sum256(nil)
	r := OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: strings.Repeat("1", 32), OwnerID: strings.Repeat("1", 32), Generation: strings.Repeat("5", 64), OperationID: strings.Repeat("6", 64), StageID: strings.Repeat("7", 64), BlobID: strings.Repeat("8", 64), Digest: hex.EncodeToString(empty[:]), Challenge: strings.Repeat("a", 64), Bytes: 0, State: "published"}
	if _, err := r.Payload(); err != nil {
		t.Fatal("empty object rejected", err)
	}
	r.Digest = strings.Repeat("9", 64)
	if _, err := r.Payload(); err == nil {
		t.Fatal("nonempty digest accepted for empty object")
	}
	r.Bytes = -1
	if _, err := r.Payload(); err == nil {
		t.Fatal("negative size accepted")
	}
}

func TestOpaqueCapacityReceiptPlainSizeBoundary(t *testing.T) {
	r := OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: strings.Repeat("1", 32), OwnerID: strings.Repeat("1", 32), Generation: strings.Repeat("5", 64), OperationID: strings.Repeat("6", 64), StageID: strings.Repeat("7", 64), BlobID: strings.Repeat("8", 64), Digest: strings.Repeat("9", 64), Challenge: strings.Repeat("a", 64), Bytes: MaxOpaquePlainBytes, State: "published"}
	if _, err := r.Payload(); err != nil {
		t.Fatal("maximum size", err)
	}
	r.Bytes++
	if _, err := r.Payload(); err == nil {
		t.Fatal("oversized receipt accepted")
	}
}
