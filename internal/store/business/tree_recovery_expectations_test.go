package business

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestRecoveryExpectationCollectorBoundsAndNativeIdentities(t *testing.T) {
	collector := recoveryExpectationCollector{owners: make(map[string]*RecoveryOwnerExpectation), locators: make(map[string]struct{})}
	owner := strings.Repeat("1", 32)
	native := sealedtree.RecoveryMediaPlacement{ObjectID: strings.Repeat("1", 64), OwnerID: owner, Kind: "lyric", BlobID: strings.Repeat("2", 64), ReadAlias: strings.Repeat("3", 64), Bytes: 10, AliasRevoked: true, AliasRevocationOperationID: strings.Repeat("a", 32)}
	if err := collector.addMedia(native); err != nil {
		t.Fatal(err)
	}
	recording := RecoveryRecordingPlacement{RecordingID: strings.Repeat("2", 32), OwnerID: owner, BlobID: strings.Repeat("4", 64), SHA256: strings.Repeat("5", 64), ReadAlias: strings.Repeat("6", 64), AliasRevision: strings.Repeat("7", 64), Descriptor: strings.Repeat("8", 64), Bytes: 12}
	if err := collector.addRecording(recording); err != nil {
		t.Fatal(err)
	}
	group := collector.owner(owner)
	if len(group.Media) != 1 || group.Media[0] != native || len(group.Recordings) != 1 {
		t.Fatal("native media or recording was not grouped")
	}
	if got := group.Recordings[0]; got.Kind != "recording" || got.ObjectID != recording.RecordingID ||
		got.OwnerID != owner || got.BlobID != recording.BlobID || got.Bytes != recording.Bytes ||
		got.NativeSHA256 != recording.SHA256 || got.ReadAlias != recording.ReadAlias ||
		got.AliasRevision != recording.AliasRevision || got.Descriptor != recording.Descriptor || got.AliasRevoked {
		t.Fatal("recording lost its physical proof fields")
	}
	// A different record/owner must not share any physical locator.
	recording.OwnerID = strings.Repeat("3", 32)
	recording.BlobID = native.ReadAlias
	recording.ReadAlias = strings.Repeat("9", 64)
	if err := collector.addRecording(recording); !errors.Is(err, errRecoveryAccounting) || collector.count != 2 {
		t.Fatal("shared native alias/blob identity accepted", err)
	}
	collector.s3 = make([]sealedtree.RecoveryMediaPlacement, recoveryS3ExpectationLimit-1)
	provider := sealedtree.RecoveryMediaPlacement{S3VersionID: "v1"}
	if err := collector.addMedia(provider); err != nil {
		t.Fatal("exact S3 limit was rejected", err)
	}
	if err := collector.addMedia(provider); !errors.Is(err, store.ErrSealedTreeInventoryLimit) {
		t.Fatal("oversized S3 inventory accepted", err)
	}
	collector.count = recoveryExpectationLimit
	if err := collector.addRecording(recording); !errors.Is(err, store.ErrSealedTreeInventoryLimit) {
		t.Fatal("oversized native inventory accepted", err)
	}
}

func TestRecoveryExpectationS3RereadMatchesPrivateProjection(t *testing.T) {
	object, owner, blob := strings.Repeat("1", 64), strings.Repeat("2", 32), strings.Repeat("3", 64)
	meta, err := mediacrypto.NewMetadata(128)
	if err != nil {
		t.Fatal(err)
	}
	expected := sealedtree.RecoveryMediaPlacement{
		ObjectID: object, Kind: "video", OwnerID: owner, BlobID: blob, Bytes: meta.CiphertextSize,
		S3VersionID: "v1", S3ETag: "etag", S3CompositeSHA256: "composite", S3ObjectRevision: 4,
	}
	view := sealedtree.S3ListingObject{
		Path:  "private-path",
		Entry: sealedtree.Entry{ObjectID: object, Kind: "video"},
		Placement: sealedtree.S3Placement{
			Version: 1, ObjectID: object, MemberID: owner, ObjectRevision: 4, Encryption: &meta,
			Location: s3store.Config{Endpoint: "https://s3.us-east-1.amazonaws.com", Region: "us-east-1", Bucket: "fixture-bucket", Prefix: "managed", AddressStyle: "path"},
			Proof: store.S3ObjectProof{Key: "objects/opaque", MediaID: object, MemberID: owner, ObjectID: blob, Bytes: meta.CiphertextSize,
				VersionID: expected.S3VersionID, ETag: expected.S3ETag, CompositeSHA256: expected.S3CompositeSHA256, MetadataFormat: store.S3OpaqueMetadata},
		},
	}
	identity, err := matchRecoveryS3Placement(expected, view)
	if err != nil || identity != (recoveryS3ObjectIdentity{"aws", "fixture-bucket", "managed/objects/opaque", "v1"}) {
		t.Fatal("exact S3 projection rejected", err)
	}
	group := RecoveryOwnerExpectation{S3: []sealedtree.S3Placement{view.Placement}}
	raw, err := json.Marshal(group)
	if err != nil || strings.Contains(string(raw), view.Placement.Proof.Key) {
		t.Fatal("private provider key escaped the in-memory expectation", err)
	}
	for _, change := range []func(*sealedtree.S3ListingObject){
		func(item *sealedtree.S3ListingObject) { item.Entry.Kind = "audio" },
		func(item *sealedtree.S3ListingObject) { item.Placement.Proof.ObjectID = object },
		func(item *sealedtree.S3ListingObject) { item.Placement.Proof.VersionID = "null" },
		func(item *sealedtree.S3ListingObject) { item.Placement.Proof.MetadataFormat = "" },
		func(item *sealedtree.S3ListingObject) { item.Placement.Proof.ETag = "other" },
		func(item *sealedtree.S3ListingObject) { item.Placement.Encryption = nil },
		func(item *sealedtree.S3ListingObject) { item.Placement.ObjectRevision++ },
	} {
		moved := view
		change(&moved)
		if got, err := matchRecoveryS3Placement(expected, moved); !errors.Is(err, errRecoveryAccounting) || got != (recoveryS3ObjectIdentity{}) {
			t.Fatal("changed S3 projection accepted", err)
		}
	}
}
