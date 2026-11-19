package sealedtree

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func fixtureS3Placement() S3Placement {
	object, member := strings.Repeat("a", 64), strings.Repeat("b", 32)
	return S3Placement{Version: 1, ObjectID: object, MemberID: member, ObjectRevision: 4,
		Location: s3store.Config{Endpoint: "https://s3.us-east-1.amazonaws.com", Region: "us-east-1", Bucket: "fixture-private", Prefix: "managed", AddressStyle: "path"},
		Proof:    store.S3ObjectProof{MediaID: object, MemberID: member, ObjectID: strings.Repeat("c", 64), SessionID: strings.Repeat("d", 32), Key: "objects/private-preserved-key", Bytes: 128, ETag: "provider-etag-private", VersionID: "provider-version-private", CompositeSHA256: base64.StdEncoding.EncodeToString(make([]byte, 32)) + "-1"}}
}

func TestS3PlacementSealsOriginalProviderMetadata(t *testing.T) {
	tree := fixture(t)
	for _, encrypted := range []bool{false, true} {
		p := fixtureS3Placement()
		if encrypted {
			meta, err := mediacrypto.NewMetadata(128)
			if err != nil {
				t.Fatal(err)
			}
			p.Encryption, p.Proof.Bytes = &meta, meta.CiphertextSize
		}
		r, err := tree.SealS3Placement(p, 7)
		if err != nil {
			normalized, normalizeErr := s3store.Normalize(p.Location)
			t.Fatalf("seal encrypted=%v normalized=%+v normalizeErr=%v bytes=%d metadata=%+v: %v", encrypted, normalized, normalizeErr, p.Proof.Bytes, p.Encryption, err)
		}
		got, err := tree.OpenS3Placement(r)
		if err != nil || !reflect.DeepEqual(got, p) {
			t.Fatal("roundtrip", err)
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{p.ObjectID, p.MemberID, p.Proof.Key, p.Proof.ETag, p.Proof.VersionID, p.Location.Bucket, p.Location.Endpoint} {
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatal("private S3 metadata in record")
			}
		}
		if encrypted && bytes.Contains(encoded, []byte(p.Encryption.FileID)) {
			t.Fatal("private encryption descriptor in record")
		}
		r2, err := tree.SealS3Placement(p, 7)
		if err != nil || bytes.Equal(r.Sealed, r2.Sealed) || r.ObjectIndex != r2.ObjectIndex {
			t.Fatal("non-random sealed record", err)
		}
		firstID, err := S3PlacementEncryptionID(r)
		if err != nil {
			t.Fatal(err)
		}
		secondID, err := S3PlacementEncryptionID(r2)
		if err != nil || firstID == secondID {
			t.Fatal("reused S3 encryption identity", err)
		}
		for _, edit := range []func(*S3PlacementRecord){
			func(v *S3PlacementRecord) { v.ObjectIndex = strings.Repeat("e", 64) },
			func(v *S3PlacementRecord) { v.Revision++ },
			func(v *S3PlacementRecord) { v.Sealed[len(v.Sealed)-1] ^= 1 },
			func(v *S3PlacementRecord) { v.Sealed = v.Sealed[:1] },
		} {
			changed := r
			changed.Sealed = bytes.Clone(r.Sealed)
			edit(&changed)
			if _, err := tree.OpenS3Placement(changed); !errors.Is(err, ErrInvalid) {
				t.Fatal("corrupt record accepted", err)
			}
		}
	}
}

func TestS3PlacementRejectsWrongBindingsAndUntrustedConfig(t *testing.T) {
	tree := fixture(t)
	for _, edit := range []func(*S3Placement){
		func(p *S3Placement) { p.Version = 2 },
		func(p *S3Placement) { p.ObjectRevision = 0 },
		func(p *S3Placement) { p.Proof.MemberID = strings.Repeat("c", 32) },
		func(p *S3Placement) { p.Proof.MediaID = strings.Repeat("c", 64) },
		func(p *S3Placement) { p.Proof.Key = "../wrong" },
		func(p *S3Placement) { p.Proof.CompositeSHA256 = "forged-1" },
		func(p *S3Placement) { p.Proof.VersionID = "illegal\x01" },
		func(p *S3Placement) { p.Proof.Bytes = 0 },
		func(p *S3Placement) { p.Location.Endpoint = "http://not-tls.example.test" },
	} {
		p := fixtureS3Placement()
		edit(&p)
		if _, err := tree.SealS3Placement(p, 1); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid S3 placement accepted", err)
		}
	}
}

func TestS3PlacementKeepsExplicitProviderMetadataFormat(t *testing.T) {
	tree := fixture(t)
	p := fixtureS3Placement()
	physical := "aabb" + strings.Repeat("0", 60)
	p.Proof.Key = "objects/aa/bb/" + physical + ".blob"
	for _, format := range []string{"", store.S3OpaqueMetadata} {
		p.Proof.MetadataFormat = format
		if format == store.S3OpaqueMetadata {
			p.Proof.MetadataOwner = strings.Repeat("e", 64)
		} else {
			p.Proof.MetadataOwner = ""
		}
		sealed, err := tree.SealS3Placement(p, 1)
		if err != nil {
			t.Fatal("valid format rejected", err)
		}
		if p.Proof.MetadataOwner != "" && bytes.Contains(sealed.Sealed, []byte(p.Proof.MetadataOwner)) {
			t.Fatal("owner exposed in sealed placement")
		}
		got, err := tree.OpenS3Placement(sealed)
		if err != nil || got.Proof.MetadataFormat != format || got.Proof.Key != p.Proof.Key || got.Proof.MetadataOwner != p.Proof.MetadataOwner {
			t.Fatal("format lost or inferred", err)
		}
	}
	p.Proof.MetadataFormat = "unknown-v2"
	if _, err := tree.SealS3Placement(p, 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown format accepted", err)
	}
	p.Proof.MetadataFormat = store.S3OpaqueMetadata
	p.Proof.Key = "objects/old/path"
	if _, err := tree.SealS3Placement(p, 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("opaque format accepted legacy key", err)
	}
	p.Proof.Key = "objects/aa/bb/" + physical + ".blob"
	for _, owner := range []string{"", physical, "wrong", p.Proof.MediaID, p.Proof.ObjectID} {
		p.Proof.MetadataOwner = owner
		if _, err := tree.SealS3Placement(p, 1); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid or non-independent owner accepted", err)
		}
	}
	p.Proof.MetadataFormat = ""
	p.Proof.MetadataOwner = strings.Repeat("e", 64)
	if _, err := tree.SealS3Placement(p, 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("legacy proof carried new owner", err)
	}
}

func TestS3PlacementUsesCurrentMemberNamespaceWithoutPinningCredentials(t *testing.T) {
	p := fixtureS3Placement()
	if !p.MatchesCurrentMember(p.MemberID, p.Location) {
		t.Fatal("original authenticated member rejected")
	}
	rotated := p.Location
	rotated.Endpoint = "https://s3.eu-west-1.amazonaws.com"
	rotated.Region = "eu-west-1"
	if !p.MatchesCurrentMember(p.MemberID, rotated) {
		t.Fatal("same AWS namespace rejected")
	}
	rotated.Bucket = "different-private"
	if p.MatchesCurrentMember(p.MemberID, rotated) || p.MatchesCurrentMember(strings.Repeat("e", 32), p.Location) {
		t.Fatal("different member or bucket accepted")
	}
}

func TestS3PlacementRetainsLargestEscapedProviderFields(t *testing.T) {
	p := fixtureS3Placement()
	p.Location.Prefix = strings.Repeat("p", 255)
	p.Proof.Key = strings.Repeat("k", 768)
	// Quotes and U+2028 are legal under the existing proof contract and are
	// escaped during JSON encoding; preserve their exact provider values.
	p.Proof.ETag = strings.Repeat("\"", 128)
	p.Proof.VersionID = strings.Repeat("\u2028", 341) + "x"
	tree := fixture(t)
	r, err := tree.SealS3Placement(p, 1)
	if err != nil {
		t.Fatal("valid maximum proof rejected", err)
	}
	got, err := tree.OpenS3Placement(r)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("maximum proof changed", err)
	}
}
