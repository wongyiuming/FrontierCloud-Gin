package s3media

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSelectedMultipartRequiresBoundEncryptedOpaqueObject(t *testing.T) {
	_, repository, _, _, _ := serviceFixture(t)
	u := repository.upload
	meta, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	u.Reservation.ID = strings.Repeat("1", 32)
	u.Reservation.MemberID = strings.Repeat("2", 32)
	u.Reservation.MediaID = strings.Repeat("3", 64)
	u.ObjectID = u.Reservation.MediaID
	u.Reservation.Encryption = &meta
	u.Reservation.ExpectedBytes = meta.CiphertextSize
	physical, owner := strings.Repeat("a", 64), strings.Repeat("b", 64)
	u.Key = "objects/aa/aa/" + physical + ".blob"
	u.Proof.MetadataFormat, u.Proof.MetadataOwner = store.S3OpaqueMetadata, owner
	part := sha256.Sum256([]byte("representative ciphertext"))
	u.Parts = []store.S3Part{{Number: 1, Bytes: meta.CiphertextSize, SHA256: base64.StdEncoding.EncodeToString(part[:]), ETag: `"part"`, Confirmed: true}}
	composite := sha256.Sum256(part[:])
	p := s3store.Proof{Size: meta.CiphertextSize, ETag: `"object"`, VersionID: "v1", ChecksumType: "COMPOSITE", ChecksumSHA256: base64.StdEncoding.EncodeToString(composite[:]) + "-1", Metadata: metadata(u)}
	got, err := VerifySelectedMultipartProof(u, p)
	if err != nil || got.SessionID != u.Reservation.ID || got.MemberID != u.Reservation.MemberID || got.MediaID != u.Reservation.MediaID || got.CompositeSHA256 != p.ChecksumSHA256 {
		t.Fatal("selected proof", err)
	}
	for name, alter := range map[string]func(*store.S3Upload){
		"plaintext":      func(v *store.S3Upload) { v.Reservation.Encryption = nil },
		"other_object":   func(v *store.S3Upload) { v.ObjectID = strings.Repeat("4", 64) },
		"other_size":     func(v *store.S3Upload) { v.Reservation.ExpectedBytes++ },
		"legacy_format":  func(v *store.S3Upload) { v.Proof.MetadataFormat = "" },
		"invalid_upload": func(v *store.S3Upload) { v.Reservation.ID = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := u
			alter(&bad)
			if _, err := VerifySelectedMultipartProof(bad, p); !errors.Is(err, ErrProof) {
				t.Fatal("invalid selected binding accepted", err)
			}
		})
	}
}

func TestOpaqueS3MetadataBindingAndLegacyCompatibility(t *testing.T) {
	_, repository, _, _, _ := serviceFixture(t)
	legacy := repository.upload
	legacyExpected := map[string]string{"fc-session": "session1", "fc-object": "object1", "fc-member": "member1", "fc-media": "media1"}
	if !reflect.DeepEqual(metadata(legacy), legacyExpected) {
		t.Fatal("historical metadata changed")
	}
	id := strings.Repeat("a", 64)
	owner := strings.Repeat("b", 64)
	current := legacy
	current.Key = "objects/aa/aa/" + id + ".blob"
	current.Proof.MetadataFormat = store.S3OpaqueMetadata
	current.Proof.MetadataOwner = owner
	expected := map[string]string{"fc-format": store.S3OpaqueMetadata, "fc-owner": owner}
	if !reflect.DeepEqual(metadata(current), expected) {
		t.Fatal("new metadata disclosed business identity or lost opaque binding")
	}
	lookalike := legacy
	lookalike.Key = current.Key
	if !reflect.DeepEqual(metadata(lookalike), legacyExpected) {
		t.Fatal("historic metadata was guessed from the key shape")
	}
	proof := completedServiceProof(current)
	proof.Metadata = expected
	result, err := VerifyMultipartObjectProof(current, proof)
	if err != nil || result.MetadataFormat != store.S3OpaqueMetadata || result.Key != current.Key {
		t.Fatal("opaque completion proof failed", err)
	}
	proof.Metadata = map[string]string{"fc-format": store.S3OpaqueMetadata, "fc-owner": strings.Repeat("c", 64)}
	if _, err := VerifyMultipartObjectProof(current, proof); !errors.Is(err, ErrProof) {
		t.Fatal("foreign object metadata accepted", err)
	}
	validProof := completedServiceProof(current)
	validProof.Metadata = expected
	for name, change := range map[string]func(*s3store.Proof){
		"wrong_size":          func(p *s3store.Proof) { p.Size++ },
		"wrong_checksum":      func(p *s3store.Proof) { p.ChecksumSHA256 = strings.Repeat("A", 44) + "-1" },
		"wrong_checksum_type": func(p *s3store.Proof) { p.ChecksumType = "FULL_OBJECT" },
		"missing_etag":        func(p *s3store.Proof) { p.ETag = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := validProof
			change(&bad)
			if _, err := VerifyMultipartObjectProof(current, bad); !errors.Is(err, ErrProof) {
				t.Fatal("mismatched provider proof accepted", err)
			}
		})
	}
	for _, format := range []string{"unknown", store.S3OpaqueMetadata} {
		bad := legacy
		bad.Proof.MetadataFormat = format
		if metadata(bad) != nil {
			t.Fatal("invalid format/key accepted", format)
		}
		if _, _, err := deleteOwned(context.Background(), &cleanupProvider{}, bad.Key, metadata(bad), "", ""); !errors.Is(err, ErrProof) {
			t.Fatal("invalid metadata allowed cleanup", err)
		}
	}
	provider := &cleanupProvider{object: &s3store.Proof{Metadata: expected, VersionID: "version1", ETag: `"opaque-object"`}}
	if _, _, err := deleteOwned(context.Background(), provider, current.Key, metadata(current), "version1", `"opaque-object"`); err != nil || provider.deletes != 1 {
		t.Fatal("opaque object could not be conditionally removed", err)
	}
}

func TestOpaqueS3CreateAndLostCompletionRecoverWithoutBusinessIDs(t *testing.T) {
	s, repository, provider, _, _ := serviceFixture(t)
	id := strings.Repeat("a", 64)
	owner := strings.Repeat("b", 64)
	repository.upload.Key = "objects/aa/aa/" + id + ".blob"
	repository.upload.Proof.MetadataFormat = store.S3OpaqueMetadata
	repository.upload.Proof.MetadataOwner = owner
	repository.upload.State, repository.upload.ProviderUploadID = "reserved", ""
	provider.create = func(_ context.Context, key string, fields map[string]string) (string, error) {
		if key != repository.upload.Key || !reflect.DeepEqual(fields, map[string]string{"fc-format": store.S3OpaqueMetadata, "fc-owner": owner}) {
			t.Fatal("provider received business identifiers or wrong ownership metadata")
		}
		return "provider-upload", nil
	}
	if _, err := s.Begin(context.Background(), "session1"); err != nil {
		t.Fatal(err)
	}
	proof := completedServiceProof(repository.upload)
	proof.Metadata = metadata(repository.upload)
	provider.head = func(context.Context, string, string) (s3store.Proof, error) { return proof, nil }
	provider.complete = func(context.Context, string, string, []s3store.Part) (s3store.Proof, error) {
		t.Fatal("already completed object was sent another completion")
		return s3store.Proof{}, nil
	}
	if _, err := s.Complete(context.Background(), "session1", store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if repository.finalized != 1 || repository.finalProof.MetadataFormat != store.S3OpaqueMetadata || repository.finalProof.MetadataOwner != owner || repository.finalProof.Key != repository.upload.Key {
		t.Fatal("publication lost the durable private metadata format")
	}
}
