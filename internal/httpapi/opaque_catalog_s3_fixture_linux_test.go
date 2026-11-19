//go:build linux && catalog_fixture

package httpapi

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func addOpaqueS3LyricTrack(ctx context.Context, t *testing.T, tree *sealedtree.SQLStore, parent string) (string, string) {
	t.Helper()
	id, providerID, member := strings.Repeat("8", 64), strings.Repeat("6", 64), strings.Repeat("7", 32)
	physical := strings.Repeat("5", 64)
	metadata, err := mediacrypto.NewMetadata(64)
	if err != nil {
		t.Fatal(err)
	}
	entry := sealedtree.Entry{ParentID: parent, ObjectID: id, Kind: "audio", Name: "s3.mp3"}
	proof := store.S3ObjectProof{
		Key: "objects/55/55/" + physical + ".blob", SessionID: strings.Repeat("9", 32),
		ObjectID: providerID, MemberID: member, MediaID: id, Bytes: metadata.CiphertextSize,
		ETag: "fixture-etag", VersionID: "fixture-version", MetadataFormat: store.S3OpaqueMetadata,
		MetadataOwner: strings.Repeat("4", 64), CompositeSHA256: base64.StdEncoding.EncodeToString(make([]byte, 32)) + "-1",
	}
	placement := sealedtree.S3Placement{Version: 1, ObjectID: id, MemberID: member, ObjectRevision: 1, Encryption: &metadata, Proof: proof,
		Location: s3store.Config{Endpoint: "https://s3.us-east-1.amazonaws.com", Bucket: "fixture-private", Region: "us-east-1", Prefix: "managed", AddressStyle: "path"}}
	if err := tree.CatalogFixtureCreateS3(ctx, entry, sealedtree.Facts{ObjectID: id}, placement); err != nil {
		t.Fatal(err)
	}
	return id, providerID
}

func addCatalogS3Fixture(ctx context.Context, t *testing.T, tree *sealedtree.SQLStore, parent string) string {
	t.Helper()
	object, member := strings.Repeat("8", 64), strings.Repeat("7", 32)
	entry := sealedtree.Entry{ParentID: parent, ObjectID: object, Kind: "audio", Name: "s3-fixture.mp3"}
	p := sealedtree.S3Placement{Version: 1, ObjectID: object, MemberID: member, ObjectRevision: 1, Location: s3store.Config{Endpoint: "https://s3.us-east-1.amazonaws.com", Bucket: "fixture-private", Region: "us-east-1", Prefix: "managed", AddressStyle: "path"}, Proof: store.S3ObjectProof{Key: "objects/private-provider-key", SessionID: strings.Repeat("5", 32), ObjectID: strings.Repeat("6", 64), MemberID: member, MediaID: object, Bytes: 128, ETag: "fixture-etag", CompositeSHA256: base64.StdEncoding.EncodeToString(make([]byte, 32)) + "-1"}}
	if err := tree.CatalogFixtureCreateS3(ctx, entry, sealedtree.Facts{ObjectID: object}, p); err != nil {
		t.Fatal(err)
	}
	return member
}
