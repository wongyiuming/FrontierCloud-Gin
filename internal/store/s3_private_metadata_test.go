package store

import (
	"strings"
	"testing"
)

func TestS3OpaqueMetadataFormatRequiresExactShardedRandomKey(t *testing.T) {
	id := strings.Repeat("ab", 32)
	valid := "objects/ab/ab/" + id + ".blob"
	if owner, ok := S3OpaqueOwner(valid); !ok || owner != id || !ValidS3MetadataFormat(S3OpaqueMetadata, valid) {
		t.Fatal("valid opaque key rejected")
	}
	for _, key := range []string{
		"", "objects/ab/ab/short.blob", "objects/aa/ab/" + id + ".blob",
		"objects/ab/aa/" + id + ".blob", "objects/ab/ab/" + strings.ToUpper(id) + ".blob",
		"objects/ab/ab/" + id, "objects/ab/ab/" + id + ".blob/extra",
		"/objects/ab/ab/" + id + ".blob", "objects/ab/ab/" + id + ".blob/..",
	} {
		if _, ok := S3OpaqueOwner(key); ok || ValidS3MetadataFormat(S3OpaqueMetadata, key) {
			t.Fatalf("invalid opaque key accepted: %q", key)
		}
	}
	if ValidS3MetadataFormat("unknown", valid) {
		t.Fatal("unknown format accepted")
	}
	if !ValidS3MetadataFormat("", valid) {
		t.Fatal("historic format was inferred from key shape")
	}
	owner := strings.Repeat("c", 64)
	if !ValidS3MetadataBinding(S3OpaqueMetadata, valid, owner) || !ValidS3MetadataBinding("", valid, "") {
		t.Fatal("valid ownership binding rejected")
	}
	for _, tc := range []struct{ format, owner string }{
		{S3OpaqueMetadata, ""}, {S3OpaqueMetadata, id}, {S3OpaqueMetadata, strings.ToUpper(owner)}, {"", owner}, {"unknown", owner},
	} {
		if ValidS3MetadataBinding(tc.format, valid, tc.owner) {
			t.Fatal("invalid ownership binding accepted", tc)
		}
	}
	if ValidS3MetadataIdentity(S3OpaqueMetadata, valid, owner, owner, strings.Repeat("d", 64)) || ValidS3MetadataIdentity(S3OpaqueMetadata, valid, owner, strings.Repeat("d", 64), owner) {
		t.Fatal("provider marker revealed a catalog/object identity")
	}
}
