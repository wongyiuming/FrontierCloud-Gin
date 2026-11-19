package store

import "strings"

// S3OpaqueMetadata is explicitly recorded in the durable upload intent; an
// absent format always means the historic metadata, regardless of key shape.
const S3OpaqueMetadata = "opaque-v1"

// S3OpaqueOwner returns the independently random physical object identifier
// from a new-format key. It is not a media ID, upload ID or business path.
func S3OpaqueOwner(key string) (string, bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 4 || parts[0] != "objects" || len(parts[1]) != 2 || len(parts[2]) != 2 || !strings.HasSuffix(parts[3], ".blob") {
		return "", false
	}
	id := strings.TrimSuffix(parts[3], ".blob")
	if len(id) != 64 || parts[1] != id[:2] || parts[2] != id[2:4] {
		return "", false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return id, true
}

func ValidS3MetadataFormat(format, key string) bool {
	if format == "" {
		return true
	}
	_, ok := S3OpaqueOwner(key)
	return format == S3OpaqueMetadata && ok
}

// ValidS3MetadataBinding keeps the provider ownership marker independently
// random from the publicly visible provider key. Legacy proofs have neither.
func ValidS3MetadataBinding(format, key, owner string) bool {
	if !ValidS3MetadataFormat(format, key) {
		return false
	}
	if format == "" {
		return owner == ""
	}
	physical, _ := S3OpaqueOwner(key)
	if len(owner) != 64 || owner == physical {
		return false
	}
	for _, c := range owner {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ValidS3MetadataIdentity also forbids using the public media or object ID as
// provider metadata. Randomness itself is guaranteed at reservation creation.
func ValidS3MetadataIdentity(format, key, owner, mediaID, objectID string) bool {
	if !ValidS3MetadataBinding(format, key, owner) {
		return false
	}
	return format == "" || owner != mediaID && owner != objectID
}
