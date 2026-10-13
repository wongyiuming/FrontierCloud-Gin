package store

// Match the native expected-inventory metadata without trusting a peer's
// metadata hash as a substitute for the Master's immutable object binding.
func MigrationNativeMetadataSHA(o MigrationObject, source string) (string, error) {
	if o.Resource == "media" {
		return MigrationDigest(MediaObject{ID: o.ObjectID, Path: o.Path, Kind: o.Kind, Encryption: o.Encryption})
	}
	if o.Resource != "recording" || o.Recording == nil || o.Recording.ID != o.ObjectID || o.Recording.Bytes != o.Bytes || o.Recording.SHA256 != o.ETag {
		return "", ErrMigrationState
	}
	p := o.Recording
	return MigrationDigest([]any{p.ID, source, p.UserID, p.Filename, p.ContentType, "ready", p.Bytes, p.SHA256})
}
