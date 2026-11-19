package s3store

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	managedVersionPageSize   = 64
	managedVersionMaxPages   = 512
	MaxManagedObjectVersions = managedVersionPageSize * managedVersionMaxPages
)

type ManagedObjectVersion struct {
	Key       string
	VersionID string
	ETag      string
	Size      int64
}

// ManagedObjectVersionLister is a recovery-only extension. The prefix is fixed
// to the member's configured objects/ namespace. Results are provisional until
// successful completion. The caller must separately establish writer stability.
type ManagedObjectVersionLister interface {
	VisitManagedObjectVersions(ctx context.Context, limit int, check func(context.Context) error, visit func(ManagedObjectVersion) error) error
}

var _ ManagedObjectVersionLister = (*Client)(nil)

// VisitManagedObjectVersions admits only a nonempty, complete scan with one
// latest numbered version per key. Historical versions and delete markers are
// incompatible with the selected immutable-key layout. An empty version list
// cannot establish that the provider has ever enabled versioning.
func (c *Client) VisitManagedObjectVersions(ctx context.Context, limit int, check func(context.Context) error, visit func(ManagedObjectVersion) error) error {
	if ctx == nil || limit < 1 || limit > MaxManagedObjectVersions || check == nil || visit == nil {
		return ErrConfig
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	key, err := c.key("objects")
	if err != nil {
		return err
	}
	prefix := key + "/"
	var keyMarker, versionMarker *string
	lastKey, lastVersion, count := "", "", 0
	var requireFirst bool
	for page := 0; page < managedVersionMaxPages; page++ {
		if err = check(ctx); err != nil {
			return err
		}
		out, err := c.sdk.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &c.config.Bucket, Prefix: &prefix, MaxKeys: aws.Int32(managedVersionPageSize),
			KeyMarker: keyMarker, VersionIdMarker: versionMarker,
		})
		if err != nil {
			return failure(err, false)
		}
		if err = check(ctx); err != nil {
			return err
		}
		if aws.ToString(out.Name) != c.config.Bucket || aws.ToString(out.Prefix) != prefix || out.IsTruncated == nil ||
			len(out.CommonPrefixes) != 0 || len(out.DeleteMarkers) != 0 || len(out.Versions) == 0 || len(out.Versions) > managedVersionPageSize ||
			len(out.Versions) > limit-count {
			return invalidResponse(false)
		}
		if requireFirst && (aws.ToString(out.Versions[0].Key) != aws.ToString(keyMarker) || aws.ToString(out.Versions[0].VersionId) != aws.ToString(versionMarker)) {
			return invalidResponse(false)
		}
		for _, item := range out.Versions {
			providerKey, version, etag, size := aws.ToString(item.Key), aws.ToString(item.VersionId), aws.ToString(item.ETag), aws.ToInt64(item.Size)
			suffix, scoped := strings.CutPrefix(providerKey, prefix)
			if !scoped || !validKey("objects/"+suffix, 768, false) || len(providerKey) > 1024 || providerKey <= lastKey ||
				!aws.ToBool(item.IsLatest) || !opaque(version, 1024) || version == "null" || !validETag(etag) || size < 1 || size > MaxObjectSize {
				return invalidResponse(false)
			}
			if err = ctx.Err(); err != nil {
				return err
			}
			if err = visit(ManagedObjectVersion{Key: "objects/" + suffix, VersionID: version, ETag: etag, Size: size}); err != nil {
				return err
			}
			lastKey, lastVersion = providerKey, version
			count++
		}
		nextKey, nextVersion := aws.ToString(out.NextKeyMarker), aws.ToString(out.NextVersionIdMarker)
		if !*out.IsTruncated {
			if nextKey != "" || nextVersion != "" {
				return invalidResponse(false)
			}
			if err = check(ctx); err != nil {
				return err
			}
			return ctx.Err()
		}
		suffix, scoped := strings.CutPrefix(nextKey, prefix)
		if !scoped || len(nextKey) > 1024 || !validKey("objects/"+suffix, 768, false) || nextKey < lastKey ||
			!opaque(nextVersion, 1024) || nextVersion == "null" || nextKey == lastKey && nextVersion != lastVersion {
			return invalidResponse(false)
		}
		if count >= limit {
			return ErrIncomplete
		}
		// A cursor ahead of the final item names the first unreturned version.
		// Require that exact row on the next page instead of skipping its key.
		requireFirst = nextKey > lastKey
		keyMarker, versionMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	return ErrIncomplete
}
