package s3media

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type selectedDeleteProvider struct {
	s3store.Provider
	proof      s3store.Proof
	expected   store.S3ObjectProof
	t          *testing.T
	headErr    error
	deleteErr  error
	keepObject bool
	calls      []string
}

func (p *selectedDeleteProvider) Head(_ context.Context, key, version string) (s3store.Proof, error) {
	p.t.Helper()
	if key != p.expected.Key || version != p.expected.VersionID {
		p.t.Fatal("HEAD lost exact object identity")
	}
	p.calls = append(p.calls, "head")
	return p.proof, p.headErr
}

func (p *selectedDeleteProvider) Delete(_ context.Context, key, version, etag string) error {
	p.t.Helper()
	if key != p.expected.Key || version != p.expected.VersionID || etag != p.expected.ETag {
		p.t.Fatal("DELETE lost exact object identity")
	}
	p.calls = append(p.calls, "delete")
	if !p.keepObject {
		p.headErr = s3store.ErrNotFound
	}
	return p.deleteErr
}

func TestDeleteSelectedPublishedObjectExactProof(t *testing.T) {
	expected := store.S3ObjectProof{Key: "objects/11/11/" + strings.Repeat("1", 64) + ".blob", MemberID: "member",
		SessionID: "upload", MediaID: "media", ObjectID: "object", ETag: "opaque-etag", VersionID: "version", Bytes: 123,
		CompositeSHA256: "composite", MetadataFormat: store.S3OpaqueMetadata, MetadataOwner: strings.Repeat("2", 64)}
	for _, mode := range []string{"deleted", "lost_reply", "already_absent", "denied", "wrong_version", "wrong_checksum", "foreign_owner", "still_present", "lost_fence"} {
		t.Run(mode, func(t *testing.T) {
			provider := &selectedDeleteProvider{t: t, expected: expected,
				proof: s3store.Proof{Size: expected.Bytes, ETag: expected.ETag, VersionID: expected.VersionID,
					ChecksumType: "COMPOSITE", ChecksumSHA256: expected.CompositeSHA256,
					Metadata: map[string]string{"fc-format": store.S3OpaqueMetadata, "fc-owner": expected.MetadataOwner}}}
			var want error
			calls, failCheck := "head,delete,head", 0
			switch mode {
			case "lost_reply":
				provider.deleteErr = &s3store.OperationError{Code: s3store.ErrNetwork, Uncertain: true}
			case "already_absent":
				provider.headErr, calls = s3store.ErrNotFound, "head"
			case "denied":
				provider.headErr, want, calls = s3store.ErrDenied, s3store.ErrDenied, "head"
			case "wrong_version":
				provider.proof.VersionID, want, calls = "foreign", ErrProof, "head"
			case "wrong_checksum":
				provider.proof.ChecksumSHA256, want, calls = "other", ErrProof, "head"
			case "foreign_owner":
				provider.proof.Metadata["fc-owner"], want, calls = "foreign", ErrProof, "head"
			case "still_present":
				provider.keepObject, want = true, ErrPending
			case "lost_fence":
				failCheck, want, calls = 2, ErrUnavailable, "head"
			}
			checks := 0
			err := DeleteSelectedPublishedObject(context.Background(), provider, expected, func(context.Context) error {
				checks++
				if checks == failCheck {
					return store.ErrNodeState
				}
				return nil
			})
			if !errors.Is(err, want) || strings.Join(provider.calls, ",") != calls {
				t.Fatalf("delete: %v, calls %v; want %v and %s", err, provider.calls, want, calls)
			}
		})
	}
}
