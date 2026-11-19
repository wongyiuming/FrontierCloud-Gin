package s3media

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSelectedReadSignsOpaqueVersionUnderCurrentGate(t *testing.T) {
	s, repo, provider := cleanupFixture(t)
	repo.member.Transport, repo.member.ProbeState, repo.member.ProbeRevision = "S3", "ready", repo.member.Revision
	expected := repo.member
	physical := strings.Repeat("a", 64)
	proof := store.S3ObjectProof{MetadataFormat: store.S3OpaqueMetadata, MetadataOwner: strings.Repeat("b", 64), Key: "objects/aa/aa/" + physical + ".blob", MemberID: expected.ID, MediaID: strings.Repeat("c", 64), ObjectID: strings.Repeat("d", 64), Bytes: 23, VersionID: "version", ETag: `"etag"`}
	deadline := time.Now().Unix() + 120
	checks, calls := 0, 0
	guard := func(context.Context) error { checks++; return nil }
	provider.read = func(_ context.Context, key, version, etag, filename string, expiry time.Duration) (s3store.Grant, error) {
		calls++
		if key != proof.Key || version != proof.VersionID || etag != proof.ETag || filename != "" || expiry <= 0 || time.Now().Add(expiry).Unix() > deadline {
			t.Fatal("GET did not bind opaque proof and deadline")
		}
		return s3store.Grant{URL: "https://s3.example/get", Headers: map[string]string{"If-Match": etag}, ExpiresAt: time.Now().Add(expiry).Unix()}, nil
	}
	provider.headGrant = func(_ context.Context, key, version, etag string, expiry time.Duration) (s3store.Grant, error) {
		calls++
		if key != proof.Key || version != proof.VersionID || etag != proof.ETag || expiry <= 0 || time.Now().Add(expiry).Unix() > deadline {
			t.Fatal("HEAD did not bind opaque proof and deadline")
		}
		return s3store.Grant{URL: "https://s3.example/head", Headers: map[string]string{"If-Match": etag}, ExpiresAt: time.Now().Add(expiry).Unix()}, nil
	}
	grant, err := s.SelectedReadSource(context.Background(), expected, proof, deadline, guard)
	if err != nil || grant.ObjectID != proof.ObjectID || grant.SizeBytes != proof.Bytes || calls != 2 || checks < 4 {
		t.Fatal("matching selected read", err)
	}
	for name, mutate := range map[string]func(){
		"member changed":     func() { repo.member.Location.Bucket = "different" },
		"credential changed": func() { repo.member.SealedCredentials += "different" },
		"probe stale":        func() { repo.member.ProbeState = "unchecked" },
	} {
		t.Run(name, func(t *testing.T) {
			repo.member = expected
			mutate()
			calls = 0
			got, err := s.SelectedReadSource(context.Background(), expected, proof, deadline, guard)
			if err == nil || calls != 0 || got.GET.URL != "" || got.HEAD.URL != "" {
				t.Fatal("stale member reached signing", err)
			}
		})
	}
	repo.member = expected
	checks, calls = 0, 0
	guard = func(context.Context) error {
		checks++
		if checks >= 2 {
			return errors.New("admission ended")
		}
		return nil
	}
	if got, err := s.SelectedReadSource(context.Background(), expected, proof, deadline, guard); err == nil || calls != 1 || got.GET.URL != "" {
		t.Fatal("ended admission exposed signed GET", err)
	}
}
