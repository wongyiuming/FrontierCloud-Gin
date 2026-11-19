package s3media

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func retainedS3ObjectFixture(t *testing.T) (*Service, *serviceRepository, *serviceProvider, sealedtree.S3Placement, s3store.Proof) {
	t.Helper()
	s, r, provider, _, _ := serviceFixture(t)
	r.member.ID = strings.Repeat("a", 32)
	r.member.Transport, r.member.ProbeState, r.member.ProbeRevision = "S3", "ready", r.member.Revision
	mediaID, physicalID, marker := strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	encryption, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	head := completedServiceProof(r.upload)
	head.Size = encryption.CiphertextSize
	head.Metadata = map[string]string{"fc-format": store.S3OpaqueMetadata, "fc-owner": marker}
	placement := sealedtree.S3Placement{
		Version: 1, ObjectID: mediaID, MemberID: r.member.ID, ObjectRevision: 2,
		Location: config(r.member.Location), Encryption: &encryption,
		Proof: store.S3ObjectProof{
			MediaID: mediaID, ObjectID: mediaID, MemberID: r.member.ID, SessionID: strings.Repeat("e", 32),
			Key: "objects/cc/cc/" + physicalID + ".blob", MetadataFormat: store.S3OpaqueMetadata, MetadataOwner: marker,
			Bytes: head.Size, ETag: head.ETag, VersionID: head.VersionID, CompositeSHA256: head.ChecksumSHA256,
		},
	}
	return s, r, provider, placement, head
}

func TestObserveRetainedS3ObjectUsesExactVersionUnderFence(t *testing.T) {
	s, r, provider, placement, head := retainedS3ObjectFixture(t)
	checks, requests := 0, 0
	provider.head = func(_ context.Context, key, version string) (s3store.Proof, error) {
		requests++
		if checks != 1 || key != placement.Proof.Key || version != placement.Proof.VersionID {
			t.Fatal("HEAD was not bound to the guarded exact placement")
		}
		return head, nil
	}
	guard := func(context.Context) error { checks++; return nil }
	got, err := s.ObserveRetainedS3Object(context.Background(), r.member, placement, guard)
	want := RetainedS3ObjectObservation{
		ObjectID: placement.ObjectID, MemberID: r.member.ID, PhysicalObjectID: strings.Repeat("c", 64),
		ObjectRevision: placement.ObjectRevision, MemberRevision: r.member.Revision, CredentialRevision: r.member.CredentialRevision,
		StoredBytes: head.Size, VersionID: head.VersionID, ETag: head.ETag, ChecksumType: "COMPOSITE", CompositeSHA256: head.ChecksumSHA256,
	}
	if err != nil || got != want || requests != 1 || checks != 2 {
		t.Fatalf("exact recovery observation failed: calls=%d guards=%d err=%v", requests, checks, err)
	}
}

func TestObserveRetainedS3ObjectRejectsWeakerProviderProof(t *testing.T) {
	for name, mutate := range map[string]func(*s3store.Proof){
		"unversioned":              func(p *s3store.Proof) { p.VersionID = "" },
		"null version":             func(p *s3store.Proof) { p.VersionID = "null" },
		"another version":          func(p *s3store.Proof) { p.VersionID = "other-version" },
		"wrong etag":               func(p *s3store.Proof) { p.ETag = `"other-etag"` },
		"wrong length":             func(p *s3store.Proof) { p.Size++ },
		"wrong checksum type":      func(p *s3store.Proof) { p.ChecksumType = "FULL_OBJECT" },
		"wrong composite checksum": func(p *s3store.Proof) { p.ChecksumSHA256 = strings.Repeat("A", 43) + "=-1" },
		"wrong marker":             func(p *s3store.Proof) { p.Metadata["fc-owner"] = strings.Repeat("f", 64) },
		"wrong format":             func(p *s3store.Proof) { p.Metadata["fc-format"] = "opaque-v2" },
		"missing metadata":         func(p *s3store.Proof) { p.Metadata = nil },
		"extra metadata":           func(p *s3store.Proof) { p.Metadata["fc-media"] = "unexpected" },
	} {
		t.Run(name, func(t *testing.T) {
			s, r, provider, placement, head := retainedS3ObjectFixture(t)
			mutate(&head)
			provider.head = func(context.Context, string, string) (s3store.Proof, error) { return head, nil }
			got, err := s.ObserveRetainedS3Object(context.Background(), r.member, placement, func(context.Context) error { return nil })
			if !errors.Is(err, ErrProof) || got != (RetainedS3ObjectObservation{}) {
				t.Fatal("weaker provider proof was accepted", err)
			}
		})
	}
}

func TestObserveRetainedS3ObjectRejectsUnversionedOrUnboundPlacement(t *testing.T) {
	for name, mutate := range map[string]func(*sealedtree.S3Placement){
		"unversioned":         func(p *sealedtree.S3Placement) { p.Proof.VersionID = "" },
		"null version":        func(p *sealedtree.S3Placement) { p.Proof.VersionID = "null" },
		"plaintext":           func(p *sealedtree.S3Placement) { p.Encryption = nil },
		"legacy metadata":     func(p *sealedtree.S3Placement) { p.Proof.MetadataFormat, p.Proof.MetadataOwner = "", "" },
		"different namespace": func(p *sealedtree.S3Placement) { p.Location.Prefix = "other-prefix" },
	} {
		t.Run(name, func(t *testing.T) {
			s, r, provider, placement, _ := retainedS3ObjectFixture(t)
			mutate(&placement)
			provider.head = func(context.Context, string, string) (s3store.Proof, error) {
				t.Fatal("unbound placement reached provider")
				return s3store.Proof{}, nil
			}
			got, err := s.ObserveRetainedS3Object(context.Background(), r.member, placement, func(context.Context) error { return nil })
			if !errors.Is(err, ErrProof) || got != (RetainedS3ObjectObservation{}) {
				t.Fatal("unbound placement was accepted", err)
			}
		})
	}
}

func TestObserveRetainedS3ObjectDiscardsProofOnFailureOrAuthorityChange(t *testing.T) {
	for _, change := range []string{"provider failure", "credential revision", "fence lost", "context canceled"} {
		t.Run(change, func(t *testing.T) {
			s, r, provider, placement, head := retainedS3ObjectFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			admission := true
			guard := func(context.Context) error {
				if !admission {
					return errors.New("fence lost")
				}
				return nil
			}
			provider.head = func(context.Context, string, string) (s3store.Proof, error) {
				switch change {
				case "provider failure":
					return s3store.Proof{}, errors.New("private provider error")
				case "credential revision":
					r.member.CredentialRevision++
				case "fence lost":
					admission = false
				case "context canceled":
					cancel()
				}
				return head, nil
			}
			got, err := s.ObserveRetainedS3Object(ctx, r.member, placement, guard)
			if err != ErrUnavailable || got != (RetainedS3ObjectObservation{}) {
				t.Fatal("invalidated observation was returned", err)
			}
		})
	}
}
