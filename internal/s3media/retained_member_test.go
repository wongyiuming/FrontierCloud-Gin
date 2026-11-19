package s3media

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestVerifyRetainedS3MemberUsesOneProviderAcrossBothProofs(t *testing.T) {
	for _, name := range []string{"complete", "fence changed during HEAD", "member changed during listing", "provider set mismatch", "invalid placement", "duplicate placement"} {
		t.Run(name, func(t *testing.T) {
			s, r, provider, first, firstHead := retainedS3ObjectFixture(t)
			second, secondHead := first, firstHead
			second.ObjectID = strings.Repeat("f", 64)
			second.Proof.ObjectID, second.Proof.MediaID = second.ObjectID, second.ObjectID
			second.Proof.Key = "objects/ee/ee/" + strings.Repeat("e", 64) + ".blob"
			second.Proof.MetadataOwner = strings.Repeat("1", 64)
			second.Proof.VersionID = "second-version"
			secondHead.VersionID = second.Proof.VersionID
			secondHead.Metadata = map[string]string{"fc-format": second.Proof.MetadataFormat, "fc-owner": second.Proof.MetadataOwner}
			expected := []sealedtree.S3Placement{second, first}
			switch name {
			case "invalid placement":
				expected[1].Proof.VersionID = "null"
			case "duplicate placement":
				expected[1] = expected[0]
			}
			fenceLive := true
			guard := func(context.Context) error {
				if !fenceLive {
					return errors.New("provider writer fence changed")
				}
				return nil
			}
			opens, closes, heads, listings := 0, 0, 0, 0
			provider.head = func(_ context.Context, key, version string) (s3store.Proof, error) {
				if !fenceLive || heads >= len(expected) || key != expected[heads].Proof.Key || version != expected[heads].Proof.VersionID {
					t.Fatal("unguarded or wrong HEAD")
				}
				heads++
				if heads == 1 {
					if name == "fence changed during HEAD" {
						fenceLive = false
					}
					return secondHead, nil
				}
				return firstHead, nil
			}
			s.factory = func(s3store.Config, s3store.Credentials) (s3store.Provider, func(), error) {
				opens++
				return &recoveryInventoryFixtureProvider{provider, func(c context.Context, limit int, check func(context.Context) error, visit func(s3store.ManagedObjectVersion) error) error {
					listings++
					if opens != 1 || heads != 2 || limit != 2 || check(c) != nil {
						t.Fatal("reverse scan did not share both guarded HEADs")
					}
					for _, item := range []sealedtree.S3Placement{first, second} {
						p := item.Proof
						row := s3store.ManagedObjectVersion{Key: p.Key, VersionID: p.VersionID, ETag: p.ETag, Size: p.Bytes}
						if name == "provider set mismatch" && item.ObjectID == second.ObjectID {
							row.VersionID = "replacement"
						}
						if err := visit(row); err != nil {
							return err
						}
					}
					if name == "member changed during listing" {
						r.member.CredentialRevision++
					}
					return check(c)
				}}, func() { closes++ }, nil
			}
			got, err := s.VerifyRetainedS3Member(context.Background(), r.member, expected, guard)
			if name == "complete" {
				if err != nil || opens != 1 || closes != 1 || heads != 2 || listings != 1 || got.MemberID != r.member.ID || got.Objects != 2 || got.StoredBytes != firstHead.Size+secondHead.Size || len(got.SetCommitment) != 64 {
					t.Fatalf("complete recovery proof failed: opens=%d closes=%d HEADs=%d listings=%d err=%v", opens, closes, heads, listings, err)
				}
				return
			}
			want, wantOpens, wantHeads, wantListings := ErrProof, 1, 2, 1
			switch name {
			case "fence changed during HEAD":
				want, wantHeads, wantListings = ErrUnavailable, 1, 0
			case "member changed during listing":
				want = ErrUnavailable
			case "invalid placement", "duplicate placement":
				wantOpens, wantHeads, wantListings = 0, 0, 0
			}
			if err != want || opens != wantOpens || closes != wantOpens || heads != wantHeads || listings != wantListings || got != (RetainedS3InventoryObservation{}) {
				t.Fatalf("invalid recovery proof escaped: opens=%d closes=%d HEADs=%d listings=%d err=%v", opens, closes, heads, listings, err)
			}
		})
	}
}
