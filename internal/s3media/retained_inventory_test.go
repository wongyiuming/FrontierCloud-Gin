package s3media

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
)

type recoveryInventoryFixtureProvider struct {
	*serviceProvider
	list func(context.Context, int, func(context.Context) error, func(s3store.ManagedObjectVersion) error) error
}

func (p *recoveryInventoryFixtureProvider) VisitManagedObjectVersions(ctx context.Context, limit int, check func(context.Context) error, visit func(s3store.ManagedObjectVersion) error) error {
	return p.list(ctx, limit, check, visit)
}

func TestVerifyRetainedS3InventoryRequiresCompleteSelectedSet(t *testing.T) {
	for _, name := range []string{"exact", "missing", "legacy key", "extra", "duplicate", "wrong version", "wrong etag", "wrong length", "permission", "lost writer fence", "stale credential", "no capability", "empty expected"} {
		t.Run(name, func(t *testing.T) {
			s, r, provider, placement, head := retainedS3ObjectFixture(t)
			ctx := context.Background()
			ownerFrozen := true
			guard := func(context.Context) error {
				if !ownerFrozen {
					return errors.New("external writer fence lost")
				}
				return nil
			}
			provider.head = func(context.Context, string, string) (s3store.Proof, error) { return head, nil }
			observation, err := s.ObserveRetainedS3Object(ctx, r.member, placement, guard)
			if err != nil {
				t.Fatal("forward proof failed", err)
			}
			member := r.member
			var requests int
			if name != "no capability" {
				s.factory = func(s3store.Config, s3store.Credentials) (s3store.Provider, func(), error) {
					return &recoveryInventoryFixtureProvider{provider, func(c context.Context, limit int, check func(context.Context) error, visit func(s3store.ManagedObjectVersion) error) error {
						requests++
						if limit != 1 || check(c) != nil {
							t.Fatal("scan lost the member bound or external authority")
						}
						row := s3store.ManagedObjectVersion{Key: placement.Proof.Key, VersionID: head.VersionID, ETag: head.ETag, Size: head.Size}
						switch name {
						case "missing":
							return nil
						case "legacy key":
							row.Key = "objects/" + placement.ObjectID + "/" + placement.Proof.SessionID
						case "wrong version":
							row.VersionID = "replacement"
						case "wrong etag":
							row.ETag = `"replacement"`
						case "wrong length":
							row.Size++
						case "permission":
							return s3store.ErrDenied
						}
						if err := visit(row); err != nil {
							return err
						}
						switch name {
						case "extra":
							row.Key = "objects/ff/ff/" + strings.Repeat("f", 64) + ".blob"
							return visit(row)
						case "duplicate":
							return visit(row)
						case "lost writer fence":
							ownerFrozen = false
						case "stale credential":
							r.member.CredentialRevision++
						}
						return check(c)
					}}, func() {}, nil
				}
			}
			items := []RetainedS3ObjectObservation{observation}
			if name == "empty expected" {
				items = nil
			}
			got, err := s.VerifyRetainedS3Inventory(ctx, member, items, guard)
			if name == "exact" {
				if err != nil || requests != 1 || got.MemberID != member.ID || got.MemberRevision != member.Revision || got.CredentialRevision != member.CredentialRevision || got.Objects != 1 || got.StoredBytes != head.Size || len(got.SetCommitment) != 64 {
					t.Fatal("matching provider inventory was rejected", err)
				}
				return
			}
			want, wantRequests := ErrProof, 1
			switch name {
			case "permission", "lost writer fence", "stale credential":
				want = ErrUnavailable
			case "no capability":
				want, wantRequests = ErrUnavailable, 0
			case "empty expected":
				wantRequests = 0
			}
			if err != want || requests != wantRequests || got != (RetainedS3InventoryObservation{}) {
				t.Fatal("unproved provider inventory was accepted", err)
			}
		})
	}
}
