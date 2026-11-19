package media

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type s3ReadTestLease struct {
	ingressTreeReader
	view  sealedtree.S3ListingObject
	check func(context.Context) error
}

func (l *s3ReadTestLease) Check(ctx context.Context) error { return ctx.Err() }
func (l *s3ReadTestLease) ReadS3ListingObject(_ context.Context, _ *sealedtree.SQLStore, id string, includeHidden bool) (sealedtree.S3ListingObject, error) {
	if id != l.view.Entry.ObjectID || !includeHidden {
		return sealedtree.S3ListingObject{}, sealedtree.ErrHidden
	}
	return l.view, nil
}
func (l *s3ReadTestLease) RegisterPrecommitCheck(check func(context.Context) error, _ time.Time) error {
	l.check = check
	return nil
}

type s3ReadTestRepo struct {
	store.PoolRepository
	member store.S3Member
}

func (r *s3ReadTestRepo) S3Member(context.Context, string) (store.S3Member, error) {
	return r.member, nil
}

type s3ReadTestGate struct {
	authorized bool
	denied     bool
}

func (g *s3ReadTestGate) CheckSelectedS3PublicOrigin(_ context.Context, _ *sealedtree.SQLStore, _ store.S3Member, origin string) error {
	if g.denied || origin != "https://public.example" {
		return errors.New("origin not probed")
	}
	return nil
}

func (g *s3ReadTestGate) AuthorizeSelectedS3Read(context.Context, *sealedtree.SQLStore, store.S3Member, int64) error {
	g.authorized = true
	return nil
}
func (g *s3ReadTestGate) CheckSelectedS3Read(context.Context, *sealedtree.SQLStore, store.S3Member, int64) error {
	if !g.authorized || g.denied {
		return errors.New("gate closed")
	}
	return nil
}
func (g *s3ReadTestGate) CheckSelectedS3Catalog(context.Context, *sealedtree.SQLStore, store.S3Member) error {
	if g.denied {
		return errors.New("gate closed")
	}
	return nil
}

type s3ReadTestSigner struct {
	s3Control
	calls int
	block bool
}

func (s *s3ReadTestSigner) SelectedReadSource(ctx context.Context, _ store.S3Member, p store.S3ObjectProof, deadline int64, check func(context.Context) error) (s3media.SourceGrant, error) {
	s.calls++
	if limit, ok := ctx.Deadline(); !ok || time.Until(limit) > 5*time.Second {
		return s3media.SourceGrant{}, errors.New("signing has no bounded deadline")
	}
	if err := check(ctx); err != nil {
		return s3media.SourceGrant{}, err
	}
	if s.block {
		<-ctx.Done()
		return s3media.SourceGrant{}, ctx.Err()
	}
	g := s3store.Grant{URL: "https://s3.example/signed", Headers: map[string]string{"If-Match": p.ETag}, ExpiresAt: deadline}
	return s3media.SourceGrant{ObjectID: p.ObjectID, SizeBytes: p.Bytes, GET: g, HEAD: g}, nil
}

func TestOpaqueS3ReadRequiresSameTreeAndPrecommitGate(t *testing.T) {
	meta, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	object, member := strings.Repeat("a", 64), strings.Repeat("b", 32)
	physical, marker := strings.Repeat("c", 64), strings.Repeat("d", 64)
	location := s3store.Config{Endpoint: "https://s3.us-east-1.amazonaws.com", Region: "us-east-1", Bucket: "fixture-private", Prefix: "managed", AddressStyle: "path"}
	p := sealedtree.S3Placement{Version: 1, ObjectID: object, MemberID: member, ObjectRevision: 1, Location: location, Encryption: &meta, Proof: store.S3ObjectProof{MetadataFormat: store.S3OpaqueMetadata, MetadataOwner: marker, Key: "objects/cc/cc/" + physical + ".blob", MediaID: object, MemberID: member, ObjectID: strings.Repeat("e", 64), SessionID: strings.Repeat("f", 32), Bytes: meta.CiphertextSize, ETag: `"etag"`, CompositeSHA256: base64.StdEncoding.EncodeToString(make([]byte, 32)) + "-1"}}
	view := sealedtree.S3ListingObject{Path: "vido/hidden/sample.mp4", Entry: sealedtree.Entry{ObjectID: object, Kind: "video"}, Placement: p}
	lease := &s3ReadTestLease{view: view}
	ctx, admission := network.WithPublicAdmission(context.Background())
	defer admission.Abort()
	ctx, err = network.WithLocalPublicIngress(ctx, network.LocalPublicIngress{NodeID: strings.Repeat("1", 32), Generation: 1, PublicOrigin: "https://public.example"})
	if err != nil {
		t.Fatal(err)
	}
	ctx = store.WithIngressPrerequisite(ctx, lease)
	tree := &sealedtree.SQLStore{}
	repo := &s3ReadTestRepo{member: store.S3Member{StorageMember: store.StorageMember{ID: member}, Location: store.S3Location{Endpoint: location.Endpoint, Region: location.Region, Bucket: location.Bucket, Prefix: location.Prefix, Style: location.AddressStyle}}}
	signer := &s3ReadTestSigner{}
	s := &Service{pool: repo, s3: signer}
	deadline := time.Now().Unix() + 60
	if _, err = s.OpaqueS3ReadSource(ctx, tree, p, deadline); err == nil || signer.calls != 0 {
		t.Fatal("missing gate issued a grant")
	}
	gate := &s3ReadTestGate{}
	if err = s.ConfigureOpaqueS3Read(tree, gate); err != nil {
		t.Fatal(err)
	}
	if media, placement, err := s.OpaquePublicS3Media(ctx, tree, view.Path, object, p.Proof.ObjectID); err != nil || media.Kind != "video" || placement.Proof != p.Proof {
		t.Fatal("hidden S3 video did not retain exact playback identity", err)
	}
	if _, _, err = s.OpaquePublicS3Media(ctx, tree, "vido/other/sample.mp4", object, p.Proof.ObjectID); err == nil {
		t.Fatal("hidden S3 video accepted a mismatched path")
	}
	if _, err = s.OpaqueS3ReadSource(ctx, tree, p, deadline); err != nil || signer.calls != 1 || lease.check == nil {
		t.Fatal("gated source", err)
	}
	repo.member.Revision++
	if lease.check(ctx) == nil {
		t.Fatal("changed member passed final admission")
	}
	repo.member.Revision--
	gate.denied = true
	if lease.check(ctx) == nil {
		t.Fatal("closed gate passed final admission")
	}
	gate.denied = false
	other := p
	other.Proof.ETag = `"other"`
	if _, err = s.OpaqueS3ReadSource(ctx, tree, other, deadline); err == nil || signer.calls != 1 {
		t.Fatal("unverified placement reached signer")
	}
	signer.block = true
	cancelled, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if grant, e := s.OpaqueS3ReadSource(cancelled, tree, p, deadline); e == nil || grant.GET.URL != "" {
		t.Fatal("cancelled signing returned a grant", e)
	}
}
