package media

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	_ "modernc.org/sqlite"
)

type selectedS3RemovalGate struct {
	s3ReadTestGate
	held bool
}

func (g *selectedS3RemovalGate) WithSelectedS3Startup(ctx context.Context, _ *sealedtree.SQLStore, fn func(context.Context) error) error {
	g.held = true
	defer func() { g.held = false }()
	return fn(ctx)
}

type selectedS3RemovalRepo struct {
	store.PoolRepository
	gate                 *selectedS3RemovalGate
	startupErr, emptyErr error
	startup, empty       int
	member               store.S3Member
}

func (r *selectedS3RemovalRepo) S3Member(context.Context, string) (store.S3Member, error) {
	return r.member, nil
}
func (r *selectedS3RemovalRepo) CheckSelectedS3Startup(ctx context.Context, _ *sealedtree.SQLStore, key []byte) error {
	_, bounded := ctx.Deadline()
	if !r.gate.held || len(key) != 32 || !bounded {
		return store.ErrNodeState
	}
	r.startup++
	return r.startupErr
}
func (r *selectedS3RemovalRepo) CheckSelectedS3MemberUnused(_ context.Context, _ *sealedtree.SQLStore, key []byte, _ string) error {
	if !r.gate.held || len(key) != 32 {
		return store.ErrNodeState
	}
	r.empty++
	return r.emptyErr
}
func (r *selectedS3RemovalRepo) CheckSelectedS3MemberNoHistory(ctx context.Context, tree *sealedtree.SQLStore, key []byte, id string) error {
	return r.CheckSelectedS3MemberUnused(ctx, tree, key, id)
}

type selectedS3RemovalNodes struct{ store.NodeRepository }

func (selectedS3RemovalNodes) ReadIdentity(context.Context) (store.NodeIdentity, error) {
	return store.NodeIdentity{Role: "Master"}, nil
}

type selectedS3RemovalControl struct {
	s3Control
	gate           *selectedS3RemovalGate
	calls          int
	configureCalls int
}

func (s *selectedS3RemovalControl) Remove(_ context.Context, _ string, _ int64, _ store.NodeAudit) error {
	if !s.gate.held {
		return store.ErrNodeState
	}
	s.calls++
	return nil
}
func (s *selectedS3RemovalControl) Configure(_ context.Context, _ string, _ int64, input s3media.Configuration, _ store.NodeAudit) (store.S3Member, error) {
	if !s.gate.held || input.Enabled {
		return store.S3Member{}, store.ErrNodeState
	}
	s.configureCalls++
	return store.S3Member{}, nil
}

func TestSelectedS3RemovalRequiresFencedEmptyHistory(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:selected-s3-removal?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.InitializeSQLite(ctx, db, codec, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	gate := &selectedS3RemovalGate{}
	repo := &selectedS3RemovalRepo{gate: gate}
	control := &selectedS3RemovalControl{gate: gate}
	s := &Service{nodes: selectedS3RemovalNodes{}, pool: repo, s3: control, opaqueS3ReadTree: tree, opaqueS3ReadGate: gate}
	id := strings.Repeat("b", 32)
	repo.startupErr = errors.New("pending recovery")
	if err = s.S3RemoveMember(ctx, id, 1, store.NodeAudit{}); err == nil || repo.empty != 0 || control.calls != 0 {
		t.Fatal("pending audit allowed removal")
	}
	repo.startupErr, repo.emptyErr = nil, errors.New("member history")
	if err = s.S3RemoveMember(ctx, id, 1, store.NodeAudit{}); err == nil || control.calls != 0 {
		t.Fatal("history allowed removal")
	}
	repo.emptyErr = nil
	if err = s.S3RemoveMember(ctx, id, 1, store.NodeAudit{}); err != nil || control.calls != 1 || gate.held {
		t.Fatal("empty member removal", err)
	}
	repo.member = store.S3Member{StorageMember: store.StorageMember{ID: id, Enabled: 1, Allocation: 1024}, Name: "empty", Revision: 2}
	cfg := s3media.Configuration{Name: "empty", Quota: 1024, Enabled: false}
	changed := cfg
	changed.Location.Bucket = "changed"
	if _, err = s.S3ConfigureMember(ctx, id, 2, changed, store.NodeAudit{}); err == nil || control.configureCalls != 0 {
		t.Fatal("location change allowed while disabling")
	}
	changed = cfg
	changed.Quota++
	if _, err = s.S3ConfigureMember(ctx, id, 2, changed, store.NodeAudit{}); err == nil || control.configureCalls != 0 {
		t.Fatal("quota change allowed while disabling")
	}
	repo.emptyErr = errors.New("member history")
	if _, err = s.S3ConfigureMember(ctx, id, 2, cfg, store.NodeAudit{}); err == nil || control.configureCalls != 0 {
		t.Fatal("history allowed disable")
	}
	repo.emptyErr = nil
	if _, err = s.S3ConfigureMember(ctx, id, 2, cfg, store.NodeAudit{}); err != nil || control.configureCalls != 1 || gate.held {
		t.Fatal("disable empty member", err)
	}
}
