//go:build linux && owner_publish_fixture

package preprodimport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// Test-only scope and transport. It does not install an Owner endpoint or grant
// source publication authority; the caller must separately authenticate that.
type fixtureOwnerAuthorization struct {
	Receipt   protocol.OpaqueCapacityReceipt
	ExpiresAt int64
}

func (a fixtureOwnerAuthorization) payload() (map[string]any, error) {
	p, e := a.Receipt.Payload()
	if e != nil || a.ExpiresAt <= 0 {
		return nil, errors.New("invalid fixture authorization")
	}
	return map[string]any{"kind": "fixture-owner-publish-auth-v1", "receipt": p, "expires_at": a.ExpiresAt}, nil
}

type fixtureOwnerPublisher struct {
	db                   store.Store
	repo                 *business.Repository
	fence                *ownerfence.Fence
	root                 *os.Root
	expectedOwner        store.NodeIdentity
	expectedRelationship store.Relationship
	afterPrepare         func() error
	beforeSign           func() error
}

func (f *fixtureOwnerPublisher) check(ctx context.Context, a fixtureOwnerAuthorization, sig string) error {
	if ctx.Err() != nil || time.Now().Unix() >= a.ExpiresAt {
		return errors.New("expired")
	}
	p, e := a.payload()
	if e != nil {
		return e
	}
	n, e := f.db.Nodes().ReadIdentity(ctx)
	if e != nil || n.ID != f.expectedOwner.ID || n.Role != "Follower" || n.PrivateKey != f.expectedOwner.PrivateKey {
		return errors.New("owner changed")
	}
	r, e := f.db.Nodes().Relationship(ctx, f.expectedRelationship.ID)
	if e != nil || r.ID != f.expectedRelationship.ID || r.PeerID != a.Receipt.MasterID || r.PublicKey != f.expectedRelationship.PublicKey || r.Credential != f.expectedRelationship.Credential || r.State != "active" || r.Direction != "upstream" || r.CreatedAt != f.expectedRelationship.CreatedAt || a.Receipt.OwnerID != n.ID || a.Receipt.RelationshipID != r.ID {
		return errors.New("relationship changed")
	}
	if protocol.Verify(r.PublicKey, p, sig) != nil {
		return errors.New("master signature")
	}
	return nil
}
func fixtureSameBytes(ctx context.Context, root *os.Root, op, blob string, size int64, want string) error {
	dest, e := sealedtree.BlobPath(blob)
	if e != nil {
		return e
	}
	stage := "staging/" + op + ".part"
	a, e := root.Open(stage)
	if e != nil {
		return e
	}
	defer a.Close()
	b, e := root.Open(dest)
	if e != nil {
		return e
	}
	defer b.Close()
	ai, e := a.Stat()
	if e != nil {
		return e
	}
	bi, e := b.Stat()
	if e != nil || !ai.Mode().IsRegular() || !os.SameFile(ai, bi) || ai.Size() != size {
		return errors.New("stage mismatch")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(a, size+1))
	if e != nil || n != size || hex.EncodeToString(h.Sum(nil)) != want || ctx.Err() != nil {
		return errors.New("digest mismatch")
	}
	aNow, e := root.Lstat(stage)
	if e != nil || !os.SameFile(ai, aNow) {
		return errors.New("stage replaced")
	}
	bNow, e := root.Lstat(dest)
	if e != nil || !os.SameFile(bi, bNow) {
		return errors.New("blob replaced")
	}
	return nil
}
func (f *fixtureOwnerPublisher) publish(ctx context.Context, a fixtureOwnerAuthorization, sig string, src io.Reader, lose bool) (string, error) {
	if e := f.check(ctx, a, sig); e != nil {
		return "", e
	}
	receiptScope, _ := a.Receipt.Payload()
	canonical, e := protocol.Canonical(map[string]any{"kind": "fixture-owner-stage-scope-v1", "receipt": receiptScope})
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(canonical)
	operation := ownerfence.StageOperation{OperationID: a.Receipt.OperationID, BlobID: a.Receipt.BlobID, ScopeDigest: hex.EncodeToString(h[:])}
	stageName := "staging/" + a.Receipt.OperationID + ".part"
	before, e := f.root.Lstat(stageName)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	if e == nil && !before.Mode().IsRegular() {
		return "", errors.New("unsafe stage")
	}
	// Prepare acquires its own exclusive owner lock; never nest a shared lease.
	if e = f.fence.PrepareStage(ctx, operation); e != nil {
		return "", e
	}
	if f.afterPrepare != nil {
		if e = f.afterPrepare(); e != nil {
			return "", e
		}
	}
	lease, e := f.fence.AcquireStagePublish(ctx, operation)
	if e != nil {
		return "", e
	}
	defer lease.Release()
	if e = lease.Check(ctx); e != nil {
		return "", e
	}
	binding, e := lease.Binding(ctx)
	if e != nil {
		return "", e
	}
	if e = f.repo.VerifyOwnerControlBinding(ctx, binding); e != nil {
		return "", e
	}
	if e = f.check(ctx, a, sig); e != nil {
		return "", e
	}
	after, stageErr := f.root.Lstat(stageName)
	if before != nil {
		if stageErr != nil || !os.SameFile(before, after) {
			return "", errors.New("stage inode changed")
		}
	} else if stageErr == nil || !errors.Is(stageErr, os.ErrNotExist) {
		return "", errors.New("unexpected stage during lock gap")
	}
	publisher, e := sealedtree.NewBlobPublisher(f.root)
	if e != nil {
		return "", e
	}
	if e = publisher.Publish(ctx, a.Receipt.OperationID, a.Receipt.BlobID, a.Receipt.Bytes, a.Receipt.Digest, src); e != nil {
		return "", e
	}
	if e = fixtureSameBytes(ctx, f.root, a.Receipt.OperationID, a.Receipt.BlobID, a.Receipt.Bytes, a.Receipt.Digest); e != nil {
		return "", e
	}
	if lose {
		os.Exit(73)
	}
	if f.beforeSign != nil {
		if e = f.beforeSign(); e != nil {
			return "", e
		}
	}
	if e = lease.Check(ctx); e != nil {
		return "", e
	}
	if e = f.repo.VerifyOwnerControlBinding(ctx, binding); e != nil {
		return "", e
	}
	if e = f.check(ctx, a, sig); e != nil {
		return "", e
	}
	secrets := filepath.Join(f.root.Name(), "secrets")
	v, e := vault.OpenExisting(secrets)
	if e != nil {
		return "", e
	}
	seed, e := v.Unseal(f.expectedOwner.PrivateKey)
	if e != nil {
		return "", e
	}
	receiptPayload, e := a.Receipt.Payload()
	if e != nil {
		return "", e
	}
	return protocol.Sign(seed, receiptPayload)
}
func TestOwnerSignedPhysicalStagePublishAndRecovery(t *testing.T) {
	ctx := context.Background()
	if os.Getenv("FRONTIERCLOUD_FIXTURE_PUBLISH_CHILD") == "1" {
		var input struct {
			Directory     string
			Authorization fixtureOwnerAuthorization
			Signature     string
			Data          []byte
		}
		if e := json.NewDecoder(os.Stdin).Decode(&input); e != nil {
			t.Fatal(e)
		}
		db, e := sqlite.OpenExisting(ctx, filepath.Join(input.Directory, "business.db"))
		if e != nil {
			t.Fatal(e)
		}
		identity, e := node.OpenExisting(ctx, db.Nodes(), filepath.Join(input.Directory, "secrets"))
		if e != nil {
			t.Fatal(e)
		}
		rel, e := db.Nodes().Relationship(ctx, input.Authorization.Receipt.RelationshipID)
		if e != nil {
			t.Fatal(e)
		}
		root, e := os.OpenRoot(input.Directory)
		if e != nil {
			t.Fatal(e)
		}
		fence, e := ownerfence.Open(root, input.Directory, identity)
		if e != nil {
			t.Fatal(e)
		}
		repo := db.Nodes().(*business.Repository)
		if e = repo.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
			return fence.Acquire(c, exclusive)
		}); e != nil {
			t.Fatal(e)
		}
		f := fixtureOwnerPublisher{db: db, repo: repo, fence: fence, root: root, expectedOwner: identity.NodeIdentity, expectedRelationship: rel}
		_, e = f.publish(ctx, input.Authorization, input.Signature, bytes.NewReader(input.Data), true)
		t.Fatal("child did not exit after publish", e)
	}
	mk := func(role string) (store.Store, *node.Identity, *vault.Vault, string) {
		d := t.TempDir()
		db, e := sqlite.Open(filepath.Join(d, "business.db"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = db.Close() })
		if e = db.Initialize(ctx); e != nil {
			t.Fatal(e)
		}
		secrets := filepath.Join(d, "secrets")
		if e = os.Mkdir(secrets, 0700); e != nil {
			t.Fatal(e)
		}
		id, e := node.Initialize(ctx, db.Nodes(), secrets)
		if e != nil {
			t.Fatal(e)
		}
		_, e = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: role, Endpoint: "https://" + strings.ToLower(role) + ".test", Allocation: store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{})
		if e != nil {
			t.Fatal(e)
		}
		id, e = node.OpenExisting(ctx, db.Nodes(), secrets)
		if e != nil {
			t.Fatal(e)
		}
		v, e := vault.OpenExisting(secrets)
		if e != nil {
			t.Fatal(e)
		}
		return db, id, v, d
	}
	master, masterID, masterVault, _ := mk("Master")
	owner, ownerID, _, ownerDir := mk("Follower")
	masterSeed, e := masterVault.Unseal(masterID.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	masterPublic, e := protocol.PublicKey(masterSeed)
	if e != nil {
		t.Fatal(e)
	}
	ownerVault, e := vault.OpenExisting(filepath.Join(ownerDir, "secrets"))
	if e != nil {
		t.Fatal(e)
	}
	ownerSeed, e := ownerVault.Unseal(ownerID.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	ownerPublic, e := protocol.PublicKey(ownerSeed)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	relationID := strings.Repeat("3", 32)
	pair := store.PairPackage{Nonce: strings.Repeat("4", 32), TokenHash: strings.Repeat("5", 64), ExpiresAt: now + 250}
	if _, e = owner.Nodes().IssuePair(ctx, pair, now, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	rel := store.Relationship{ID: relationID, PeerID: masterID.ID, Endpoint: "https://master.test", PublicKey: masterPublic, Credential: "sealed-owner-fixture", Direction: "upstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: now}
	if e = owner.Nodes().ConsumePair(ctx, pair, rel, now, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = owner.Nodes().ActivateRelationship(ctx, relationID, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	masterRel := store.Relationship{ID: relationID, PeerID: ownerID.ID, Endpoint: "https://follower.test", PublicKey: ownerPublic, Credential: "sealed-master-fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: now}
	if e = master.Nodes().PrepareRelationship(ctx, masterRel, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = master.Nodes().ActivateRelationship(ctx, relationID, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	rel, e = owner.Nodes().Relationship(ctx, relationID)
	if e != nil {
		t.Fatal(e)
	}
	masterRel, e = master.Nodes().Relationship(ctx, relationID)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(ownerDir, ".opaque-aliases"), 0700); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(ownerDir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	fence, e := ownerfence.Create(root, ownerDir, ownerID)
	if e != nil {
		t.Fatal(e)
	}
	repo := owner.Nodes().(*business.Repository)
	if e = repo.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); e != nil {
		t.Fatal(e)
	}
	if e = repo.InitializeOwnerControlMarker(ctx); e != nil {
		t.Fatal(e)
	}
	data := []byte("fixture isolated owner bytes")
	digest := sha256.Sum256(data)
	binding := store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: ownerID.ID, RelationshipID: masterRel.ID, PublicKey: masterRel.PublicKey, ControlEndpoint: masterRel.Endpoint, CredentialDigest: store.PeerCredentialDigest(masterRel.Credential), CreatedAt: masterRel.CreatedAt})
	receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: masterID.ID, OwnerID: ownerID.ID, RelationshipID: relationID, RelationshipBinding: binding, Generation: strings.Repeat("6", 64), OperationID: strings.Repeat("7", 64), StageID: strings.Repeat("8", 64), BlobID: strings.Repeat("9", 64), Digest: hex.EncodeToString(digest[:]), Challenge: strings.Repeat("a", 64), Bytes: int64(len(data)), State: "published"}
	auth := fixtureOwnerAuthorization{Receipt: receipt, ExpiresAt: now + 240}
	p, e := auth.payload()
	if e != nil {
		t.Fatal(e)
	}
	signature, e := protocol.Sign(masterSeed, p)
	if e != nil {
		t.Fatal(e)
	}
	f := fixtureOwnerPublisher{db: owner, repo: repo, fence: fence, root: root, expectedOwner: ownerID.NodeIdentity, expectedRelationship: rel}
	if _, e = f.publish(ctx, auth, signature+"x", bytes.NewReader(data), false); e == nil {
		t.Fatal("bad signature accepted")
	}
	expired := auth
	expired.ExpiresAt = now - 1
	if _, e = f.publish(ctx, expired, signature, bytes.NewReader(data), false); e == nil {
		t.Fatal("expired accepted")
	}
	input, e := json.Marshal(struct {
		Directory     string
		Authorization fixtureOwnerAuthorization
		Signature     string
		Data          []byte
	}{ownerDir, auth, signature, data})
	if e != nil {
		t.Fatal(e)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	child := exec.Command(exe, "-test.run=^TestOwnerSignedPhysicalStagePublishAndRecovery$")
	child.Env = append(os.Environ(), "FRONTIERCLOUD_FIXTURE_PUBLISH_CHILD=1")
	child.Stdin = bytes.NewReader(input)
	output, e := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("publish crash exit=%v output=%s", e, output)
	}
	// Reopen the actual journal and identity after publication before re-signing.
	reopened, e := ownerfence.Open(root, ownerDir, ownerID)
	if e != nil {
		t.Fatal(e)
	}
	f.fence = reopened
	signed, e := f.publish(ctx, auth, signature, bytes.NewReader(nil), false)
	if e != nil {
		t.Fatal("recovery", e)
	}
	rp, e := receipt.Payload()
	if e != nil || protocol.Verify(masterRel.PublicKey, rp, signed) != nil {
		t.Fatal("owner receipt", e)
	}
	changed := auth
	changed.Receipt.Digest = strings.Repeat("b", 64)
	cp, e := changed.payload()
	if e != nil {
		t.Fatal(e)
	}
	cs, e := protocol.Sign(masterSeed, cp)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.publish(ctx, changed, cs, bytes.NewReader(data), false); e == nil {
		t.Fatal("scope rebound")
	}
	if e = fixtureSameBytes(ctx, root, receipt.OperationID, receipt.BlobID, receipt.Bytes, receipt.Digest); e != nil {
		t.Fatal("bytes not preserved", e)
	}
	// A stage substituted after the immutable claim but before reacquiring the
	// shared lock must not be published or overwritten.
	substituted := auth
	substituted.Receipt.OperationID = strings.Repeat("b", 64)
	substituted.Receipt.StageID = strings.Repeat("c", 64)
	substituted.Receipt.BlobID = strings.Repeat("d", 64)
	sp, e := substituted.payload()
	if e != nil {
		t.Fatal(e)
	}
	ss, e := protocol.Sign(masterSeed, sp)
	if e != nil {
		t.Fatal(e)
	}
	badStage := "staging/" + substituted.Receipt.OperationID + ".part"
	badBytes := []byte("preserve substituted bytes")
	if e = root.WriteFile(badStage, data, 0600); e != nil {
		t.Fatal(e)
	}
	f.afterPrepare = func() error {
		if e := root.Rename(badStage, badStage+".original"); e != nil {
			return e
		}
		return root.WriteFile(badStage, badBytes, 0600)
	}
	if _, e = f.publish(ctx, substituted, ss, bytes.NewReader(data), false); e == nil {
		t.Fatal("substituted stage signed")
	}
	f.afterPrepare = nil
	got, e := root.ReadFile(badStage)
	if e != nil || !bytes.Equal(got, badBytes) {
		t.Fatal("substituted stage overwritten", e)
	}
	original, e := root.ReadFile(badStage + ".original")
	if e != nil || !bytes.Equal(original, data) {
		t.Fatal("original stage lost", e)
	}
	// A pre-existing conflicting destination is never replaced or signed.
	conflict := auth
	conflict.Receipt.OperationID = strings.Repeat("1", 64)
	conflict.Receipt.StageID = strings.Repeat("2", 64)
	conflict.Receipt.BlobID = strings.Repeat("3", 64)
	cpayload, e := conflict.payload()
	if e != nil {
		t.Fatal(e)
	}
	conflictSig, e := protocol.Sign(masterSeed, cpayload)
	if e != nil {
		t.Fatal(e)
	}
	dest, e := sealedtree.BlobPath(conflict.Receipt.BlobID)
	if e != nil {
		t.Fatal(e)
	}
	if e = root.MkdirAll(path.Dir(dest), 0700); e != nil {
		t.Fatal(e)
	}
	other := []byte("existing conflicting destination")
	if e = root.WriteFile(dest, other, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = f.publish(ctx, conflict, conflictSig, bytes.NewReader(data), false); e == nil {
		t.Fatal("conflicting destination signed")
	}
	got, e = root.ReadFile(dest)
	if e != nil || !bytes.Equal(got, other) {
		t.Fatal("destination overwritten", e)
	}
	// A changed Owner identity between claim creation and lease acquisition fails
	// before any bytes are published. This direct SQL injection is test-only.
	altered := auth
	altered.Receipt.OperationID = strings.Repeat("4", 64)
	altered.Receipt.StageID = strings.Repeat("5", 64)
	altered.Receipt.BlobID = strings.Repeat("e", 64)
	ap, e := altered.payload()
	if e != nil {
		t.Fatal(e)
	}
	as, e := protocol.Sign(masterSeed, ap)
	if e != nil {
		t.Fatal(e)
	}
	raw := owner.(interface{ Database() *sql.DB }).Database()
	f.afterPrepare = func() error {
		_, e := raw.Exec("UPDATE node_identity SET private_key=? WHERE singleton=1", "changed-fixture")
		return e
	}
	if _, e = f.publish(ctx, altered, as, bytes.NewReader(data), false); e == nil {
		t.Fatal("changed owner signed")
	}
	f.afterPrepare = nil
	if _, e = raw.Exec("UPDATE node_identity SET private_key=? WHERE singleton=1", ownerID.PrivateKey); e != nil {
		t.Fatal(e)
	}
	// Use the real wall clock to cross the authorization deadline after bytes are
	// durable but before the receipt. The destination remains for reconciliation.
	late := auth
	late.Receipt.OperationID = strings.Repeat("f", 64)
	late.Receipt.StageID = strings.Repeat("0", 64)
	late.Receipt.BlobID = strings.Repeat("4", 64)
	late.ExpiresAt = time.Now().Unix() + 2
	lp, e := late.payload()
	if e != nil {
		t.Fatal(e)
	}
	ls, e := protocol.Sign(masterSeed, lp)
	if e != nil {
		t.Fatal(e)
	}
	f.beforeSign = func() error {
		if delay := time.Until(time.Unix(late.ExpiresAt, 0)); delay > 0 {
			time.Sleep(delay + 20*time.Millisecond)
		}
		return nil
	}
	if _, e = f.publish(ctx, late, ls, bytes.NewReader(data), false); e == nil {
		t.Fatal("expired authorization signed")
	}
	f.beforeSign = nil
	if e = fixtureSameBytes(ctx, root, late.Receipt.OperationID, late.Receipt.BlobID, late.Receipt.Bytes, late.Receipt.Digest); e != nil {
		t.Fatal("expired operation lost data", e)
	}
	stagePayload, _ := auth.Receipt.Payload()
	canon, _ := protocol.Canonical(map[string]any{"kind": "fixture-owner-stage-scope-v1", "receipt": stagePayload})
	sum := sha256.Sum256(canon)
	op := ownerfence.StageOperation{OperationID: receipt.OperationID, BlobID: receipt.BlobID, ScopeDigest: hex.EncodeToString(sum[:])}
	stopped, e := reopened.StopStageAndAcquireCleanup(ctx, op)
	if e != nil {
		t.Fatal(e)
	}
	stopped.Release()
	if _, e = f.publish(ctx, auth, signature, bytes.NewReader(data), false); e == nil {
		t.Fatal("stopped stage revived")
	}
	if e = fixtureSameBytes(ctx, root, receipt.OperationID, receipt.BlobID, receipt.Bytes, receipt.Digest); e != nil {
		t.Fatal(fmt.Errorf("stop changed data: %w", e))
	}
}
