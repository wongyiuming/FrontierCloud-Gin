//go:build linux && owner_publish_fixture && ledger_fixture

package preprodimport

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

// Test-only input travels over an inherited pipe and is never a product grant.
// Source database locking covers cooperating SQLite writers only; it does not
// establish the driver's actual file inode or prevent whole-store rollback.
type sourceOwnerCrashInput struct {
	MasterDir, TreeFenceDir, SourceDBPath, OwnerDir, RootID string
	TreeIndexKey, TreeFactsKey, CapacityKey, EvidenceRoot   []byte
	SourceRef                                               sourceEvidenceRef
	Pin                                                     sourceAuthorityPin
	Complete                                                completeSnapshot
	Envelope, ObjectProof                                   store.EncryptedMediaSourceSnapshot
	Challenge, MediaID                                      string
	ProofScope                                              objectProofScope
	Entry                                                   sealedtree.Entry
	Placement                                               sealedtree.Placement
	Facts                                                   sealedtree.Facts
	OwnerAuth                                               fixtureOwnerAuthorization
	MasterSignature, OwnerReceiptSignature                  string
	Phase                                                   string
}

// The parent invokes this test in an isolated subprocess with JSON on stdin.
// Exit 74 is after both target SQL mutations but before COMMIT; 73 is after
// COMMIT. The default invocation is intentionally inert.
func TestSourceOwnerCrashChild(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_SOURCE_OWNER_CRASH_CHILD") != "1" {
		return
	}
	var in sourceOwnerCrashInput
	if e := json.NewDecoder(os.Stdin).Decode(&in); e != nil {
		t.Fatal(e)
	}
	if in.Phase != "before" && in.Phase != "after" {
		t.Fatal("invalid crash phase")
	}
	ctx := context.Background()
	master, e := sqlite.OpenExisting(ctx, filepath.Join(in.MasterDir, "business.db"))
	if e != nil {
		t.Fatal(e)
	}
	masterVault, e := vault.OpenExisting(filepath.Join(in.MasterDir, "secrets"))
	if e != nil {
		t.Fatal(e)
	}
	identity, e := master.Nodes().ReadIdentity(ctx)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := masterVault.Unseal(identity.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := protocol.Decode(encoded)
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := receiverFromMasterSeed(seed)
	clear(seed)
	if e != nil {
		t.Fatal(e)
	}
	repo := master.Nodes().(*business.Repository)
	sealedPin, found, e := repo.LoadOpaqueSourcePin(ctx, identity, masterVault)
	if e != nil || !found {
		t.Fatal("target pin missing", e)
	}
	pin, e := decodeSourceAuthority(masterVault, sealedPin)
	if e != nil || !reflect.DeepEqual(pin, in.Pin) {
		t.Fatal("target pin changed", e)
	}
	signed, sourceDigest, e := authenticateCompleteSource(in.Envelope, receiver, pin, in.Challenge, time.Now(), in.Complete)
	if e != nil {
		t.Fatal("signed source", e)
	}
	var media Media
	for _, m := range in.Complete.Projection.Media {
		if m.MediaID == in.MediaID {
			media = m
			break
		}
	}
	if media.MediaID == "" {
		t.Fatal("media absent")
	}
	if e = verifySSHObjectProof(in.ObjectProof, receiver, pin, signed.Snapshot, sourceDigest, media, in.ProofScope, time.Now()); e != nil {
		t.Fatal("object proof", e)
	}
	proof, e := decodeObjectEvidenceProof(in.ObjectProof, receiver)
	if e != nil {
		t.Fatal(e)
	}
	tree, e := sealedtree.New(in.TreeIndexKey, in.TreeFactsKey)
	if e != nil {
		t.Fatal(e)
	}
	target, e := sealedtree.OpenSQLite(ctx, master.Database(), tree, in.RootID)
	if e != nil {
		t.Fatal(e)
	}
	treeRoot, e := os.OpenRoot(in.TreeFenceDir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = sealedtree.OpenFence(ctx, target, treeRoot, in.TreeFenceDir); e != nil {
		t.Fatal(e)
	}
	readLease, e := target.AcquireReadFence(ctx)
	if e != nil {
		t.Fatal(e)
	}
	observed, e := reconcilePlainOrLyric(ctx, target, readLease, receiver, pin, in.Envelope, in.ObjectProof, in.Challenge, in.Complete, in.MediaID, in.ProofScope, time.Now())
	readLease.Release()
	if e != nil || observed.RuntimeReady {
		t.Fatal("pending reconciliation", e)
	}
	sourceDB, e := sql.Open("sqlite", in.SourceDBPath)
	if e != nil {
		t.Fatal(e)
	}
	sourceDB.SetMaxOpenConns(1)
	readTx, e := sourceDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		t.Fatal(e)
	}
	record, _, e := readSourceEvidenceTx(ctx, readTx, in.EvidenceRoot, receiver, pin, in.SourceRef)
	if e != nil || !reflect.DeepEqual(record.Envelope, in.Envelope) {
		t.Fatal("source vault original", e)
	}
	tag, e := sourceEvidenceTag(in.EvidenceRoot, in.SourceRef.Digest)
	if e != nil {
		t.Fatal(e)
	}
	rowHash, e := fixtureEvidenceRowHash(ctx, readTx, tag)
	if e != nil {
		t.Fatal(e)
	}
	if e = readTx.Commit(); e != nil {
		t.Fatal(e)
	}
	// The independent Owner lock precedes the source reservation and target
	// tree mutation; all authority is checked again before target COMMIT.
	ownerDB, e := sqlite.OpenExisting(ctx, filepath.Join(in.OwnerDir, "business.db"))
	if e != nil {
		t.Fatal(e)
	}
	ownerIdentity, e := node.OpenExisting(ctx, ownerDB.Nodes(), filepath.Join(in.OwnerDir, "secrets"))
	if e != nil {
		t.Fatal(e)
	}
	rel, e := ownerDB.Nodes().Relationship(ctx, in.OwnerAuth.Receipt.RelationshipID)
	if e != nil {
		t.Fatal(e)
	}
	ownerRoot, e := os.OpenRoot(in.OwnerDir)
	if e != nil {
		t.Fatal(e)
	}
	fence, e := ownerfence.Open(ownerRoot, in.OwnerDir, ownerIdentity)
	if e != nil {
		t.Fatal(e)
	}
	ownerRepo := ownerDB.Nodes().(*business.Repository)
	if e = ownerRepo.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); e != nil {
		t.Fatal(e)
	}
	publisher := fixtureOwnerPublisher{db: ownerDB, repo: ownerRepo, fence: fence, root: ownerRoot, expectedOwner: ownerIdentity.NodeIdentity, expectedRelationship: rel}
	payload, e := in.OwnerAuth.Receipt.Payload()
	if e != nil {
		t.Fatal(e)
	}
	canonical, e := protocol.Canonical(map[string]any{"kind": "fixture-owner-stage-scope-v1", "receipt": payload})
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(canonical)
	op := ownerfence.StageOperation{OperationID: in.OwnerAuth.Receipt.OperationID, BlobID: in.OwnerAuth.Receipt.BlobID, ScopeDigest: hex.EncodeToString(sum[:])}
	ownerLease, e := fence.AcquireStagePublish(ctx, op)
	if e != nil {
		t.Fatal(e)
	}
	ownerBinding, e := ownerLease.Binding(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = publisher.check(ctx, in.OwnerAuth, in.MasterSignature); e != nil {
		t.Fatal(e)
	}
	if e = ownerRepo.VerifyOwnerControlBinding(ctx, ownerBinding); e != nil {
		t.Fatal(e)
	}
	if e = fixtureSameBytes(ctx, ownerRoot, op.OperationID, op.BlobID, in.OwnerAuth.Receipt.Bytes, in.OwnerAuth.Receipt.Digest); e != nil {
		t.Fatal(e)
	}
	deadline := signed.Snapshot.ExpiresUnix
	if proof.Proof.ExpiresUnix < deadline {
		deadline = proof.Proof.ExpiresUnix
	}
	evidenceFence, e := fixtureAcquireEvidenceFence(ctx, sourceDB, in.SourceDBPath, tag, rowHash, deadline)
	if e != nil {
		t.Fatal(e)
	}
	check := func() error {
		if e := evidenceFence.Check(ctx); e != nil {
			return e
		}
		if e := ownerLease.Check(ctx); e != nil {
			return e
		}
		if e := ownerRepo.VerifyOwnerControlBinding(ctx, ownerBinding); e != nil {
			return e
		}
		return publisher.check(ctx, in.OwnerAuth, in.MasterSignature)
	}
	before := func(conn *sql.Conn) error {
		if e := check(); e != nil {
			return e
		}
		var current store.NodeIdentity
		if e := conn.QueryRowContext(ctx, "SELECT node_id,`role`,endpoint,private_key,created_at FROM node_identity WHERE singleton=1").Scan(&current.ID, &current.Role, &current.Endpoint, &current.PrivateKey, &current.CreatedAt); e != nil || current != identity {
			return errors.New("target identity changed")
		}
		var currentPin string
		if e := conn.QueryRowContext(ctx, `SELECT sealed FROM sealed_tree_source_pin WHERE singleton=1`).Scan(&currentPin); e != nil || currentPin != sealedPin {
			return errors.New("target pin changed")
		}
		return sealedtree.FixtureValidatePendingExact(ctx, target, conn, in.OwnerAuth.Receipt.OperationID, media.Path, in.Entry, in.Placement, in.Facts)
	}
	after := func() error {
		if e := check(); e != nil {
			return e
		}
		if in.Phase == "before" {
			os.Exit(74)
		}
		return nil
	}
	if _, e = sealedtree.FixtureCommitSignedPendingWithChecks(ctx, target, in.CapacityKey, masterVault, in.OwnerAuth.Receipt, in.OwnerReceiptSignature, before, after); e != nil {
		t.Fatal("target commit", e)
	}
	if in.Phase == "after" {
		os.Exit(73)
	}
	t.Fatal("unexpected crash phase return")
}
