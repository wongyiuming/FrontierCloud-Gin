//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

func revocationFixture(t *testing.T) (*SQLStore, Entry, Placement) {
	t.Helper()
	_, s, root, _, _ := fencedFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "synthetic"}
	content := []byte("synthetic content")
	sum := sha256.Sum256(content)
	placement := fixturePlacement(t, entry.ObjectID)
	placement.Bytes, placement.SHA256, placement.State = int64(len(content)), hex.EncodeToString(sum[:]), "active"
	placement.BlobID, placement.ReadAlias = "", ""
	prepared, err := s.PrepareFileWithFreshLocators(context.Background(), entry, placement, Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	placement.BlobID, placement.ReadAlias = prepared.BlobID, prepared.ReadAlias
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(context.Background(), prepared.OperationID, pub, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	public, err := protocol.PublicKey(protocol.Encode(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT NOT NULL,role TEXT NOT NULL,private_key TEXT NOT NULL,created_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TABLE node_relationships(relationship_id TEXT PRIMARY KEY,peer_id TEXT NOT NULL,peer_key TEXT NOT NULL,peer_endpoint TEXT NOT NULL,credential TEXT NOT NULL,direction TEXT NOT NULL,state TEXT NOT NULL,protocol INTEGER NOT NULL,created_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master','synthetic-master-key',123)`, strings.Repeat("1", 32)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO node_relationships VALUES(?,?,?,'https://owner.test','synthetic-credential','downstream','active',?,123)`, strings.Repeat("2", 32), placement.OwnerID, public, protocol.Version); err != nil {
		t.Fatal(err)
	}
	return s, entry, placement
}

func TestRevocationIntentBlocksNewReadsAndRecoversWithoutClaimingOwnerAck(t *testing.T) {
	ctx := context.Background()
	s, entry, placement := revocationFixture(t)
	master, relation := strings.Repeat("1", 32), strings.Repeat("2", 32)
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	type result struct {
		intent RevocationIntent
		err    error
	}
	ready := make(chan result, 1)
	go func() {
		close(started)
		intent, err := s.BeginOpaqueRevocation(ctx, entry.ObjectID, master, relation, "delete", 1, 1)
		ready <- result{intent, err}
	}()
	<-started
	select {
	case <-ready:
		lease.Release()
		t.Fatal("revocation bypassed an active read fence")
	case <-time.After(80 * time.Millisecond):
	}
	lease.Release()
	var first result
	select {
	case first = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("revocation did not resume")
	}
	if first.err != nil || first.intent.Alias != placement.ReadAlias || first.intent.BlobID != placement.BlobID || first.intent.OwnerID != placement.OwnerID || len(first.intent.OperationID) != 32 {
		t.Fatal("intent binding invalid", first.err)
	}
	retry, err := s.BeginOpaqueRevocation(ctx, entry.ObjectID, master, relation, "delete", 1, 1)
	if err != nil || retry != first.intent {
		t.Fatal("lost-response retry changed intent", err)
	}
	if _, err = s.BeginOpaqueRevocation(ctx, entry.ObjectID, master, relation, "migrate", 1, 1); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting operation accepted", err)
	}
	if _, err = s.SetFacts(ctx, Facts{ObjectID: entry.ObjectID}, 2); !errors.Is(err, ErrConflict) {
		t.Fatal("ordinary facts write cleared intent", err)
	}
	if _, err = s.Move(ctx, entry.ObjectID, entry.ParentID, "renamed", 1); !errors.Is(err, ErrRevocationPending) {
		t.Fatal("move crossed a pending owner revocation", err)
	}
	reopened, err := OpenSQLite(ctx, s.db, s.tree, s.rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFence(ctx, reopened, s.fence.root, s.fence.directory); err != nil {
		t.Fatal(err)
	}
	lease, err = reopened.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err = reopened.ReadVisibleObjectByAliasWithLease(ctx, lease, placement.ReadAlias); !errors.Is(err, ErrRevocationPending) {
		t.Fatal("new alias read admitted while revocation pending", err)
	}
	recovered, found, err := reopened.RecoverOpaqueRevocationWithLease(ctx, lease, entry.ObjectID)
	if err != nil || !found || recovered != first.intent {
		t.Fatal("pending operation could not be recovered", err)
	}
	page, next, err := reopened.ListOpaqueRevocationsWithLease(ctx, lease, "", 1)
	if err != nil || next != "" || len(page) != 1 || page[0].ObjectID != entry.ObjectID || page[0].Intent != first.intent {
		t.Fatal("pending index did not recover operation", err)
	}
	byOperation, found, err := reopened.RecoverOpaqueRevocationByOperationWithLease(ctx, lease, first.intent.OperationID)
	if err != nil || !found || byOperation.ObjectID != entry.ObjectID || byOperation.Intent != first.intent {
		t.Fatal("operation lookup did not recover original intent", err)
	}
	var sealed []byte
	if err = s.db.QueryRow(`SELECT sealed FROM sealed_tree_facts`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{first.intent.OperationID, master, relation, first.intent.MasterBinding, first.intent.RelationshipBinding, placement.ReadAlias, placement.BlobID} {
		if bytes.Contains(sealed, []byte(secret)) {
			t.Fatal("revocation intent leaked into stored facts")
		}
	}
	lease.Release()
	if _, err = s.db.Exec(`UPDATE sealed_tree_revocations SET operation_index=?`, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	lease, err = reopened.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, _, err = reopened.RecoverOpaqueRevocationWithLease(ctx, lease, entry.ObjectID); !errors.Is(err, ErrInvalid) {
		t.Fatal("tampered pending index was accepted", err)
	}
	if rows, _, err := reopened.ListOpaqueRevocationsWithLease(ctx, lease, "", 64); !errors.Is(err, ErrInvalid) || rows != nil {
		t.Fatal("tampered pending index was listed", err)
	}
}

func TestRevocationIntentTransactionRollsBackWithoutBlockingReads(t *testing.T) {
	ctx := context.Background()
	s, entry, placement := revocationFixture(t)
	if _, err := s.db.Exec(`CREATE TRIGGER reject_revoke BEFORE INSERT ON sealed_tree_revocations BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginOpaqueRevocation(ctx, entry.ObjectID, strings.Repeat("1", 32), strings.Repeat("2", 32), "delete", 1, 1); err == nil {
		t.Fatal("injected index failure committed intent")
	}
	var reserved, pending int
	if err := s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM sealed_tree_blob_ids),(SELECT COUNT(*) FROM sealed_tree_revocations)`).Scan(&reserved, &pending); err != nil || reserved != 2 || pending != 0 {
		t.Fatal("failed intent left reservations or index", err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err = s.ReadVisibleObjectByAliasWithLease(ctx, lease, placement.ReadAlias); err != nil {
		t.Fatal("failed intent blocked an unchanged object", err)
	}
}

func TestRevocationIndexPagesIndependentPendingOperations(t *testing.T) {
	ctx := context.Background()
	s, first, _ := revocationFixture(t)
	second := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "other"}
	content := []byte("second synthetic content")
	sum := sha256.Sum256(content)
	placement := fixturePlacement(t, second.ObjectID)
	placement.Bytes, placement.SHA256, placement.State = int64(len(content)), hex.EncodeToString(sum[:]), "active"
	placement.BlobID, placement.ReadAlias = "", ""
	prepared, err := s.PrepareFileWithFreshLocators(ctx, second, placement, Facts{ObjectID: second.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := NewBlobPublisher(s.fence.root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	for _, objectID := range []string{first.ObjectID, second.ObjectID} {
		if _, err = s.BeginOpaqueRevocation(ctx, objectID, strings.Repeat("1", 32), strings.Repeat("2", 32), "delete", 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	page, next, err := s.ListOpaqueRevocationsWithLease(ctx, lease, "", 1)
	if err != nil || len(page) != 1 || next == "" {
		t.Fatal("first revocation page invalid", err)
	}
	last, end, err := s.ListOpaqueRevocationsWithLease(ctx, lease, next, 1)
	if err != nil || len(last) != 1 || end != "" || page[0].ObjectID == last[0].ObjectID {
		t.Fatal("second revocation page invalid", err)
	}
}

func TestOwnerAckRequiresPinnedSignatureAndLeavesIntentBlocked(t *testing.T) {
	ctx := context.Background()
	s, entry, placement := revocationFixture(t)
	intent, err := s.BeginOpaqueRevocation(ctx, entry.ObjectID, strings.Repeat("1", 32), strings.Repeat("2", 32), "delete", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	receipt := revocationReceipt(intent)
	payload, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := protocol.Sign(protocol.Encode(bytes.Repeat([]byte{7}, 32)), payload)
	if err != nil {
		t.Fatal(err)
	}
	deleted := deletionReceipt(intent)
	deletePayload, err := deleted.Payload()
	if err != nil {
		t.Fatal(err)
	}
	deleteSignature, err := protocol.Sign(protocol.Encode(bytes.Repeat([]byte{7}, 32)), deletePayload)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueDeletionReceipt(ctx, entry.ObjectID, deleted, deleteSignature); !errors.Is(err, ErrInvalid) {
		t.Fatal("deletion receipt accepted before owner revoke", err)
	}
	wrongSignature, err := protocol.Sign(protocol.Encode(bytes.Repeat([]byte{8}, 32)), payload)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueRevocationAck(ctx, entry.ObjectID, receipt, wrongSignature); !errors.Is(err, ErrInvalid) {
		t.Fatal("unpaired owner signature was accepted", err)
	}
	wrongReceipt := receipt
	wrongReceipt.Alias = strings.Repeat("e", 64)
	if err = s.RecordOpaqueRevocationAck(ctx, entry.ObjectID, wrongReceipt, signature); !errors.Is(err, ErrInvalid) {
		t.Fatal("mismatched owner receipt was accepted", err)
	}
	if _, err = s.db.Exec(`UPDATE node_relationships SET credential='replacement' WHERE relationship_id=?`, intent.RelationshipID); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueRevocationAck(ctx, entry.ObjectID, receipt, signature); !errors.Is(err, ErrInvalid) {
		t.Fatal("replacement relationship was accepted", err)
	}
	if _, err = s.db.Exec(`UPDATE node_relationships SET credential='synthetic-credential' WHERE relationship_id=?`, intent.RelationshipID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE node_identity SET private_key='replacement-master-key' WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueRevocationAck(ctx, entry.ObjectID, receipt, signature); !errors.Is(err, ErrInvalid) {
		t.Fatal("replacement master identity was accepted", err)
	}
	if _, err = s.db.Exec(`UPDATE node_identity SET private_key='synthetic-master-key' WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER reject_ack BEFORE UPDATE ON sealed_tree_facts BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueRevocationAck(ctx, entry.ObjectID, receipt, signature); err == nil {
		t.Fatal("failed ACK transaction committed", err)
	}
	if _, err = s.db.Exec(`DROP TRIGGER reject_ack`); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueRevocationAck(ctx, entry.ObjectID, receipt, signature); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueRevocationAck(ctx, entry.ObjectID, receipt, signature); err != nil {
		t.Fatal("ACK retry was not idempotent", err)
	}
	if err = s.RecordOpaqueDeletionReceipt(ctx, entry.ObjectID, deleted, wrongSignature); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong deletion signature was accepted", err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER reject_deletion BEFORE UPDATE ON sealed_tree_facts BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueDeletionReceipt(ctx, entry.ObjectID, deleted, deleteSignature); err == nil {
		t.Fatal("failed deletion receipt transaction committed")
	}
	if _, err = s.db.Exec(`DROP TRIGGER reject_deletion`); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueDeletionReceipt(ctx, entry.ObjectID, deleted, deleteSignature); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueDeletionReceipt(ctx, entry.ObjectID, deleted, deleteSignature); err != nil {
		t.Fatal("deletion receipt retry was not idempotent", err)
	}
	reopened, err := OpenSQLite(ctx, s.db, s.tree, s.rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFence(ctx, reopened, s.fence.root, s.fence.directory); err != nil {
		t.Fatal(err)
	}
	lease, err := reopened.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := reopened.RecoverOpaqueRevocationWithLease(ctx, lease, entry.ObjectID)
	if err != nil || !found || got.OwnerSignature != signature || got.OwnerPublicKey == "" || got.DeletionSignature != deleteSignature || got.DeletionPublicKey != got.OwnerPublicKey {
		lease.Release()
		t.Fatal("signed owner proof was not recoverable", err)
	}
	if _, err = reopened.ReadVisibleObjectByAliasWithLease(ctx, lease, placement.ReadAlias); !errors.Is(err, ErrRevocationPending) {
		lease.Release()
		t.Fatal("ACK alone resumed access", err)
	}
	lease.Release()
	otherKey, err := protocol.PublicKey(protocol.Encode(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE node_relationships SET peer_key=? WHERE relationship_id=?`, otherKey, intent.RelationshipID); err != nil {
		t.Fatal(err)
	}
	lease, err = reopened.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, _, err = reopened.RecoverOpaqueRevocationWithLease(ctx, lease, entry.ObjectID); !errors.Is(err, ErrInvalid) {
		t.Fatal("changed owner pin silently accepted", err)
	}
}
