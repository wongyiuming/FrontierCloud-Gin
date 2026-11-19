//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// The fixture constructs synthetic owner evidence. This tests SQL atomicity,
// not source authorization, physical publication, or runtime readiness.
func TestSignedPendingAndCapacityCommitAtomically(t *testing.T) {
	ctx := context.Background()
	db, tree, _ := sqliteFixture(t)
	master := strings.Repeat("f", 32)
	entry := Entry{ParentID: tree.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "fixture"}
	placement := fixturePlacement(t, entry.ObjectID)
	op, err := tree.PrepareFileWithFacts(ctx, entry, placement, Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.Encode(bytes.Repeat([]byte{9}, 32))
	private, err := v.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,endpoint TEXT,private_key TEXT,created_at INTEGER)`,
		`CREATE TABLE cluster_storage_members(member_id TEXT PRIMARY KEY,member_kind TEXT,relationship_id TEXT,used_bytes INTEGER,reserved_bytes INTEGER,allocated_bytes INTEGER)`,
	} {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO node_identity VALUES(1,?,'Master','',?,123)`, master, private); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO cluster_storage_members VALUES(?,'MasterLocal',NULL,0,7,100)`, master); err != nil {
		t.Fatal(err)
	}
	mac := func(domain, value string) string {
		return hex.EncodeToString(opaqueledger.MAC(key, domain, []byte(value)))
	}
	verifier := hex.EncodeToString(opaqueledger.MAC(key, "verifier", nil))
	if _, err = db.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_meta(singleton,verifier) VALUES(1,?)`, verifier); err != nil {
		t.Fatal(err)
	}
	identityRaw, _ := json.Marshal(struct {
		ID      string `json:"id"`
		Sealed  string `json:"sealed_private"`
		Created int64  `json:"created_at"`
	}{master, private, 123})
	h := sha256.New()
	h.Write([]byte("frontiercloud:sealed-tree:master-instance:v1\x00"))
	h.Write(identityRaw)
	masterBinding := hex.EncodeToString(h.Sum(nil))
	generation, stage, challenge, cleanup := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64)
	receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: master, OwnerID: master, Generation: generation, OperationID: op, StageID: stage, BlobID: placement.BlobID, Digest: placement.SHA256, Challenge: challenge, Bytes: placement.Bytes, State: "published"}
	payload, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := protocol.Sign(seed, payload)
	if err != nil {
		t.Fatal(err)
	}
	operationIndex, memberIndex := mac("operation", op), mac("member", master)
	seal := func(index string, value any) (string, []byte) {
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		id, ciphertext, e := opaqueledger.Seal(key, index, raw)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, id); e != nil {
			t.Fatal(e)
		}
		return id, ciphertext
	}
	intentID, intentCipher := seal(operationIndex, map[string]any{"operation_id": op, "master_id": master, "member_id": master, "blob_id": placement.BlobID, "digest": placement.SHA256, "bytes": placement.Bytes})
	if _, err = db.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_intents(operation_index,member_index,blob_index,encryption_id,sealed) VALUES(?,?,?,?,?)`, operationIndex, memberIndex, mac("blob", placement.BlobID), intentID, intentCipher); err != nil {
		t.Fatal(err)
	}
	accountID, accountCipher := seal(memberIndex, map[string]any{"member_id": master, "total": placement.Bytes, "revision": 1})
	if _, err = db.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_accounts(member_index,encryption_id,sealed) VALUES(?,?,?)`, memberIndex, accountID, accountCipher); err != nil {
		t.Fatal(err)
	}
	scopeID, scopeCipher := seal(operationIndex, map[string]any{"operation_id": op, "generation": generation, "stage_id": stage, "master_binding": masterBinding, "relationship_id": "", "relationship_binding": "", "publish_challenge": challenge, "cleanup_challenge": cleanup, "published_signature": signature})
	if _, err = db.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_scopes(operation_index,encryption_id,sealed) VALUES(?,?,?)`, operationIndex, scopeID, scopeCipher); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{challenge, cleanup} {
		if _, err = db.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, mac("challenge", c)); err != nil {
			t.Fatal(err)
		}
	}
	invoke := func(store *SQLStore, sig string, commit bool) (bool, error) {
		conn, e := db.Conn(ctx)
		if e != nil {
			return false, e
		}
		defer conn.Close()
		if _, e = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); e != nil {
			return false, e
		}
		defer conn.ExecContext(context.Background(), `ROLLBACK`)
		already, e := store.finalizeSignedPendingTx(ctx, conn, key, v, receipt, sig, "")
		if e != nil || !commit {
			return already, e
		}
		_, e = conn.ExecContext(ctx, `COMMIT`)
		return already, e
	}
	assertState := func(used, reserved int64, visible bool) {
		t.Helper()
		var u, r int64
		if e := db.QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&u, &r); e != nil || u != used || r != reserved {
			t.Fatalf("accounting used=%d reserved=%d: %v", u, r, e)
		}
		_, _, e := tree.Get(ctx, entry.ObjectID)
		if (e == nil) != visible {
			t.Fatalf("visible=%v: %v", visible, e)
		}
	}
	standalone, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = opaqueledger.SettlePublished(ctx, standalone, key, tree.tree.indexKey[:], v, receipt, signature, ""); err == nil {
		standalone.Rollback()
		t.Fatal("settlement accepted without authenticated tree completion")
	}
	standalone.Rollback()
	if _, err = invoke(tree, signature+"a", true); err == nil {
		t.Fatal("bad signature accepted")
	}
	assertState(0, 7, false)
	if _, err = db.ExecContext(ctx, `CREATE TRIGGER fail_tree_publish BEFORE INSERT ON sealed_tree_placements BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = invoke(tree, signature, true); err == nil {
		t.Fatal("fault did not abort")
	}
	assertState(0, 7, false)
	if _, err = db.ExecContext(ctx, `DROP TRIGGER fail_tree_publish`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TRIGGER fail_ledger_publish BEFORE UPDATE ON sealed_tree_capacity_scopes BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = invoke(tree, signature, true); err == nil {
		t.Fatal("ledger fault did not abort")
	}
	assertState(0, 7, false)
	if _, err = db.ExecContext(ctx, `DROP TRIGGER fail_ledger_publish`); err != nil {
		t.Fatal(err)
	}
	if already, e := invoke(tree, signature, true); e != nil || already {
		t.Fatalf("commit: %v %v", already, e)
	}
	assertState(7, 0, true)
	reopened, err := OpenSQLite(ctx, db, tree.tree, tree.rootID)
	if err != nil {
		t.Fatal(err)
	}
	reopened.unsafePrototype = true
	if already, e := invoke(reopened, signature, true); e != nil || !already {
		t.Fatal(fmt.Sprintf("recovery retry: %v %v", already, e))
	}
	assertState(7, 0, true)
}
