package business_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// The completion is synthetic; the genuine tree transition is separately
// exercised by the sealedtree same-transaction crash/rollback fixture.
func TestOpaqueCapacitySettledHistoryRecoversWithoutRereserving(t *testing.T) {
	for _, size := range []int64{0, 123, 10 * store.GiB} {
		t.Run(fmt.Sprintf("bytes_%d", size), func(t *testing.T) {
			ctx := context.Background()
			db := database(t)
			raw := db.(interface{ Database() *sql.DB }).Database()
			master := strings.Repeat("1", 32)
			key, treeKey := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{6}, 32)
			v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			seed := protocol.Encode(bytes.Repeat([]byte{9}, 32))
			sealed, err := v.Seal(seed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: master, Role: "Standalone", PrivateKey: sealed, CreatedAt: 123}); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 10 * store.GiB, PhysicalFree: 20 * store.GiB}, store.NodeAudit{}); err != nil {
				t.Fatal(err)
			}
			repo := db.Nodes().(*business.Repository)
			if err = repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
				t.Fatal(err)
			}
			digest := strings.Repeat("c", 64)
			if size == 0 {
				empty := sha256.Sum256(nil)
				digest = hex.EncodeToString(empty[:])
			}
			in := business.OpaqueCapacityIntent{OperationID: strings.Repeat("a", 64), MasterID: master, MemberID: master, BlobID: strings.Repeat("b", 64), Digest: digest, Bytes: size}
			if _, err = repo.ReserveOpaqueCapacity(ctx, key, in, 20*store.GiB); err != nil {
				t.Fatal(err)
			}
			sc, _, err := repo.BindOpaqueCapacityScope(ctx, key, in.OperationID, strings.Repeat("2", 64), strings.Repeat("3", 64))
			if err != nil {
				t.Fatal(err)
			}
			receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: master, OwnerID: master, Generation: sc.Generation, OperationID: in.OperationID, StageID: sc.StageID, BlobID: in.BlobID, Digest: in.Digest, Challenge: sc.PublishChallenge, Bytes: in.Bytes, State: "published"}
			payload, err := receipt.Payload()
			if err != nil {
				t.Fatal(err)
			}
			signature, err := protocol.Sign(seed, payload)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature); err != nil {
				t.Fatal(err)
			}
			mac := func(value string) string {
				h := hmac.New(sha256.New, treeKey)
				h.Write([]byte(value))
				return hex.EncodeToString(h.Sum(nil))
			}
			objectIndex := strings.Repeat("e", 64)
			blobIndex := mac("frontiercloud:sealed-tree:blob:v1\x00" + in.BlobID)
			completion := mac("frontiercloud:sealed-tree:completion:v1\x00" + in.OperationID + objectIndex + blobIndex)
			if _, err = raw.ExecContext(ctx, `INSERT INTO sealed_tree_operation_ids(operation_id,completed,object_index,blob_index,receipt_mac) VALUES(?,1,?,?,?)`, in.OperationID, objectIndex, blobIndex, completion); err != nil {
				t.Fatal(err)
			}
			tx, err := raw.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			lock := ""
			if db.Backend() == "mysql" {
				lock = " FOR UPDATE"
			}
			if already, e := opaqueledger.SettlePublished(ctx, tx, key, treeKey, v, receipt, signature, lock); e != nil || already {
				tx.Rollback()
				t.Fatalf("settle: %v %v", already, e)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			for _, current := range []*business.Repository{repo, business.New(raw, db.Backend())} {
				if already, e := current.ReserveOpaqueCapacity(ctx, key, in, 10*store.GiB); e != nil || !already {
					t.Fatalf("settled reserve retry: %v %v", already, e)
				}
				if got, found, e := current.RecoverOpaqueCapacity(ctx, key, in.OperationID); e != nil || !found || got != in {
					t.Fatalf("settled recovery: %v %v", found, e)
				}
				if already, e := current.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature); e != nil || !already {
					t.Fatalf("settled receipt retry: %v %v", already, e)
				}
			}
			var workers sync.WaitGroup
			errs := make(chan error, 8)
			for range 8 {
				workers.Add(1)
				go func() {
					defer workers.Done()
					already, e := repo.ReserveOpaqueCapacity(ctx, key, in, 10*store.GiB)
					if e == nil && !already {
						e = fmt.Errorf("settled operation was reserved again")
					}
					if e != nil {
						errs <- e
					}
				}()
			}
			workers.Wait()
			close(errs)
			for e := range errs {
				t.Fatal("concurrent settled retry", e)
			}
			var used, reserved int64
			if err = raw.QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&used, &reserved); err != nil || used != in.Bytes || reserved != 0 {
				t.Fatalf("double accounting %d %d: %v", used, reserved, err)
			}
			if _, err = raw.ExecContext(ctx, `UPDATE sealed_tree_operation_ids SET receipt_mac=? WHERE operation_id=?`, strings.Repeat("f", 64), in.OperationID); err != nil {
				t.Fatal(err)
			}
			if _, err = repo.ReserveOpaqueCapacity(ctx, key, in, 10*store.GiB); err == nil {
				t.Fatal("changed completion MAC accepted")
			}
			if _, _, err = repo.RecoverOpaqueCapacity(ctx, key, in.OperationID); err == nil {
				t.Fatal("changed completion MAC recovered")
			}
			if _, err = raw.ExecContext(ctx, `UPDATE sealed_tree_operation_ids SET receipt_mac=? WHERE operation_id=?`, completion, in.OperationID); err != nil {
				t.Fatal(err)
			}
			if _, err = raw.ExecContext(ctx, `INSERT INTO sealed_tree_pending_facts(operation_id,object_index,revision,encryption_id,sealed) VALUES(?,?,1,?,?)`, in.OperationID, strings.Repeat("d", 64), strings.Repeat("e", 64), []byte{1}); err != nil {
				t.Fatal(err)
			}
			if _, err = repo.ReserveOpaqueCapacity(ctx, key, in, 10*store.GiB); err == nil {
				t.Fatal("conflicting pending facts accepted")
			}
			if _, _, err = repo.RecoverOpaqueCapacity(ctx, key, in.OperationID); err == nil {
				t.Fatal("conflicting pending facts recovered")
			}
			if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature); err == nil {
				t.Fatal("conflicting pending facts allowed receipt retry")
			}
			if _, err = raw.ExecContext(ctx, `DELETE FROM sealed_tree_pending_facts WHERE operation_id=?`, in.OperationID); err != nil {
				t.Fatal(err)
			}
			if _, err = raw.ExecContext(ctx, `DELETE FROM sealed_tree_operation_ids WHERE operation_id=?`, in.OperationID); err != nil {
				t.Fatal(err)
			}
			if _, err = repo.ReserveOpaqueCapacity(ctx, key, in, 10*store.GiB); err == nil {
				t.Fatal("missing completion accepted")
			}
			if _, _, err = repo.RecoverOpaqueCapacity(ctx, key, in.OperationID); err == nil {
				t.Fatal("missing completion recovered")
			}
			if _, err = raw.ExecContext(ctx, `INSERT INTO sealed_tree_operation_ids(operation_id,completed,object_index,blob_index,receipt_mac) VALUES(?,1,?,?,?)`, in.OperationID, objectIndex, blobIndex, completion); err != nil {
				t.Fatal(err)
			}
			var ciphertext []byte
			if err = raw.QueryRowContext(ctx, `SELECT sealed FROM sealed_tree_capacity_scopes`).Scan(&ciphertext); err != nil {
				t.Fatal(err)
			}
			ciphertext[len(ciphertext)-1] ^= 1
			if _, err = raw.ExecContext(ctx, `UPDATE sealed_tree_capacity_scopes SET sealed=?`, ciphertext); err != nil {
				t.Fatal(err)
			}
			if _, err = repo.ReserveOpaqueCapacity(ctx, key, in, 10*store.GiB); err == nil {
				t.Fatal("tampered settled scope accepted")
			}
			if _, _, err = repo.RecoverOpaqueCapacity(ctx, key, in.OperationID); err == nil {
				t.Fatal("tampered settled scope recovered")
			}
		})
	}
}
