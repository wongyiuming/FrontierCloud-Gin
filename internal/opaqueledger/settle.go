package opaqueledger

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type Transaction interface {
	Query
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// SettlePublished is an internal transaction primitive, not an import API.
// The caller must roll the whole transaction back on any error. This function
// independently re-verifies the recorded owner signature and its bindings;
// it does not authorize the source or establish an owner fence.
func SettlePublished(ctx context.Context, q Transaction, key, treeIndexKey []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature, lock string) (bool, error) {
	if err := VerifyPublished(ctx, q, key, nodeVault, receipt, signature, lock); err != nil {
		return false, err
	}
	if len(treeIndexKey) != 32 {
		return false, ErrInvalid
	}
	var objectIndex, blobIndex, receiptMAC string
	if q.QueryRowContext(ctx, `SELECT object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`+lock, receipt.OperationID).Scan(&objectIndex, &blobIndex, &receiptMAC) != nil || !hashID.MatchString(objectIndex) || !hashID.MatchString(blobIndex) {
		return false, ErrInvalid
	}
	blobMAC := hmac.New(sha256.New, treeIndexKey)
	blobMAC.Write([]byte("frontiercloud:sealed-tree:blob:v1\x00" + receipt.BlobID))
	completion := hmac.New(sha256.New, treeIndexKey)
	completion.Write([]byte("frontiercloud:sealed-tree:completion:v1\x00" + receipt.OperationID + objectIndex + blobIndex))
	if !hmac.Equal([]byte(blobIndex), []byte(hex.EncodeToString(blobMAC.Sum(nil)))) || !hmac.Equal([]byte(receiptMAC), []byte(hex.EncodeToString(completion.Sum(nil)))) {
		return false, ErrInvalid
	}
	for _, table := range []string{"sealed_tree_pending_files", "sealed_tree_pending_facts"} {
		var count int
		if q.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE operation_id=?`, receipt.OperationID).Scan(&count) != nil || count != 0 {
			return false, ErrInvalid
		}
	}
	index := keyed(key, "operation", receipt.OperationID)
	var scopeID string
	var sealed []byte
	if q.QueryRowContext(ctx, `SELECT encryption_id,sealed FROM sealed_tree_capacity_scopes WHERE operation_index=?`+lock, index).Scan(&scopeID, &sealed) != nil {
		return false, ErrInvalid
	}
	raw, err := Open(key, index, scopeID, sealed)
	if err != nil {
		return false, ErrInvalid
	}
	var sc scope
	ok := decodeRecord(raw, &sc)
	clear(raw)
	if !ok {
		return false, ErrInvalid
	}
	if sc.Settled {
		return true, nil
	}
	memberIndex := keyed(key, "member", receipt.OwnerID)
	var accountID string
	if q.QueryRowContext(ctx, `SELECT encryption_id,sealed FROM sealed_tree_capacity_accounts WHERE member_index=?`+lock, memberIndex).Scan(&accountID, &sealed) != nil {
		return false, ErrInvalid
	}
	raw, err = Open(key, memberIndex, accountID, sealed)
	if err != nil {
		return false, ErrInvalid
	}
	var a account
	ok = decodeRecord(raw, &a)
	clear(raw)
	if !ok || a.MemberID != receipt.OwnerID || a.Total < receipt.Bytes || a.Revision <= 0 || a.Revision == math.MaxInt64 {
		return false, ErrInvalid
	}
	var used, reserved, allocation int64
	if q.QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes,allocated_bytes FROM cluster_storage_members WHERE member_id=?`+lock, receipt.OwnerID).Scan(&used, &reserved, &allocation) != nil || used < 0 || reserved < a.Total || allocation < used || reserved > allocation-used || receipt.Bytes > allocation-used {
		return false, ErrInvalid
	}
	a.Total -= receipt.Bytes
	a.Revision++
	sc.Settled = true
	sc.CompletionBinding = CompletionBinding(objectIndex, blobIndex, receiptMAC)
	if sc.CompletionBinding == "" {
		return false, ErrInvalid
	}
	accountRaw, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	defer clear(accountRaw)
	newAccountID, newAccount, err := Seal(key, memberIndex, accountRaw)
	if err != nil {
		return false, err
	}
	scopeRaw, err := json.Marshal(sc)
	if err != nil {
		return false, err
	}
	defer clear(scopeRaw)
	newScopeID, newScope, err := Seal(key, index, scopeRaw)
	if err != nil {
		return false, err
	}
	for _, id := range []string{newAccountID, newScopeID} {
		if _, err = q.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, id); err != nil {
			return false, err
		}
	}
	result, err := q.ExecContext(ctx, `UPDATE sealed_tree_capacity_accounts SET encryption_id=?,sealed=? WHERE member_index=? AND encryption_id=?`, newAccountID, newAccount, memberIndex, accountID)
	if err != nil {
		return false, err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return false, ErrInvalid
	}
	result, err = q.ExecContext(ctx, `UPDATE sealed_tree_capacity_scopes SET encryption_id=?,sealed=? WHERE operation_index=? AND encryption_id=?`, newScopeID, newScope, index, scopeID)
	if err != nil {
		return false, err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return false, ErrInvalid
	}
	if receipt.Bytes != 0 {
		result, err = q.ExecContext(ctx, `UPDATE cluster_storage_members SET used_bytes=used_bytes+?,reserved_bytes=reserved_bytes-? WHERE member_id=? AND used_bytes=? AND reserved_bytes=?`, receipt.Bytes, receipt.Bytes, receipt.OwnerID, used, reserved)
		if err != nil {
			return false, err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return false, ErrInvalid
		}
	}
	return false, nil
}
