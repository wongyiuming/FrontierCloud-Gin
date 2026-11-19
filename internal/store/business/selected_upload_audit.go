package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// auditSelectedScopesMaintenanceOnly checks every selected reservation and
// scope in an already exclusive, stable maintenance transaction. It is not a
// recovery authorization: the caller must separately prove maintenance, physical
// database identity, sealed-tree placement, and reconcile actual Owner data.
// This private helper is not connected to startup or public upload routes.
func (r *Repository) auditSelectedScopesMaintenanceOnly(ctx context.Context, tx *sql.Tx, key []byte) error {
	if ctx == nil || tx == nil || !validCapacityKey(key) {
		return store.ErrNodeState
	}
	type scoperow struct {
		index, enc string
		sealed     []byte
	}
	type intentrow struct {
		index, upload, member, blob, enc string
		sealed                           []byte
	}
	after := ""
	for {
		rows, err := tx.QueryContext(ctx, "SELECT parent_index,encryption_id,sealed FROM selected_upload_parent_scopes WHERE parent_index>? ORDER BY parent_index LIMIT 32", after)
		if err != nil {
			return err
		}
		scopes := make([]scoperow, 0, 32)
		for rows.Next() {
			var x scoperow
			if err = rows.Scan(&x.index, &x.enc, &x.sealed); err != nil {
				rows.Close()
				return err
			}
			scopes = append(scopes, x)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(scopes) == 0 {
			break
		}
		for _, row := range scopes {
			if ctx.Err() != nil || row.index <= after || !capacityIDExists(ctx, tx, row.enc, r.lock()) {
				return store.ErrNodeState
			}
			after = row.index
			raw, err := openCapacityRecord(key, row.index, row.enc, row.sealed)
			if err != nil {
				return store.ErrNodeState
			}
			var scope selectedParentScope
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			e := dec.Decode(&scope)
			tail := dec.Decode(new(any))
			clear(raw)
			if e != nil || tail != io.EOF || !nodeHashPattern.MatchString(scope.ParentID) || !nodeIDPattern.MatchString(scope.MemberID) || selectedParentIndex(key, scope.ParentID) != row.index || scope.Count < 1 || scope.Bytes < scope.Count || scope.Bytes > store.MaxStorageAllocation {
				return store.ErrNodeState
			}
			var count, total int64
			childAfter := ""
			for {
				childRows, e := tx.QueryContext(ctx, "SELECT operation_index,upload_index,member_index,blob_index,encryption_id,sealed FROM selected_upload_intents WHERE parent_index=? AND state='pending' AND operation_index>? ORDER BY operation_index LIMIT 64", row.index, childAfter)
				if e != nil {
					return e
				}
				batch := make([]intentrow, 0, 64)
				for childRows.Next() {
					var x intentrow
					if e = childRows.Scan(&x.index, &x.upload, &x.member, &x.blob, &x.enc, &x.sealed); e != nil {
						childRows.Close()
						return e
					}
					batch = append(batch, x)
				}
				e = childRows.Err()
				childRows.Close()
				if e != nil {
					return e
				}
				if len(batch) == 0 {
					break
				}
				for _, x := range batch {
					if ctx.Err() != nil || x.index <= childAfter || !capacityIDExists(ctx, tx, x.enc, r.lock()) {
						return store.ErrNodeState
					}
					childAfter = x.index
					raw, e := openCapacityRecord(key, x.index, x.enc, x.sealed)
					if e != nil {
						return store.ErrNodeState
					}
					var selected selectedOpaqueIntent
					d := json.NewDecoder(bytes.NewReader(raw))
					d.DisallowUnknownFields()
					e = d.Decode(&selected)
					tail = d.Decode(new(any))
					clear(raw)
					capacity := selected.Capacity.capacity()
					if e != nil || tail != io.EOF || selected.State != "pending" || selected.CompletionBinding != "" || !validOpaqueCapacity(capacity) || capacity.Bytes <= 0 || selected.ParentID != scope.ParentID || capacity.MemberID != scope.MemberID || x.index != opaqueCapacityIndex(key, capacity.OperationID) || x.upload != selectedUploadIndex(key, selected.UploadID) || x.member != opaqueCapacityMemberIndex(key, capacity.MemberID) || x.blob != opaqueCapacityBlobIndex(key, capacity.BlobID) || !nodeIDPattern.MatchString(selected.UploadID) || !nodeHashPattern.MatchString(selected.AdminBinding) || !validSelectedOwnerBinding(selected) || selected.Revision < 1 || !nodeHashPattern.MatchString(selected.OriginBinding) || !nodeHashPattern.MatchString(selected.PendingBinding) || !nodeHashPattern.MatchString(selected.MasterBinding) {
						return store.ErrNodeState
					}
					var member, blob, enc string
					var ciphertext []byte
					if e = tx.QueryRowContext(ctx, "SELECT member_index,blob_index,encryption_id,sealed FROM sealed_tree_capacity_intents WHERE operation_index=?"+r.lock(), x.index).Scan(&member, &blob, &enc, &ciphertext); e != nil || member != x.member || blob != x.blob || !capacityIDExists(ctx, tx, enc, r.lock()) {
						return store.ErrNodeState
					}
					original, e := openOpaqueCapacity(key, x.index, enc, ciphertext)
					if e != nil || original != capacity || total > store.MaxStorageAllocation-capacity.Bytes {
						return store.ErrNodeState
					}
					total += capacity.Bytes
					count++
				}
			}
			if count != scope.Count || total != scope.Bytes {
				return store.ErrNodeState
			}
			account, _, ok, err := r.readOpaqueCapacityAccount(ctx, tx, key, scope.MemberID, r.lock())
			if err != nil || !ok || account.Total < scope.Bytes {
				return store.ErrNodeState
			}
		}
	}
	// Detect child rows whose scope was deleted; the maintenance transaction is
	// exclusive, so this view cannot race an authorized ledger mutation.
	var orphan string
	err := tx.QueryRowContext(ctx, "SELECT i.operation_index FROM selected_upload_intents i LEFT JOIN selected_upload_parent_scopes s ON s.parent_index=i.parent_index WHERE i.state='pending' AND s.parent_index IS NULL LIMIT 1").Scan(&orphan)
	if !errors.Is(err, sql.ErrNoRows) {
		return store.ErrNodeState
	}
	return nil
}
