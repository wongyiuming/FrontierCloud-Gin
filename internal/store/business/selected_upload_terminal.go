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

// selectedIntentAnyTx authenticates a durable active or terminal selected
// intent. The plain state column is only an index; the encrypted copy must
// match. Callers must separately authorize the request and validate any Owner
// receipt or tree completion record before returning a terminal result.
func (r *Repository) selectedIntentAnyTx(ctx context.Context, q queryer, key []byte, uploadID string) (selectedOpaqueIntent, string, bool, error) {
	var zero selectedOpaqueIntent
	if ctx == nil || q == nil || !validCapacityKey(key) || !nodeIDPattern.MatchString(uploadID) || checkCapacityVerifier(ctx, q, key) != nil {
		return zero, "", false, store.ErrNodeState
	}
	var index, uploadIndex, parentIndex, memberIndex, blobIndex, id, state string
	var sealed []byte
	err := q.QueryRowContext(ctx, "SELECT operation_index,upload_index,parent_index,member_index,blob_index,encryption_id,sealed,state FROM selected_upload_intents WHERE upload_index=?"+r.lock(), selectedUploadIndex(key, uploadID)).Scan(&index, &uploadIndex, &parentIndex, &memberIndex, &blobIndex, &id, &sealed, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, "", false, nil
	}
	if err != nil || !capacityIDExists(ctx, q, id, r.lock()) {
		return zero, "", false, store.ErrNodeState
	}
	raw, err := openCapacityRecord(key, index, id, sealed)
	if err != nil {
		return zero, "", false, store.ErrNodeState
	}
	defer clear(raw)
	var selected selectedOpaqueIntent
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&selected) != nil || dec.Decode(new(any)) != io.EOF {
		return zero, "", false, store.ErrNodeState
	}
	capacity := selected.Capacity.capacity()
	validState := state == "pending" && selected.CompletionBinding == "" || state == "completed" && !selected.CancelRequested && nodeHashPattern.MatchString(selected.CompletionBinding) || state == "cancelled" && selected.CancelRequested && nodeHashPattern.MatchString(selected.CompletionBinding)
	if !validState || selected.State != state || !validOpaqueCapacity(capacity) || capacity.Bytes <= 0 || selected.UploadID != uploadID || uploadIndex != selectedUploadIndex(key, uploadID) || index != opaqueCapacityIndex(key, capacity.OperationID) || parentIndex != selectedParentIndex(key, selected.ParentID) || memberIndex != opaqueCapacityMemberIndex(key, capacity.MemberID) || blobIndex != opaqueCapacityBlobIndex(key, capacity.BlobID) || !nodeHashPattern.MatchString(selected.ParentID) || !nodeHashPattern.MatchString(selected.AdminBinding) || !validSelectedOwnerBinding(selected) || selected.Revision < 1 || !nodeHashPattern.MatchString(selected.OriginBinding) || !nodeHashPattern.MatchString(selected.PendingBinding) || !nodeHashPattern.MatchString(selected.MasterBinding) {
		return zero, "", false, store.ErrNodeState
	}
	return selected, id, true, nil
}
