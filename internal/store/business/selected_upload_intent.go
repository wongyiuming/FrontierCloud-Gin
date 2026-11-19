package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// selectedOpaqueIntent is trusted Master state. This dormant transaction does
// not authenticate an Admin session, verify a public endpoint, enforce sealed
// tree folder affinity, issue a capability, or register an upload route.
type selectedCapacity struct {
	OperationID string `json:"o"`
	MasterID    string `json:"m"`
	MemberID    string `json:"n"`
	BlobID      string `json:"b"`
	Digest      string `json:"d"`
	Bytes       int64  `json:"s"`
}

func validSelectedTransport(policy, origin string) bool {
	return policy == "Direct" && validPublicOrigin(origin) || (policy == "Relay" || policy == "Local" || policy == "S3") && origin == ""
}

func validSelectedOwnerBinding(v selectedOpaqueIntent) bool {
	capacity := v.Capacity.capacity()
	if v.Policy == "Local" {
		return capacity.MemberID == capacity.MasterID && v.Revision == 1 && v.RelationshipID == "" && v.RelationshipBinding == ""
	}
	if v.Policy == "S3" {
		return capacity.MemberID != capacity.MasterID && v.RelationshipID == "" && nodeHashPattern.MatchString(v.RelationshipBinding)
	}
	return (v.Policy == "Direct" || v.Policy == "Relay") && capacity.MemberID != capacity.MasterID && nodeIDPattern.MatchString(v.RelationshipID) && nodeHashPattern.MatchString(v.RelationshipBinding)
}

// selectedPendingBinding authenticates the actual pending tree identity and
// complete encryption descriptor against the selected upload intent. It does
// not expose the descriptor, logical name or identifiers to an Owner.
func selectedPendingBinding(key []byte, pending sealedtree.SelectedPending) (string, error) {
	if !validCapacityKey(key) || !nodeHashPattern.MatchString(pending.OperationID) || !nodeHashPattern.MatchString(pending.ObjectID) || !nodeHashPattern.MatchString(pending.ParentID) || pending.Name == "" || pending.Placement.ObjectID != pending.ObjectID || !nodeIDPattern.MatchString(pending.Placement.OwnerID) || !nodeHashPattern.MatchString(pending.Placement.BlobID) || !nodeHashPattern.MatchString(pending.Placement.ReadAlias) || !nodeHashPattern.MatchString(pending.Placement.SHA256) || !nodeIDPattern.MatchString(pending.Admission.UploadID) || !nodeHashPattern.MatchString(pending.Admission.AdminBinding) || !validSelectedTransport(pending.Admission.Policy, pending.Admission.Origin) || pending.Admission.Revision < 1 {
		return "", store.ErrNodeState
	}
	descriptor, err := protocol.IngressMediaDescriptor(pending.Placement.Bytes, pending.Placement.Encryption)
	if err != nil || descriptor != pending.Descriptor {
		return "", store.ErrNodeState
	}
	canonical, err := json.Marshal(struct {
		OperationID string                        `json:"operation_id"`
		ObjectID    string                        `json:"object_id"`
		ParentID    string                        `json:"parent_id"`
		Name        string                        `json:"name"`
		OwnerID     string                        `json:"owner_id"`
		BlobID      string                        `json:"blob_id"`
		Alias       string                        `json:"alias"`
		Bytes       int64                         `json:"bytes"`
		Digest      string                        `json:"digest"`
		Descriptor  string                        `json:"descriptor"`
		Admission   sealedtree.SelectedUploadFact `json:"admission"`
	}{pending.OperationID, pending.ObjectID, pending.ParentID, pending.Name, pending.Placement.OwnerID, pending.Placement.BlobID, pending.Placement.ReadAlias, pending.Placement.Bytes, pending.Placement.SHA256, descriptor, pending.Admission})
	if err != nil {
		return "", store.ErrNodeState
	}
	defer clear(canonical)
	return hex.EncodeToString(capacityMAC(key, "selected-pending-binding-v1", canonical)), nil
}

// verifySelectedPendingBinding reauthenticates a recovered tree record against
// the selected reservation. Neither this comparison nor historical recovery
// proves that the Owner still has the same bytes or that a new Admin is allowed.
func verifySelectedPendingBinding(key []byte, selected selectedOpaqueIntent, pending sealedtree.SelectedPending) error {
	binding, err := selectedPendingBinding(key, pending)
	capacity := selected.Capacity.capacity()
	if err != nil || binding != selected.PendingBinding || pending.OperationID != capacity.OperationID || pending.ParentID != selected.ParentID || pending.Placement.OwnerID != capacity.MemberID || pending.Placement.BlobID != capacity.BlobID || pending.Placement.Bytes != capacity.Bytes || pending.Placement.SHA256 != capacity.Digest || pending.Admission.UploadID != selected.UploadID || pending.Admission.AdminBinding != selected.AdminBinding || pending.Admission.Policy != selected.Policy || pending.Admission.Revision != selected.Revision || selectedOriginBinding(key, pending.Admission.Origin) != selected.OriginBinding {
		return store.ErrNodeState
	}
	return nil
}

func selectedCapacityFrom(v OpaqueCapacityIntent) selectedCapacity {
	return selectedCapacity{OperationID: v.OperationID, MasterID: v.MasterID, MemberID: v.MemberID, BlobID: v.BlobID, Digest: v.Digest, Bytes: v.Bytes}
}

func (v selectedCapacity) capacity() OpaqueCapacityIntent {
	return OpaqueCapacityIntent{OperationID: v.OperationID, MasterID: v.MasterID, MemberID: v.MemberID, BlobID: v.BlobID, Digest: v.Digest, Bytes: v.Bytes}
}

type selectedOpaqueIntent struct {
	State               string           `json:"s"`
	CancelRequested     bool             `json:"x,omitempty"`
	CompletionBinding   string           `json:"f,omitempty"`
	Capacity            selectedCapacity `json:"c"`
	UploadID            string           `json:"u"`
	ParentID            string           `json:"d"`
	AdminBinding        string           `json:"a"`
	Policy              string           `json:"p"`
	Revision            int64            `json:"v"`
	OriginBinding       string           `json:"o"`
	PendingBinding      string           `json:"t"`
	MasterBinding       string           `json:"m"`
	RelationshipID      string           `json:"r"`
	RelationshipBinding string           `json:"b"`
}

func selectedUploadIndex(key []byte, upload string) string {
	return hex.EncodeToString(capacityMAC(key, "selected-upload-id-v1", []byte(upload)))
}

func selectedOriginBinding(key []byte, origin string) string {
	return hex.EncodeToString(capacityMAC(key, "selected-origin-v1", []byte(origin)))
}

func selectedParentIndex(key []byte, parent string) string {
	return hex.EncodeToString(capacityMAC(key, "selected-upload-parent-v1", []byte(parent)))
}

// selectedParentScope is authoritative only while all updates to its selected
// intents and capacity reservations occur in the same trusted Master transaction.
// Restores must audit the full ledger before enabling this dormant prototype.
type selectedParentScope struct {
	ParentID string `json:"p"`
	MemberID string `json:"m"`
	Count    int64  `json:"c"`
	Bytes    int64  `json:"b"`
}

func (r *Repository) readSelectedParentScope(ctx context.Context, q queryer, key []byte, parent, owner string) (selectedParentScope, bool, error) {
	index := selectedParentIndex(key, parent)
	var enc string
	var sealed []byte
	err := q.QueryRowContext(ctx, "SELECT encryption_id,sealed FROM selected_upload_parent_scopes WHERE parent_index=?"+r.lock(), index).Scan(&enc, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		var existing string
		err = q.QueryRowContext(ctx, "SELECT operation_index FROM selected_upload_intents WHERE parent_index=? AND state='pending' LIMIT 1", index).Scan(&existing)
		if !errors.Is(err, sql.ErrNoRows) {
			return selectedParentScope{}, false, store.ErrNodeState
		}
		return selectedParentScope{ParentID: parent, MemberID: owner}, false, nil
	}
	if err != nil || !capacityIDExists(ctx, q, enc, r.lock()) {
		return selectedParentScope{}, false, store.ErrNodeState
	}
	raw, err := openCapacityRecord(key, index, enc, sealed)
	if err != nil {
		return selectedParentScope{}, false, store.ErrNodeState
	}
	defer clear(raw)
	var scope selectedParentScope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&scope) != nil || decoder.Decode(new(any)) != io.EOF || scope.ParentID != parent || scope.MemberID != owner || scope.Count < 1 || scope.Bytes < scope.Count || scope.Bytes > store.MaxStorageAllocation {
		return selectedParentScope{}, false, store.ErrNodeState
	}
	// A missing entire child ledger is a partial failure, not permission to reset.
	var existing int64
	if err = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM selected_upload_intents WHERE parent_index=? AND state='pending'", index).Scan(&existing); err != nil || existing != scope.Count {
		return selectedParentScope{}, false, store.ErrNodeState
	}
	account, _, ok, err := r.readOpaqueCapacityAccount(ctx, q, key, owner, r.lock())
	if err != nil || !ok || account.Total < scope.Bytes {
		return selectedParentScope{}, false, store.ErrNodeState
	}
	return scope, true, nil
}

func (r *Repository) writeSelectedParentScope(ctx context.Context, q queryer, key []byte, scope selectedParentScope, exists bool) error {
	if scope.Count < 1 || scope.Bytes < scope.Count || scope.Bytes > store.MaxStorageAllocation {
		return store.ErrNodeState
	}
	index := selectedParentIndex(key, scope.ParentID)
	raw, err := json.Marshal(scope)
	if err != nil {
		return store.ErrNodeState
	}
	defer clear(raw)
	enc, sealed, err := sealCapacityRecord(key, index, raw)
	if err != nil {
		return err
	}
	if _, err = q.ExecContext(ctx, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", enc); err != nil {
		return store.ErrNodeState
	}
	var result sql.Result
	if exists {
		result, err = q.ExecContext(ctx, "UPDATE selected_upload_parent_scopes SET encryption_id=?,sealed=? WHERE parent_index=?", enc, sealed, index)
	} else {
		result, err = q.ExecContext(ctx, "INSERT INTO selected_upload_parent_scopes(parent_index,encryption_id,sealed) VALUES(?,?,?)", index, enc, sealed)
	}
	if err != nil {
		return store.ErrNodeState
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return store.ErrNodeState
	}
	return nil
}

// reserveSelectedOpaqueCapacity is deliberately unexported until callers can
// hold an authenticated Admin/session fence and a sealed-tree folder-ownership
// fence through authorization and ticket issuance. It currently implements
// only an applied Direct Follower, and explicitly rejects MasterLocal, Relay,
// and S3 rather than silently choosing another owner or transport.
func (r *Repository) reserveSelectedOpaqueCapacity(ctx context.Context, key []byte, capacity OpaqueCapacityIntent, uploadID, parentID, adminBinding string, revision int64, origin string, free int64, pendingBinding string) (bool, error) {
	if ctx == nil || !validCapacityKey(key) || !validOpaqueCapacity(capacity) || capacity.Bytes <= 0 || !nodeIDPattern.MatchString(uploadID) || !nodeHashPattern.MatchString(parentID) || !nodeHashPattern.MatchString(adminBinding) || revision < 1 || !validPublicOrigin(origin) || !nodeHashPattern.MatchString(pendingBinding) {
		return false, store.ErrNodeState
	}
	return r.reserveOpaqueCapacity(ctx, key, capacity, free, r.selectedCapacityPreparation(ctx, key, capacity, uploadID, parentID, adminBinding, "Direct", revision, origin, pendingBinding))
}

// selectedCapacityPreparation validates and writes selected state on the
// transaction owned by the trusted coordinator. It does not start a commit.
func (r *Repository) selectedCapacityPreparation(ctx context.Context, key []byte, capacity OpaqueCapacityIntent, uploadID, parentID, adminBinding, policy string, revision int64, origin, pendingBinding string) func(queryer, store.NodeIdentity) error {
	return func(q queryer, identity store.NodeIdentity) error {
		if identity.PrivateKey == "" || identity.CreatedAt <= 0 || !validSelectedTransport(policy, origin) {
			return store.ErrNodeState
		}
		member, err := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), capacity.MemberID))
		if err != nil {
			return store.ErrNodeState
		}
		var relationID, relationBinding string
		if policy == "Local" {
			if capacity.MemberID != identity.ID || member.Kind != "MasterLocal" || member.RelationshipID != nil || revision != 1 {
				return store.ErrNodeState
			}
		} else if policy == "S3" {
			if capacity.MemberID == identity.ID || member.Kind != "S3" || member.Transport != "S3" || member.RelationshipID != nil {
				return store.ErrNodeState
			}
			current, err := r.s3Member(ctx, q, member.ID, r.lock())
			if err != nil || current.Revision != revision {
				return store.ErrNodeState
			}
			relationBinding, err = selectedS3MemberBinding(key, current, time.Now().Unix())
			if err != nil {
				return err
			}
		} else {
			if capacity.MemberID == identity.ID || member.Kind != "Follower" || member.RelationshipID == nil {
				return store.ErrNodeState
			}
			relation, err := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), *member.RelationshipID))
			now := time.Now().Unix()
			if err != nil || relation.PeerID != member.ID || relation.Direction != "downstream" || relation.State != "active" || relation.Status != "online" || relation.Protocol != protocol.Version || relation.Endpoint == "" || relation.Credential == "" || relation.CreatedAt <= 0 || relation.LastHeartbeat <= 0 || now-relation.LastHeartbeat < 0 || now-relation.LastHeartbeat >= 120 {
				return store.ErrNodeState
			}
			if pub, err := protocol.Decode(relation.PublicKey); err != nil || len(pub) != 32 {
				return store.ErrNodeState
			}
			var desired string
			var currentRevision int64
			if err = q.QueryRowContext(ctx, "SELECT configured_transport,revision FROM native_transport_policy WHERE member_id=?"+r.lock(), member.ID).Scan(&desired, &currentRevision); err != nil || desired != policy || currentRevision != revision {
				return store.ErrNodeState
			}
			encoded, err := json.Marshal(relation.Summary[nativeTransportReceiptKey])
			var receipt nativeTransportReceipt
			if err != nil || json.Unmarshal(encoded, &receipt) != nil || receipt.Transport != policy || receipt.Revision != revision || receipt.Origin != origin || policy == "Direct" && relation.Summary["native_resource_origin"] != origin {
				return store.ErrNodeState
			}
			relationID = relation.ID
			relationBinding = store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt})
		}
		expected := selectedOpaqueIntent{State: "pending", Capacity: selectedCapacityFrom(capacity), UploadID: uploadID, ParentID: parentID, AdminBinding: adminBinding, Policy: policy, Revision: revision, OriginBinding: selectedOriginBinding(key, origin), PendingBinding: pendingBinding, MasterBinding: capacityMasterBinding(identity), RelationshipID: relationID, RelationshipBinding: relationBinding}
		index := opaqueCapacityIndex(key, capacity.OperationID)
		uploadIndex := selectedUploadIndex(key, uploadID)
		parentIndex := selectedParentIndex(key, parentID)
		memberIndex, blobIndex := opaqueCapacityMemberIndex(key, capacity.MemberID), opaqueCapacityBlobIndex(key, capacity.BlobID)
		scope, scopeExists, err := r.readSelectedParentScope(ctx, q, key, parentID, capacity.MemberID)
		if err != nil {
			return err
		}
		var storedUpload, storedMember, storedParent, storedBlob, encID, state string
		var sealed []byte
		err = q.QueryRowContext(ctx, "SELECT upload_index,member_index,parent_index,blob_index,encryption_id,sealed,state FROM selected_upload_intents WHERE operation_index=?"+r.lock(), index).Scan(&storedUpload, &storedMember, &storedParent, &storedBlob, &encID, &sealed, &state)
		var priorCapacity int
		if e := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM sealed_tree_capacity_intents WHERE operation_index=?", index).Scan(&priorCapacity); e != nil {
			return e
		}
		var migrationScope int
		if e := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM sealed_tree_capacity_scopes WHERE operation_index=?", index).Scan(&migrationScope); e != nil || migrationScope < 0 || migrationScope > 1 {
			return store.ErrNodeState
		}
		if err == nil {
			if priorCapacity != 1 || state != "pending" || storedUpload != uploadIndex || storedMember != memberIndex || storedParent != parentIndex || storedBlob != blobIndex || !capacityIDExists(ctx, q, encID, r.lock()) {
				return store.ErrNodeState
			}
			raw, err := openCapacityRecord(key, index, encID, sealed)
			if err != nil {
				return store.ErrNodeState
			}
			defer clear(raw)
			var stored selectedOpaqueIntent
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF || stored != expected {
				return store.ErrNodeState
			}
			if migrationScope != 0 {
				scope, found, e := r.selectedScopeTx(ctx, q, key, stored)
				if e != nil || !found || scope.PublishedSignature != "" || scope.CleanupSignature != "" || scope.Settled || scope.CompletionBinding != "" {
					return store.ErrNodeState
				}
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) || priorCapacity != 0 || migrationScope != 0 {
			return store.ErrNodeState
		}
		if scope.Count == int64(^uint64(0)>>1) || scope.Bytes > store.MaxStorageAllocation-capacity.Bytes {
			return store.ErrNodeState
		}
		scope.Count++
		scope.Bytes += capacity.Bytes
		if err := r.writeSelectedParentScope(ctx, q, key, scope, scopeExists); err != nil {
			return err
		}
		raw, err := json.Marshal(expected)
		if err != nil {
			return store.ErrNodeState
		}
		defer clear(raw)
		encID, sealed, err = sealCapacityRecord(key, index, raw)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", encID); err != nil {
			return store.ErrNodeState
		}
		if _, err = q.ExecContext(ctx, "INSERT INTO selected_upload_intents(operation_index,upload_index,member_index,parent_index,blob_index,encryption_id,sealed) VALUES(?,?,?,?,?,?,?)", index, uploadIndex, memberIndex, parentIndex, blobIndex, encID, sealed); err != nil {
			return store.ErrNodeState
		}
		return nil
	}
}

// recoverSelectedOpaqueCapacityTx reads a committed historical reservation by
// its stable upload ID. The caller must hold the same exclusive coordinator
// fences and a transaction, so a missing row is not confused with an ongoing
// writer. A recovered record does not authorize reissuing a capability: current
// session, policy, owner and directory authority must be checked separately.
func (r *Repository) recoverSelectedOpaqueCapacityTx(ctx context.Context, q queryer, key []byte, uploadID string) (selectedOpaqueIntent, bool, error) {
	var zero selectedOpaqueIntent
	if ctx == nil || q == nil || !validCapacityKey(key) || !nodeIDPattern.MatchString(uploadID) {
		return zero, false, store.ErrNodeState
	}
	if err := checkCapacityVerifier(ctx, q, key); err != nil {
		return zero, false, err
	}
	var index, uploadIndex, parentIndex, memberIndex, blobIndex, encID, state string
	var sealed []byte
	err := q.QueryRowContext(ctx, "SELECT operation_index,upload_index,parent_index,member_index,blob_index,encryption_id,sealed,state FROM selected_upload_intents WHERE upload_index=?"+r.lock(), selectedUploadIndex(key, uploadID)).Scan(&index, &uploadIndex, &parentIndex, &memberIndex, &blobIndex, &encID, &sealed, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil || !capacityIDExists(ctx, q, encID, r.lock()) {
		return zero, false, store.ErrNodeState
	}
	raw, err := openCapacityRecord(key, index, encID, sealed)
	if err != nil {
		return zero, false, store.ErrNodeState
	}
	defer clear(raw)
	var selected selectedOpaqueIntent
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&selected) != nil || dec.Decode(new(any)) != io.EOF {
		return zero, false, store.ErrNodeState
	}
	capacity := selected.Capacity.capacity()
	if state != "pending" || selected.State != state || selected.CancelRequested || selected.CompletionBinding != "" || !validOpaqueCapacity(capacity) || capacity.Bytes <= 0 || selected.UploadID != uploadID || uploadIndex != selectedUploadIndex(key, uploadID) || index != opaqueCapacityIndex(key, capacity.OperationID) || parentIndex != selectedParentIndex(key, selected.ParentID) || memberIndex != opaqueCapacityMemberIndex(key, capacity.MemberID) || blobIndex != opaqueCapacityBlobIndex(key, capacity.BlobID) || !nodeHashPattern.MatchString(selected.ParentID) || !nodeHashPattern.MatchString(selected.AdminBinding) || !validSelectedOwnerBinding(selected) || selected.Revision < 1 || !nodeHashPattern.MatchString(selected.OriginBinding) || !nodeHashPattern.MatchString(selected.PendingBinding) || !nodeHashPattern.MatchString(selected.MasterBinding) {
		return zero, false, store.ErrNodeState
	}
	identity, err := readNode(ctx, q, r.lock())
	if err != nil || identity.ID != capacity.MasterID || identity.Role != "Master" || capacityMasterBinding(identity) != selected.MasterBinding {
		return zero, false, store.ErrNodeState
	}
	var oldMember, oldBlob, oldID string
	var oldSealed []byte
	if q.QueryRowContext(ctx, "SELECT member_index,blob_index,encryption_id,sealed FROM sealed_tree_capacity_intents WHERE operation_index=?"+r.lock(), index).Scan(&oldMember, &oldBlob, &oldID, &oldSealed) != nil || oldMember != memberIndex || oldBlob != blobIndex || !capacityIDExists(ctx, q, oldID, r.lock()) {
		return zero, false, store.ErrNodeState
	}
	old, err := openOpaqueCapacity(key, index, oldID, oldSealed)
	if err != nil || old != capacity {
		return zero, false, store.ErrNodeState
	}
	if _, exists, err := r.readSelectedParentScope(ctx, q, key, selected.ParentID, capacity.MemberID); err != nil || !exists {
		return zero, false, store.ErrNodeState
	}
	member, err := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), capacity.MemberID))
	if err != nil {
		return zero, false, store.ErrNodeState
	}
	account, _, exists, err := r.readOpaqueCapacityAccount(ctx, q, key, capacity.MemberID, r.lock())
	if err != nil || !exists || account.Total < capacity.Bytes || member.Reserved < account.Total {
		return zero, false, store.ErrNodeState
	}
	return selected, true, nil
}
