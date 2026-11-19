package business

// Isolated encrypted capacity reservations for preproduction import. These
// methods do not publish objects, authorize imports, release reservations or
// activate the sealed tree. The capacity key is domain-separated and Master-only.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// OpaqueCapacityIntent is trusted Master memory. No media path, title or raw
// object ID is persisted; operation and blob must be independent random IDs.
type OpaqueCapacityIntent struct {
	OperationID string `json:"operation_id"`
	MasterID    string `json:"master_id"`
	MemberID    string `json:"member_id"`
	BlobID      string `json:"blob_id"`
	Digest      string `json:"digest"`
	Bytes       int64  `json:"bytes"`
}

func capacityMAC(key []byte, domain string, data []byte) []byte {
	return opaqueledger.MAC(key, domain, data)
}
func validCapacityKey(key []byte) bool { return opaqueledger.ValidKey(key) }
func validOpaqueCapacity(v OpaqueCapacityIntent) bool {
	empty := sha256.Sum256(nil)
	return nodeHashPattern.MatchString(v.OperationID) && nodeIDPattern.MatchString(v.MasterID) && nodeIDPattern.MatchString(v.MemberID) && nodeHashPattern.MatchString(v.BlobID) && nodeHashPattern.MatchString(v.Digest) && v.OperationID != v.BlobID && v.Bytes >= 0 && v.Bytes <= 10*store.GiB && (v.Bytes != 0 || v.Digest == hex.EncodeToString(empty[:]))
}
func opaqueCapacityIndex(key []byte, operation string) string {
	return hex.EncodeToString(capacityMAC(key, "operation", []byte(operation)))
}
func opaqueCapacityBlobIndex(key []byte, blob string) string {
	return hex.EncodeToString(capacityMAC(key, "blob", []byte(blob)))
}
func opaqueCapacityMemberIndex(key []byte, member string) string {
	return hex.EncodeToString(capacityMAC(key, "member", []byte(member)))
}

type opaqueCapacityAccount struct {
	MemberID string `json:"member_id"`
	Total    int64  `json:"total"`
	Revision int64  `json:"revision"`
}

func opaqueCapacityVerifier(key []byte) string {
	return opaqueledger.Verifier(key)
}
func checkCapacityVerifier(ctx context.Context, q queryer, key []byte) error {
	var verifier string
	if !validCapacityKey(key) || q.QueryRowContext(ctx, "SELECT verifier FROM sealed_tree_capacity_meta WHERE singleton=1").Scan(&verifier) != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(opaqueCapacityVerifier(key))) != 1 {
		return store.ErrNodeState
	}
	return nil
}

// VerifyOpaqueCapacityKey checks the durable verifier without initializing it.
func (r *Repository) VerifyOpaqueCapacityKey(ctx context.Context, key []byte) error {
	if r == nil || ctx == nil {
		return store.ErrNodeState
	}
	return checkCapacityVerifier(ctx, r.db, key)
}

func sealOpaqueCapacity(key []byte, index string, intent OpaqueCapacityIntent) (string, []byte, error) {
	raw, err := json.Marshal(intent)
	if err != nil {
		return "", nil, store.ErrNodeState
	}
	defer clear(raw)
	return sealCapacityRecord(key, index, raw)
}
func sealCapacityRecord(key []byte, index string, raw []byte) (string, []byte, error) {
	id, sealed, err := opaqueledger.Seal(key, index, raw)
	if errors.Is(err, opaqueledger.ErrInvalid) {
		return "", nil, store.ErrNodeState
	}
	return id, sealed, err
}
func openOpaqueCapacity(key []byte, index, encID string, sealed []byte) (OpaqueCapacityIntent, error) {
	var out OpaqueCapacityIntent
	raw, err := openCapacityRecord(key, index, encID, sealed)
	if err != nil {
		return out, err
	}
	defer clear(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&out) != nil || dec.Decode(new(any)) != io.EOF || !validOpaqueCapacity(out) || opaqueCapacityIndex(key, out.OperationID) != index {
		return OpaqueCapacityIntent{}, store.ErrNodeState
	}
	return out, nil
}
func openCapacityRecord(key []byte, index, encID string, sealed []byte) ([]byte, error) {
	raw, err := opaqueledger.Open(key, index, encID, sealed)
	if err != nil {
		return nil, store.ErrNodeState
	}
	return raw, nil
}
func (r *Repository) readOpaqueCapacityAccount(ctx context.Context, q queryer, key []byte, memberID, lock string) (opaqueCapacityAccount, string, bool, error) {
	index := opaqueCapacityMemberIndex(key, memberID)
	var encID string
	var sealed []byte
	err := q.QueryRowContext(ctx, "SELECT encryption_id,sealed FROM sealed_tree_capacity_accounts WHERE member_index=?"+lock, index).Scan(&encID, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		var prior string
		err := q.QueryRowContext(ctx, "SELECT operation_index FROM sealed_tree_capacity_intents WHERE member_index=? LIMIT 1"+lock, index).Scan(&prior)
		if !errors.Is(err, sql.ErrNoRows) {
			return opaqueCapacityAccount{}, "", false, store.ErrNodeState
		}
		return opaqueCapacityAccount{MemberID: memberID}, "", false, nil
	}
	if err != nil {
		return opaqueCapacityAccount{}, "", false, err
	}
	if !capacityIDExists(ctx, q, encID, lock) {
		return opaqueCapacityAccount{}, "", false, store.ErrNodeState
	}
	raw, err := openCapacityRecord(key, index, encID, sealed)
	if err != nil {
		return opaqueCapacityAccount{}, "", false, err
	}
	defer clear(raw)
	var account opaqueCapacityAccount
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&account) != nil || dec.Decode(new(any)) != io.EOF || account.MemberID != memberID || account.Total < 0 || account.Total > store.MaxStorageAllocation || account.Revision <= 0 {
		return opaqueCapacityAccount{}, "", false, store.ErrNodeState
	}
	return account, encID, true, nil
}

// InitializeOpaqueCapacityKey must be called only in an explicit offline
// initialization with all writers stopped. It never generates a replacement
// secret; an absent marker after data rollback needs external reconciliation.
func (r *Repository) InitializeOpaqueCapacityKey(ctx context.Context, key []byte) error {
	if ctx == nil || !validCapacityKey(key) {
		return store.ErrNodeState
	}
	return r.ingressWrite(ctx, func(q queryer) error {
		var verifier string
		err := q.QueryRowContext(ctx, "SELECT verifier FROM sealed_tree_capacity_meta WHERE singleton=1"+r.lock()).Scan(&verifier)
		if err == nil {
			if subtle.ConstantTimeCompare([]byte(verifier), []byte(opaqueCapacityVerifier(key))) != 1 {
				return store.ErrNodeState
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		for _, table := range []string{"sealed_tree_capacity_intents", "sealed_tree_capacity_accounts", "sealed_tree_capacity_scopes", "sealed_tree_capacity_ids"} {
			var count int
			if err = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
				return store.ErrNodeState
			}
		}
		_, err = q.ExecContext(ctx, "INSERT INTO sealed_tree_capacity_meta(singleton,verifier) VALUES(1,?)", opaqueCapacityVerifier(key))
		return err
	})
}

// ReserveOpaqueCapacity atomically binds an exact random operation to one
// member and increments the same reserved counter as normal uploads. A retry
// with the exact intent is idempotent; expiry never releases capacity. It does
// not authorize a source plan or accept an owner receipt. Call before taking
// an ingress shared lease: this transaction needs its exclusive writer fence.
// An idempotent retry proves only the stored accounting, not current member
// health, relationship, capacity or authority; those need a fresh admission.
func (r *Repository) ReserveOpaqueCapacity(ctx context.Context, key []byte, intent OpaqueCapacityIntent, localPhysicalFree int64) (bool, error) {
	return r.reserveOpaqueCapacity(ctx, key, intent, localPhysicalFree, nil)
}

// prepare runs inside the same fenced SQL transaction before accounting. It
// may add a domain-specific durable intent, but does not authorize a caller.
func (r *Repository) reserveOpaqueCapacity(ctx context.Context, key []byte, intent OpaqueCapacityIntent, localPhysicalFree int64, prepare func(queryer, store.NodeIdentity) error) (bool, error) {
	if ctx == nil || !validCapacityKey(key) || !validOpaqueCapacity(intent) || localPhysicalFree < 0 {
		return false, store.ErrNodeState
	}
	index := opaqueCapacityIndex(key, intent.OperationID)
	encID, sealed, err := sealOpaqueCapacity(key, index, intent)
	if err != nil {
		return false, err
	}
	var already bool
	err = r.ingressWrite(ctx, func(q queryer) error {
		var inner error
		already, inner = r.reserveOpaqueCapacityTx(ctx, q, key, intent, localPhysicalFree, prepare, index, encID, sealed, false)
		return inner
	})
	return already, err
}

// reserveOpaqueCapacityTx mutates only the transaction provided by the trusted
// repository coordinator. It does not start/commit a transaction or authorize
// a request; all Owner and ingress fences remain the caller's responsibility.
func (r *Repository) reserveOpaqueCapacityTx(ctx context.Context, q queryer, key []byte, intent OpaqueCapacityIntent, localPhysicalFree int64, prepare func(queryer, store.NodeIdentity) error, index, encID string, sealed []byte, allowSelectedS3 bool) (bool, error) {
	var already bool
	err := func() error {
		already = false
		if err := checkCapacityVerifier(ctx, q, key); err != nil {
			return err
		}
		identity, err := readNode(ctx, q, r.lock())
		if err != nil || identity.Role != "Master" || identity.ID != intent.MasterID {
			return store.ErrNodeState
		}
		if prepare == nil {
			var selected int
			if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM selected_upload_intents WHERE operation_index=?", index).Scan(&selected); err != nil || selected != 0 {
				return store.ErrNodeState
			}
		}
		if prepare != nil {
			if err := prepare(q, identity); err != nil {
				return err
			}
		}
		var priorMember, priorBlob, priorID string
		var prior []byte
		err = q.QueryRowContext(ctx, "SELECT member_index,blob_index,encryption_id,sealed FROM sealed_tree_capacity_intents WHERE operation_index=?"+r.lock(), index).Scan(&priorMember, &priorBlob, &priorID, &prior)
		if err == nil {
			old, e := openOpaqueCapacity(key, index, priorID, prior)
			if e != nil || old != intent || priorMember != opaqueCapacityMemberIndex(key, old.MemberID) || priorBlob != opaqueCapacityBlobIndex(key, old.BlobID) {
				return store.ErrNodeState
			}
			if !capacityIDExists(ctx, q, priorID, r.lock()) {
				return store.ErrNodeState
			}
			member, e := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), intent.MemberID))
			if e != nil {
				return store.ErrNodeState
			}
			settled, e := capacityScopeSettled(ctx, q, key, old, identity, r.lock())
			if e != nil {
				return store.ErrNodeState
			}
			account, _, exists, e := r.readOpaqueCapacityAccount(ctx, q, key, intent.MemberID, r.lock())
			if e != nil || !exists || !settled && account.Total < intent.Bytes || member.Reserved < account.Total {
				return store.ErrNodeState
			}
			already = true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		member, err := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), intent.MemberID))
		if err != nil || member.Kind != "MasterLocal" && member.Kind != "Follower" && !(allowSelectedS3 && prepare != nil && member.Kind == "S3" && member.Transport == "S3") {
			return store.ErrStorageCapacity
		}
		if member.Kind == "S3" {
			if member.ID == identity.ID || member.RelationshipID != nil {
				return store.ErrNodeState
			}
		} else if member.ID == identity.ID {
			if member.Kind != "MasterLocal" || member.RelationshipID != nil {
				return store.ErrNodeState
			}
			member.PhysicalFree = localPhysicalFree
		} else {
			if member.Kind != "Follower" || member.RelationshipID == nil {
				return store.ErrNodeState
			}
			var state, status, peer, direction string
			var last int64
			if err = q.QueryRowContext(ctx, "SELECT state,status,last_heartbeat,peer_id,direction FROM node_relationships WHERE relationship_id=?"+r.lock(), *member.RelationshipID).Scan(&state, &status, &last, &peer, &direction); err != nil || state != "active" || direction != "downstream" || peer != member.ID || status != "online" || last <= 0 || time.Now().Unix()-last < 0 || time.Now().Unix()-last >= 120 {
				return store.ErrStorageCapacity
			}
		}
		if member.Kind != "S3" {
			draining, err := r.migrationDraining(ctx, q, member.ID)
			if err != nil || draining {
				return store.ErrStorageCapacity
			}
		}
		if member.Allocation < 0 || member.Used < 0 || member.Reserved < 0 || member.PhysicalFree < 0 || member.Used > member.Allocation || member.Reserved > member.Allocation-member.Used {
			return store.ErrStorageCapacity
		}
		if member.Enabled == 0 || member.Writable == 0 || member.Health != "online" || member.Draining || (member.Kind != "S3" && (member.PhysicalFree < store.PhysicalReserve || member.Reserved > member.PhysicalFree-store.PhysicalReserve)) || capacity(member) < intent.Bytes {
			return store.ErrStorageCapacity
		}
		account, previousID, exists, err := r.readOpaqueCapacityAccount(ctx, q, key, member.ID, r.lock())
		if err != nil || member.Reserved < account.Total || account.Total > store.MaxStorageAllocation-intent.Bytes || account.Revision == int64(^uint64(0)>>1) {
			return store.ErrNodeState
		}
		account.Total += intent.Bytes
		account.Revision++
		accountRaw, err := json.Marshal(account)
		if err != nil {
			return store.ErrNodeState
		}
		accountID, accountSealed, err := sealCapacityRecord(key, opaqueCapacityMemberIndex(key, member.ID), accountRaw)
		clear(accountRaw)
		if err != nil {
			return err
		}
		for _, id := range []string{encID, accountID} {
			if _, err = q.ExecContext(ctx, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", id); err != nil {
				return store.ErrNodeState
			}
		}
		if _, err = q.ExecContext(ctx, "INSERT INTO sealed_tree_capacity_intents(operation_index,member_index,blob_index,encryption_id,sealed) VALUES(?,?,?,?,?)", index, opaqueCapacityMemberIndex(key, intent.MemberID), opaqueCapacityBlobIndex(key, intent.BlobID), encID, sealed); err != nil {
			return store.ErrNodeState
		}
		if exists {
			updated, e := q.ExecContext(ctx, "UPDATE sealed_tree_capacity_accounts SET encryption_id=?,sealed=? WHERE member_index=? AND encryption_id=?", accountID, accountSealed, opaqueCapacityMemberIndex(key, member.ID), previousID)
			if e != nil {
				return e
			}
			if n, e := updated.RowsAffected(); e != nil || n != 1 {
				return store.ErrNodeState
			}
		} else if _, err = q.ExecContext(ctx, "INSERT INTO sealed_tree_capacity_accounts(member_index,encryption_id,sealed) VALUES(?,?,?)", opaqueCapacityMemberIndex(key, member.ID), accountID, accountSealed); err != nil {
			return store.ErrNodeState
		}
		if intent.Bytes == 0 {
			// Do not depend on MySQL reporting an affected row for an unchanged
			// zero-byte counter. The locked member, intent and account still
			// commit atomically; no physical capacity is claimed as freed.
			return nil
		}
		updated, err := q.ExecContext(ctx, "UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes+?,physical_free_bytes=?,updated_at=? WHERE member_id=?", intent.Bytes, member.PhysicalFree, time.Now().Unix(), member.ID)
		if err != nil {
			return err
		}
		if n, e := updated.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		return nil
	}()
	return already, err
}

// RecoverOpaqueCapacity returns only a verified exact historical intent; it
// does not establish that capacity remains reserved, current owner authority,
// an authenticated tree completion or physical publication.
func (r *Repository) RecoverOpaqueCapacity(ctx context.Context, key []byte, operation string) (OpaqueCapacityIntent, bool, error) {
	var out OpaqueCapacityIntent
	if ctx == nil || !validCapacityKey(key) || !nodeHashPattern.MatchString(operation) {
		return out, false, store.ErrNodeState
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, false, err
	}
	defer tx.Rollback()
	if err = checkCapacityVerifier(ctx, tx, key); err != nil {
		return out, false, err
	}
	index := opaqueCapacityIndex(key, operation)
	var memberIndex, blobIndex, encID string
	var sealed []byte
	err = tx.QueryRowContext(ctx, "SELECT member_index,blob_index,encryption_id,sealed FROM sealed_tree_capacity_intents WHERE operation_index=?", index).Scan(&memberIndex, &blobIndex, &encID, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	out, err = openOpaqueCapacity(key, index, encID, sealed)
	if err != nil || memberIndex != opaqueCapacityMemberIndex(key, out.MemberID) || blobIndex != opaqueCapacityBlobIndex(key, out.BlobID) {
		return OpaqueCapacityIntent{}, false, store.ErrNodeState
	}
	var n int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sealed_tree_capacity_ids WHERE encryption_id=?", encID).Scan(&n); err != nil || n != 1 {
		return OpaqueCapacityIntent{}, false, store.ErrNodeState
	}
	identity, err := readNode(ctx, tx, "")
	if err != nil || identity.Role != "Master" || identity.ID != out.MasterID {
		return OpaqueCapacityIntent{}, false, store.ErrNodeState
	}
	settled, err := capacityScopeSettled(ctx, tx, key, out, identity, "")
	if err != nil {
		return OpaqueCapacityIntent{}, false, store.ErrNodeState
	}
	account, _, exists, err := r.readOpaqueCapacityAccount(ctx, tx, key, out.MemberID, "")
	if err != nil || !exists || !settled && account.Total < out.Bytes {
		return OpaqueCapacityIntent{}, false, store.ErrNodeState
	}
	member, err := scanMember(tx.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?", out.MemberID))
	if err != nil || member.Reserved < account.Total {
		return OpaqueCapacityIntent{}, false, store.ErrNodeState
	}
	if err = tx.Commit(); err != nil {
		return OpaqueCapacityIntent{}, false, err
	}
	return out, true, nil
}
