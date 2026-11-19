package business

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// These records are trusted Master memory. Only keyed indexes, random
// encryption IDs and fixed-size encrypted envelopes go to the ledger.
type nativeMigrationTaskRecord struct {
	TaskID, MasterID, SourceOwnerID, TargetOwnerID       string
	SourceRelationshipID, TargetRelationshipID           string
	SourceRelationshipBinding, TargetRelationshipBinding string
	PlanSHA                                              string
	UnitCount, ObjectCount, Bytes                        int64
}

type nativeMigrationUnitRecord struct {
	TaskID, UnitID            string
	Unit                      sealedtree.NativeMigrationUnit
	Bytes                     int64
	CommittedAt, CleanupAfter int64
}

type nativeMigrationObjectRecord struct {
	TaskID, UnitID     string
	Object             sealedtree.NativeMigrationObject
	SourceOperationID  string
	Expected           protocol.OpaqueMigrationTargetReceipt
	ChallengeExpiresAt int64
}

type nativeMigrationReceiptRecord struct {
	TaskID, UnitID, ObjectID string
	Receipt                  protocol.OpaqueMigrationTargetReceipt
	Signature                string
	AcceptedAt               int64
}

type nativeMigrationTerminalRecord struct {
	TaskID, State                                                string
	CommittedUnits, CommittedObjects, CommittedBytes, FinishedAt int64
}

func nativeMigrationTaskIndex(key []byte, taskID string) string {
	if !validCapacityKey(key) || !nodeIDPattern.MatchString(taskID) {
		return ""
	}
	return nativeMigrationIndex(key, "task", taskID)
}

func nativeMigrationUnitIndex(key []byte, taskID, unitID string) string {
	if !validCapacityKey(key) || !nodeIDPattern.MatchString(taskID) || !nodeHashPattern.MatchString(unitID) {
		return ""
	}
	return nativeMigrationIndex(key, "unit", taskID+unitID)
}

func nativeMigrationObjectIndex(key []byte, taskID, unitID, objectID string) string {
	if !validCapacityKey(key) || !nodeIDPattern.MatchString(taskID) || !nodeHashPattern.MatchString(unitID) || !nodeHashPattern.MatchString(objectID) {
		return ""
	}
	return nativeMigrationIndex(key, "object", taskID+unitID+objectID)
}

func nativeMigrationParentIndex(key []byte, parentID string) string {
	if !validCapacityKey(key) || !nodeHashPattern.MatchString(parentID) {
		return ""
	}
	return nativeMigrationIndex(key, "parent", parentID)
}

func nativeMigrationRetiredAliasIndex(key []byte, ownerID, alias string) string {
	if !validCapacityKey(key) || !nodeIDPattern.MatchString(ownerID) || !nodeHashPattern.MatchString(alias) {
		return ""
	}
	return nativeMigrationIndex(key, "retired-alias", ownerID+alias)
}

func nativeMigrationIndex(key []byte, kind, identity string) string {
	return hex.EncodeToString(capacityMAC(key, "native-migration-ledger-index/"+kind, []byte(identity)))
}

type nativeMigrationLedgerPhase string

const (
	nativeMigrationTaskPhase     nativeMigrationLedgerPhase = "task-intent"
	nativeMigrationUnitPhase     nativeMigrationLedgerPhase = "unit-intent"
	nativeMigrationObjectPhase   nativeMigrationLedgerPhase = "object-intent"
	nativeMigrationReceiptPhase  nativeMigrationLedgerPhase = "target-receipt"
	nativeMigrationTerminalPhase nativeMigrationLedgerPhase = "task-terminal"
)

func (p nativeMigrationLedgerPhase) padding() int {
	switch p {
	case nativeMigrationTaskPhase, nativeMigrationUnitPhase, nativeMigrationTerminalPhase:
		return 1024
	case nativeMigrationObjectPhase:
		return 4096
	case nativeMigrationReceiptPhase:
		return 2048
	default:
		return 0
	}
}

type nativeMigrationLedgerScope struct {
	task, unit, object string
}

type nativeMigrationLedgerValue interface {
	ledgerScope([]byte) (nativeMigrationLedgerScope, bool)
}

func nativeMigrationScope(key []byte, taskID, unitID, objectID string) nativeMigrationLedgerScope {
	return nativeMigrationLedgerScope{
		task:   nativeMigrationTaskIndex(key, taskID),
		unit:   nativeMigrationUnitIndex(key, taskID, unitID),
		object: nativeMigrationObjectIndex(key, taskID, unitID, objectID),
	}
}

func (s nativeMigrationLedgerScope) valid(phase nativeMigrationLedgerPhase) bool {
	if !nodeHashPattern.MatchString(s.task) {
		return false
	}
	switch phase {
	case nativeMigrationTaskPhase, nativeMigrationTerminalPhase:
		return s.unit == "" && s.object == ""
	case nativeMigrationUnitPhase:
		return nodeHashPattern.MatchString(s.unit) && s.object == ""
	case nativeMigrationObjectPhase, nativeMigrationReceiptPhase:
		return nodeHashPattern.MatchString(s.unit) && nodeHashPattern.MatchString(s.object)
	default:
		return false
	}
}

func validNativeMigrationTotals(units, objects, size int64) bool {
	return units > 0 && objects >= units && size >= 0 && (size == 0 || (size-1)/(10*store.GiB) < objects)
}

func (v nativeMigrationTaskRecord) ledgerScope(key []byte) (nativeMigrationLedgerScope, bool) {
	return nativeMigrationScope(key, v.TaskID, "", ""),
		nodeIDPattern.MatchString(v.MasterID) && nodeIDPattern.MatchString(v.SourceOwnerID) && nodeIDPattern.MatchString(v.TargetOwnerID) &&
			v.MasterID != v.SourceOwnerID && v.MasterID != v.TargetOwnerID && v.SourceOwnerID != v.TargetOwnerID &&
			nodeIDPattern.MatchString(v.SourceRelationshipID) && nodeIDPattern.MatchString(v.TargetRelationshipID) &&
			v.SourceRelationshipID != v.TargetRelationshipID && nodeHashPattern.MatchString(v.SourceRelationshipBinding) &&
			nodeHashPattern.MatchString(v.TargetRelationshipBinding) && v.SourceRelationshipBinding != v.TargetRelationshipBinding &&
			nodeHashPattern.MatchString(v.PlanSHA) && validNativeMigrationTotals(v.UnitCount, v.ObjectCount, v.Bytes)
}

func (v nativeMigrationUnitRecord) ledgerScope(key []byte) (nativeMigrationLedgerScope, bool) {
	u := v.Unit
	validTimes := v.CommittedAt == 0 && v.CleanupAfter == 0 ||
		v.CommittedAt > 0 && v.CleanupAfter >= v.CommittedAt && v.CleanupAfter-v.CommittedAt >= nativeMigrationCleanupGrace
	return nativeMigrationScope(key, v.TaskID, v.UnitID, ""),
		nodeHashPattern.MatchString(u.ParentID) && nodeIDPattern.MatchString(u.SourceOwnerID) &&
			nodeHashPattern.MatchString(u.Digest) && u.TreeGeneration > 0 && validNativeMigrationTotals(1, u.ObjectCount, v.Bytes) && validTimes
}

func (v nativeMigrationObjectRecord) ledgerScope(key []byte) (nativeMigrationLedgerScope, bool) {
	o, r := v.Object, v.Expected
	scope := nativeMigrationScope(key, v.TaskID, v.UnitID, o.ObjectID)
	if r.TaskID != v.TaskID || r.UnitID != v.UnitID || v.ChallengeExpiresAt <= 0 ||
		!nodeHashPattern.MatchString(o.NativeObjectID) || o.Kind != "audio" && o.Kind != "video" ||
		r.Source.Alias != o.ReadAlias || r.Source.Blob != o.BlobID || r.Source.Digest != o.SHA256 ||
		r.Source.Descriptor != o.Descriptor || r.Source.Revision != o.SourceRevision || r.Source.Size != o.Bytes ||
		!nodeHashPattern.MatchString(v.SourceOperationID) {
		return scope, false
	}
	for _, id := range []string{r.Source.Alias, r.Source.Blob, r.Target.Alias, r.Target.Blob, r.PublicationOperation, r.Challenge} {
		if id == o.ObjectID || id == o.NativeObjectID || id == v.SourceOperationID {
			return scope, false
		}
	}
	if v.SourceOperationID == o.ObjectID || v.SourceOperationID == o.NativeObjectID {
		return scope, false
	}
	_, err := r.Payload()
	return scope, err == nil
}

func (v nativeMigrationReceiptRecord) ledgerScope(key []byte) (nativeMigrationLedgerScope, bool) {
	scope := nativeMigrationScope(key, v.TaskID, v.UnitID, v.ObjectID)
	if v.Receipt.TaskID != v.TaskID || v.Receipt.UnitID != v.UnitID || v.AcceptedAt <= 0 ||
		len(v.Signature) != 86 {
		return scope, false
	}
	signature, err := protocol.Decode(v.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || protocol.Encode(signature) != v.Signature {
		return scope, false
	}
	_, err = v.Receipt.Payload()
	return scope, err == nil
}

func (v nativeMigrationTerminalRecord) ledgerScope(key []byte) (nativeMigrationLedgerScope, bool) {
	counts := validNativeMigrationTotals(v.CommittedUnits, v.CommittedObjects, v.CommittedBytes)
	if v.State == "cancelled" && v.CommittedUnits == 0 && v.CommittedObjects == 0 && v.CommittedBytes == 0 {
		counts = true
	}
	return nativeMigrationScope(key, v.TaskID, "", ""),
		(v.State == "completed" || v.State == "cancelled") && v.FinishedAt > 0 && counts
}

// verifyNativeMigrationReceipt binds the signed observation to the immutable
// admission and its original expiry, including after a worker restart.
// The caller authenticates targetPublic against the pinned live relationship.
func verifyNativeMigrationReceipt(object nativeMigrationObjectRecord, receipt nativeMigrationReceiptRecord, targetPublic string) error {
	if receipt.TaskID != object.TaskID || receipt.UnitID != object.UnitID || receipt.ObjectID != object.Object.ObjectID ||
		receipt.AcceptedAt <= 0 || receipt.AcceptedAt >= object.ChallengeExpiresAt ||
		protocol.VerifyOpaqueMigrationTargetReceipt(targetPublic, object.Expected, receipt.Receipt, receipt.Signature) != nil {
		return store.ErrMigrationState
	}
	return nil
}

func sealNativeMigrationTask(key []byte, value nativeMigrationTaskRecord) (string, []byte, error) {
	return sealNativeMigrationRecord(key, nativeMigrationTaskPhase, value)
}

func openNativeMigrationTask(key []byte, taskIndex, id string, sealed []byte) (nativeMigrationTaskRecord, error) {
	return openNativeMigrationRecord[nativeMigrationTaskRecord](key, nativeMigrationTaskPhase, nativeMigrationLedgerScope{task: taskIndex}, id, sealed)
}

func sealNativeMigrationUnit(key []byte, value nativeMigrationUnitRecord) (string, []byte, error) {
	return sealNativeMigrationRecord(key, nativeMigrationUnitPhase, value)
}

func openNativeMigrationUnit(key []byte, taskIndex, unitIndex, id string, sealed []byte) (nativeMigrationUnitRecord, error) {
	return openNativeMigrationRecord[nativeMigrationUnitRecord](key, nativeMigrationUnitPhase, nativeMigrationLedgerScope{task: taskIndex, unit: unitIndex}, id, sealed)
}

func sealNativeMigrationObject(key []byte, value nativeMigrationObjectRecord) (string, []byte, error) {
	return sealNativeMigrationRecord(key, nativeMigrationObjectPhase, value)
}

func openNativeMigrationObject(key []byte, taskIndex, unitIndex, objectIndex, id string, sealed []byte) (nativeMigrationObjectRecord, error) {
	return openNativeMigrationRecord[nativeMigrationObjectRecord](key, nativeMigrationObjectPhase, nativeMigrationLedgerScope{taskIndex, unitIndex, objectIndex}, id, sealed)
}

func sealNativeMigrationReceipt(key []byte, value nativeMigrationReceiptRecord) (string, []byte, error) {
	return sealNativeMigrationRecord(key, nativeMigrationReceiptPhase, value)
}

func openNativeMigrationReceipt(key []byte, taskIndex, unitIndex, objectIndex, id string, sealed []byte) (nativeMigrationReceiptRecord, error) {
	return openNativeMigrationRecord[nativeMigrationReceiptRecord](key, nativeMigrationReceiptPhase, nativeMigrationLedgerScope{taskIndex, unitIndex, objectIndex}, id, sealed)
}

func sealNativeMigrationTerminal(key []byte, value nativeMigrationTerminalRecord) (string, []byte, error) {
	return sealNativeMigrationRecord(key, nativeMigrationTerminalPhase, value)
}

func openNativeMigrationTerminal(key []byte, taskIndex, id string, sealed []byte) (nativeMigrationTerminalRecord, error) {
	return openNativeMigrationRecord[nativeMigrationTerminalRecord](key, nativeMigrationTerminalPhase, nativeMigrationLedgerScope{task: taskIndex}, id, sealed)
}

func nativeMigrationEnvelope(key []byte, phase nativeMigrationLedgerPhase, salt []byte) (string, cipher.AEAD, error) {
	derived := capacityMAC(key, "native-migration-ledger-cipher/"+string(phase), salt)
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return "", nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	id := hex.EncodeToString(capacityMAC(key, "native-migration-ledger-encryption-id/"+string(phase), salt))
	return id, aead, err
}

func nativeMigrationAAD(phase nativeMigrationLedgerPhase, scope nativeMigrationLedgerScope, id string) []byte {
	return []byte("frontiercloud:native-migration-ledger:v1\x00" + string(phase) + ":" + scope.task + ":" + scope.unit + ":" + scope.object + ":" + id)
}

const nativeMigrationEnvelopeHeader = 1 + 32
const nativeMigrationGCMOverhead = 12 + 16

func sealNativeMigrationRecord[T nativeMigrationLedgerValue](key []byte, phase nativeMigrationLedgerPhase, value T) (string, []byte, error) {
	scope, valid := value.ledgerScope(key)
	if !valid || !scope.valid(phase) {
		return "", nil, store.ErrMigrationState
	}
	raw, err := json.Marshal(value)
	defer clear(raw)
	size := phase.padding()
	if err != nil || len(raw) == 0 || len(raw) > size-2 {
		return "", nil, store.ErrMigrationState
	}
	plain := make([]byte, size)
	defer clear(plain)
	binary.BigEndian.PutUint16(plain[:2], uint16(len(raw)))
	copy(plain[2:], raw)
	sealed := make([]byte, nativeMigrationEnvelopeHeader, nativeMigrationEnvelopeHeader+size+nativeMigrationGCMOverhead)
	sealed[0] = 1
	if _, err := rand.Read(sealed[1:]); err != nil {
		return "", nil, err
	}
	id, aead, err := nativeMigrationEnvelope(key, phase, sealed[1:])
	if err != nil {
		return "", nil, err
	}
	return id, aead.Seal(sealed, nil, plain, nativeMigrationAAD(phase, scope, id)), nil
}

func openNativeMigrationRecord[T nativeMigrationLedgerValue](key []byte, phase nativeMigrationLedgerPhase, scope nativeMigrationLedgerScope, id string, sealed []byte) (T, error) {
	var value, zero T
	size := phase.padding()
	if !validCapacityKey(key) || !scope.valid(phase) || !nodeHashPattern.MatchString(id) ||
		len(sealed) != nativeMigrationEnvelopeHeader+size+nativeMigrationGCMOverhead || sealed[0] != 1 {
		return zero, store.ErrMigrationState
	}
	expected, aead, err := nativeMigrationEnvelope(key, phase, sealed[1:nativeMigrationEnvelopeHeader])
	if err != nil || !hmac.Equal([]byte(id), []byte(expected)) {
		return zero, store.ErrMigrationState
	}
	plain, err := aead.Open(nil, nil, sealed[nativeMigrationEnvelopeHeader:], nativeMigrationAAD(phase, scope, id))
	if err != nil {
		return zero, store.ErrMigrationState
	}
	defer clear(plain)
	n := int(binary.BigEndian.Uint16(plain[:2]))
	if n == 0 || n > len(plain)-2 {
		return zero, store.ErrMigrationState
	}
	for _, b := range plain[n+2:] {
		if b != 0 {
			return zero, store.ErrMigrationState
		}
	}
	dec := json.NewDecoder(bytes.NewReader(plain[2 : n+2]))
	dec.DisallowUnknownFields()
	if dec.Decode(&value) != nil || dec.Decode(new(any)) != io.EOF {
		return zero, store.ErrMigrationState
	}
	actual, valid := value.ledgerScope(key)
	if !valid || actual != scope {
		return zero, store.ErrMigrationState
	}
	return value, nil
}
