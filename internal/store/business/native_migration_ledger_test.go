package business

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func nativeMigrationLedgerFixture(t *testing.T) (nativeMigrationTaskRecord, nativeMigrationUnitRecord, nativeMigrationObjectRecord, nativeMigrationReceiptRecord, string) {
	t.Helper()
	hex := strings.Repeat
	meta, err := mediacrypto.NewMetadata(32)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := protocol.IngressMediaDescriptor(meta.CiphertextSize, &meta)
	if err != nil {
		t.Fatal(err)
	}
	task := nativeMigrationTaskRecord{
		TaskID: hex("1", 32), MasterID: hex("2", 32), SourceOwnerID: hex("3", 32), TargetOwnerID: hex("4", 32),
		SourceRelationshipID: hex("5", 32), TargetRelationshipID: hex("6", 32),
		SourceRelationshipBinding: hex("5", 64), TargetRelationshipBinding: hex("6", 64),
		PlanSHA: hex("f", 64), UnitCount: 1, ObjectCount: 1, Bytes: meta.CiphertextSize,
	}
	unit := nativeMigrationUnitRecord{
		TaskID: task.TaskID, UnitID: hex("1", 64), Bytes: task.Bytes,
		Unit: sealedtree.NativeMigrationUnit{ParentID: hex("2", 64), SourceOwnerID: task.SourceOwnerID, TreeGeneration: 7, Digest: hex("3", 64), ObjectCount: 1},
	}
	owner := func(id, relationship, alias, blob string) protocol.OpaqueOwnerBinding {
		digest := hex("4", 64)
		revision, err := protocol.OpaquePlacementRevisionFromDescriptor(alias, blob, digest, descriptor, task.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return protocol.OpaqueOwnerBinding{
			MasterID: task.MasterID, OwnerID: id, RelationshipID: relationship,
			Alias: alias, Blob: blob, Revision: revision, Digest: digest, Descriptor: descriptor, Size: task.Bytes,
		}
	}
	source := owner(task.SourceOwnerID, task.SourceRelationshipID, hex("7", 64), hex("8", 64))
	target := owner(task.TargetOwnerID, task.TargetRelationshipID, hex("9", 64), hex("a", 64))
	expected := protocol.OpaqueMigrationTargetReceipt{
		TaskID: task.TaskID, UnitID: unit.UnitID, PublicationOperation: hex("b", 64), Challenge: hex("c", 64),
		SourceRelationshipBinding: task.SourceRelationshipBinding, TargetRelationshipBinding: task.TargetRelationshipBinding,
		Source: source, Target: target,
	}
	object := nativeMigrationObjectRecord{
		TaskID: task.TaskID, UnitID: unit.UnitID, SourceOperationID: hex("d", 64), ChallengeExpiresAt: 160,
		Object: sealedtree.NativeMigrationObject{
			ObjectID: hex("e", 64), NativeObjectID: hex("0", 64), Kind: "audio", BlobID: source.Blob, ReadAlias: source.Alias,
			SHA256: source.Digest, Descriptor: source.Descriptor, SourceRevision: source.Revision, Bytes: source.Size,
		},
		Expected: expected,
	}
	payload, err := expected.Payload()
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.Encode(bytes.Repeat([]byte{19}, 32))
	signature, err := protocol.Sign(seed, payload)
	if err != nil {
		t.Fatal(err)
	}
	public, err := protocol.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	receipt := nativeMigrationReceiptRecord{TaskID: task.TaskID, UnitID: unit.UnitID, ObjectID: object.Object.ObjectID, Receipt: expected, Signature: signature, AcceptedAt: 159}
	return task, unit, object, receipt, public
}

func TestNativeMigrationLedgerTypedRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{11}, 32)
	task, unit, object, receipt, targetPublic := nativeMigrationLedgerFixture(t)
	terminal := nativeMigrationTerminalRecord{TaskID: task.TaskID, State: "completed", CommittedUnits: 1, CommittedObjects: 1, CommittedBytes: task.Bytes, FinishedAt: 200}
	taskIndex := nativeMigrationTaskIndex(key, task.TaskID)
	unitIndex := nativeMigrationUnitIndex(key, task.TaskID, unit.UnitID)
	objectIndex := nativeMigrationObjectIndex(key, task.TaskID, unit.UnitID, object.Object.ObjectID)
	rawObject, err := json.Marshal(object)
	if err != nil || len(rawObject) <= 1022 {
		t.Fatalf("fixture does not exercise larger nested receipt: %d, %v", len(rawObject), err)
	}
	taskID, taskSealed, err := sealNativeMigrationTask(key, task)
	if got, openErr := openNativeMigrationTask(key, taskIndex, taskID, taskSealed); err != nil || openErr != nil || got != task {
		t.Fatal(err, openErr)
	}
	unitID, unitSealed, err := sealNativeMigrationUnit(key, unit)
	if got, openErr := openNativeMigrationUnit(key, taskIndex, unitIndex, unitID, unitSealed); err != nil || openErr != nil || got != unit {
		t.Fatal(err, openErr)
	}
	objectID, objectSealed, err := sealNativeMigrationObject(key, object)
	if got, openErr := openNativeMigrationObject(key, taskIndex, unitIndex, objectIndex, objectID, objectSealed); err != nil || openErr != nil || got != object {
		t.Fatal(err, openErr)
	}
	receiptID, receiptSealed, err := sealNativeMigrationReceipt(key, receipt)
	gotReceipt, openErr := openNativeMigrationReceipt(key, taskIndex, unitIndex, objectIndex, receiptID, receiptSealed)
	if err != nil || openErr != nil || gotReceipt != receipt || verifyNativeMigrationReceipt(object, gotReceipt, targetPublic) != nil {
		t.Fatal(err, openErr)
	}
	terminalID, terminalSealed, err := sealNativeMigrationTerminal(key, terminal)
	if got, openErr := openNativeMigrationTerminal(key, taskIndex, terminalID, terminalSealed); err != nil || openErr != nil || got != terminal {
		t.Fatal(err, openErr)
	}
	for _, value := range []struct {
		envelope []byte
		size     int
	}{{taskSealed, 1085}, {unitSealed, 1085}, {objectSealed, 4157}, {receiptSealed, 2109}, {terminalSealed, 1085}} {
		if len(value.envelope) != value.size {
			t.Fatalf("expected fixed envelope size %d, got %d", value.size, len(value.envelope))
		}
		for _, identity := range []string{task.TaskID, unit.Unit.ParentID, object.Object.NativeObjectID, object.Expected.Target.Blob, object.Expected.Challenge, receipt.Signature} {
			if bytes.Contains(value.envelope, []byte(identity)) {
				t.Fatal("sealed envelope exposes private identity")
			}
		}
	}
	againID, again, err := sealNativeMigrationObject(key, object)
	if err != nil || objectID == againID || bytes.Equal(objectSealed, again) {
		t.Fatal("record sealing reused encryption material", err)
	}
}

func TestNativeMigrationLedgerUnitBindsCommitAndCleanupTimes(t *testing.T) {
	key := bytes.Repeat([]byte{16}, 32)
	task, unit, _, _, _ := nativeMigrationLedgerFixture(t)
	taskIndex := nativeMigrationTaskIndex(key, task.TaskID)
	unitIndex := nativeMigrationUnitIndex(key, task.TaskID, unit.UnitID)
	const commit = 100
	for _, test := range []struct {
		name                      string
		committedAt, cleanupAfter int64
		valid                     bool
	}{
		{"staged", 0, 0, true},
		{"committed", commit, commit + nativeMigrationCleanupGrace, true},
		{"missing_commit", 0, commit + nativeMigrationCleanupGrace, false},
		{"missing_cleanup", commit, 0, false},
		{"short_grace", commit, commit + nativeMigrationCleanupGrace - 1, false},
		{"backwards_cleanup", commit, commit - 1, false},
		{"negative_commit", -1, nativeMigrationCleanupGrace, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			unit.CommittedAt, unit.CleanupAfter = test.committedAt, test.cleanupAfter
			id, sealed, err := sealNativeMigrationUnit(key, unit)
			if test.valid {
				got, openErr := openNativeMigrationUnit(key, taskIndex, unitIndex, id, sealed)
				if err != nil || openErr != nil || got != unit {
					t.Fatal(got, err, openErr)
				}
				return
			}
			if !errors.Is(err, store.ErrMigrationState) {
				t.Fatal("invalid commit timestamps sealed", err)
			}
			scope := nativeMigrationLedgerScope{task: taskIndex, unit: unitIndex}
			id, sealed = sealNativeMigrationLedgerTestValue(t, key, nativeMigrationUnitPhase, scope, unit, false)
			if _, err := openNativeMigrationUnit(key, taskIndex, unitIndex, id, sealed); !errors.Is(err, store.ErrMigrationState) {
				t.Fatal("invalid authenticated commit timestamps opened", err)
			}
		})
	}
}

func TestNativeMigrationLedgerBindsPhaseAndEveryIndex(t *testing.T) {
	key := bytes.Repeat([]byte{12}, 32)
	task, unit, object, _, _ := nativeMigrationLedgerFixture(t)
	taskIndex, unitIndex, objectIndex := nativeMigrationTaskIndex(key, task.TaskID), nativeMigrationUnitIndex(key, task.TaskID, unit.UnitID), nativeMigrationObjectIndex(key, task.TaskID, unit.UnitID, object.Object.ObjectID)
	taskID, taskSealed, err := sealNativeMigrationTask(key, task)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openNativeMigrationTerminal(key, taskIndex, taskID, taskSealed); !errors.Is(err, store.ErrMigrationState) {
		t.Fatal("task accepted as same-size terminal envelope", err)
	}
	id, sealed, err := sealNativeMigrationObject(key, object)
	if err != nil {
		t.Fatal(err)
	}
	foreign := strings.Repeat("0", 64)
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	for _, item := range []struct {
		key                 []byte
		task, unit, obj, id string
		blob                []byte
	}{
		{key, foreign, unitIndex, objectIndex, id, sealed},
		{key, taskIndex, foreign, objectIndex, id, sealed},
		{key, taskIndex, unitIndex, foreign, id, sealed},
		{key, taskIndex, unitIndex, objectIndex, foreign, sealed},
		{key, taskIndex, unitIndex, objectIndex, id, tampered},
		{key, taskIndex, unitIndex, objectIndex, id, sealed[:len(sealed)-1]},
		{bytes.Repeat([]byte{13}, 32), taskIndex, unitIndex, objectIndex, id, sealed},
	} {
		if got, err := openNativeMigrationObject(item.key, item.task, item.unit, item.obj, item.id, item.blob); !errors.Is(err, store.ErrMigrationState) || got != (nativeMigrationObjectRecord{}) {
			t.Fatal("incorrect record binding accepted", err)
		}
	}
	// Even an authenticated envelope must rederive its tuple from its content.
	scope := nativeMigrationLedgerScope{taskIndex, unitIndex, foreign}
	wrongIndex, wrongIndexSealed := sealNativeMigrationLedgerTestValue(t, key, nativeMigrationObjectPhase, scope, object, false)
	if _, err := openNativeMigrationObject(key, taskIndex, unitIndex, foreign, wrongIndex, wrongIndexSealed); !errors.Is(err, store.ErrMigrationState) {
		t.Fatal("content identity did not bind authenticated column indexes", err)
	}
	taskScope := nativeMigrationLedgerScope{task: taskIndex}
	for _, extra := range []bool{false, true} {
		value := any(task)
		if !extra {
			value = struct {
				nativeMigrationTaskRecord
				Path string
			}{task, "music/private.mp3"}
		}
		id, sealed := sealNativeMigrationLedgerTestValue(t, key, nativeMigrationTaskPhase, taskScope, value, extra)
		if _, err := openNativeMigrationTask(key, taskIndex, id, sealed); !errors.Is(err, store.ErrMigrationState) {
			t.Fatal("noncanonical payload accepted", err)
		}
	}
	parent := nativeMigrationParentIndex(key, object.Object.ObjectID)
	alias := nativeMigrationRetiredAliasIndex(key, task.SourceOwnerID, object.Object.ObjectID)
	if parent == objectIndex || alias == parent || alias == objectIndex || parent == object.Object.ObjectID ||
		alias == nativeMigrationRetiredAliasIndex(key, task.TargetOwnerID, object.Object.ObjectID) ||
		unitIndex == nativeMigrationUnitIndex(key, task.SourceOwnerID, unit.UnitID) ||
		objectIndex == nativeMigrationObjectIndex(key, task.TaskID, object.Object.ObjectID, object.Object.ObjectID) ||
		nativeMigrationTaskIndex(key, "music/path") != "" || nativeMigrationParentIndex(make([]byte, 32), unit.Unit.ParentID) != "" {
		t.Fatal("index domain or scope separation failed")
	}
}

func sealNativeMigrationLedgerTestValue(t *testing.T, key []byte, phase nativeMigrationLedgerPhase, scope nativeMigrationLedgerScope, value any, corruptPadding bool) (string, []byte) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil || len(raw) >= phase.padding()-2 {
		t.Fatal(err)
	}
	plain := make([]byte, phase.padding())
	binary.BigEndian.PutUint16(plain[:2], uint16(len(raw)))
	copy(plain[2:], raw)
	if corruptPadding {
		plain[len(plain)-1] = 1
	}
	header := append([]byte{1}, bytes.Repeat([]byte{14}, 32)...)
	id, aead, err := nativeMigrationEnvelope(key, phase, header[1:])
	if err != nil {
		t.Fatal(err)
	}
	return id, aead.Seal(header, nil, plain, nativeMigrationAAD(phase, scope, id))
}

func TestNativeMigrationLedgerRejectsMalformedAdmissionAndReceipt(t *testing.T) {
	key := bytes.Repeat([]byte{15}, 32)
	task, unit, object, receipt, public := nativeMigrationLedgerFixture(t)
	task.UnitCount++
	if _, _, err := sealNativeMigrationTask(key, task); !errors.Is(err, store.ErrMigrationState) {
		t.Fatal("inconsistent task roster accepted", err)
	}
	unit.Bytes = 10*store.GiB + 1
	if _, _, err := sealNativeMigrationUnit(key, unit); !errors.Is(err, store.ErrMigrationState) {
		t.Fatal("impossible unit bytes accepted", err)
	}
	otherKey, err := protocol.PublicKey(protocol.Encode(bytes.Repeat([]byte{20}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if verifyNativeMigrationReceipt(object, receipt, otherKey) == nil {
		t.Fatal("foreign target signature accepted")
	}
	receipt.AcceptedAt = object.ChallengeExpiresAt
	if verifyNativeMigrationReceipt(object, receipt, public) == nil {
		t.Fatal("receipt accepted at challenge expiry")
	}
	receipt.AcceptedAt--
	receipt.ObjectID = strings.Repeat("1", 64)
	if verifyNativeMigrationReceipt(object, receipt, public) == nil {
		t.Fatal("receipt transplanted to a different logical object")
	}
	receipt.Signature += "A"
	if _, _, err := sealNativeMigrationReceipt(key, receipt); !errors.Is(err, store.ErrMigrationState) {
		t.Fatal("invalid signature encoding accepted", err)
	}
	object.Object.BlobID = object.Expected.Target.Blob
	if _, _, err := sealNativeMigrationObject(key, object); !errors.Is(err, store.ErrMigrationState) {
		t.Fatal("receipt mismatching source placement accepted", err)
	}
}
