package business

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	_ "modernc.org/sqlite"
)

func TestRecoveryRecordingInventoryChecksSignedHiddenOwner(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "recordings.sqlite")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	statements, err := migrations.Statements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range statements {
		exec(stmt)
	}
	r := New(db, "sqlite")
	key := bytes.Repeat([]byte{9}, 32)
	exec(`INSERT INTO sealed_tree_capacity_meta VALUES(1,?)`, opaqueCapacityVerifier(key))
	nodeVault, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	masterSeed, ownerSeed := protocol.Encode(bytes.Repeat([]byte{7}, 32)), protocol.Encode(bytes.Repeat([]byte{6}, 32))
	master := store.NodeIdentity{ID: strings.Repeat("1", 32), Role: "Master", Endpoint: "https://master.test", CreatedAt: 1}
	master.PrivateKey, err = nodeVault.Seal(masterSeed)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO node_identity VALUES(1,?,?,?,?,?)`, master.ID, master.Role, master.Endpoint, master.PrivateKey, master.CreatedAt)
	owner, relation, user, id := strings.Repeat("2", 32), strings.Repeat("3", 32), strings.Repeat("4", 32), strings.Repeat("5", 32)
	ownerPublic, err := protocol.PublicKey(ownerSeed)
	if err != nil {
		t.Fatal(err)
	}
	const peerEndpoint, credential = "https://owner.test", "private-fixture-credential"
	peerBinding := store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: owner, RelationshipID: relation, PublicKey: ownerPublic, ControlEndpoint: peerEndpoint, CredentialDigest: store.PeerCredentialDigest(credential), CreatedAt: 1})
	exec(`INSERT INTO node_relationships VALUES(?,?,?,?,?,'downstream','Direct','active','offline',1,0,0,0,'fixture',?,'{}',1)`, relation, owner, peerEndpoint, ownerPublic, credential, protocol.Version)
	meta, err := mediacrypto.NewMetadata(32)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO cluster_storage_members VALUES(?,?,'Follower','Direct',1,4096,?,0,0,'offline',0,1)`, owner, relation, meta.CiphertextSize+1)
	exec(`INSERT INTO karaoke_users VALUES(?,'fixture','fixture','!','banned',2048,?,1,1)`, user, meta.CiphertextSize)
	const title = "private-fixture-recording-title"
	titleDigest := sha256.Sum256([]byte(title))
	intent := recordingAudioIntent{
		UserID: user, RecordingID: id, MasterID: master.ID, MemberID: owner,
		OperationID: strings.Repeat("a", 64), BlobID: strings.Repeat("b", 64), Digest: strings.Repeat("c", 64), Bytes: meta.CiphertextSize,
		Binding:      "recording-audio:v1:" + user + ":" + strings.Repeat("d", 64) + ":" + id,
		OwnerBinding: strings.Repeat("e", 64), ContentType: "audio/webm", Encryption: meta,
		TitleDigest: hex.EncodeToString(titleDigest[:]), State: "pending",
	}
	if err = r.insertRecordingAudioIntentTx(ctx, db, key, intent, title, nil); err != nil {
		t.Fatal(err)
	}
	if err = r.markRecordingAudioReadyTx(ctx, db, key, intent); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO karaoke_recordings VALUES(?,?,?,'private-fixture.bin','audio/webm',?,?,'ready',?,'[]',1,1)`, id, user, owner, intent.Bytes, intent.Digest, title)
	index := opaqueCapacityIndex(key, intent.OperationID)
	memberIndex := opaqueCapacityMemberIndex(key, owner)
	encID, sealed, err := sealOpaqueCapacity(key, index, OpaqueCapacityIntent{OperationID: intent.OperationID, MasterID: master.ID, MemberID: owner, BlobID: intent.BlobID, Digest: intent.Digest, Bytes: intent.Bytes})
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO sealed_tree_capacity_ids VALUES(?)`, encID)
	exec(`INSERT INTO sealed_tree_capacity_intents VALUES(?,?,?,?,?)`, index, memberIndex, opaqueCapacityBlobIndex(key, intent.BlobID), encID, sealed)
	sealJSON := func(index string, value any) (string, []byte) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		id, record, err := sealCapacityRecord(key, index, raw)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO sealed_tree_capacity_ids VALUES(?)`, id)
		return id, record
	}
	accountID, sealedAccount := sealJSON(memberIndex, opaqueCapacityAccount{MemberID: owner, Revision: 1})
	exec(`INSERT INTO sealed_tree_capacity_accounts VALUES(?,?,?)`, memberIndex, accountID, sealedAccount)
	objectIndex, blobIndex, mac := strings.Repeat("f", 64), strings.Repeat("0", 64), strings.Repeat("1", 64)
	exec(`INSERT INTO sealed_tree_operation_ids VALUES(?,1,?,?,?)`, intent.OperationID, objectIndex, blobIndex, mac)
	scope := OpaqueCapacityScope{
		OperationID: intent.OperationID, Generation: strings.Repeat("2", 64), StageID: strings.Repeat("3", 64),
		MasterBinding: capacityMasterBinding(master), RelationshipID: relation, RelationshipBinding: peerBinding,
		PublishChallenge: strings.Repeat("4", 64), CleanupChallenge: strings.Repeat("5", 64),
		Settled: true, CompletionBinding: opaqueledger.CompletionBinding(objectIndex, blobIndex, mac),
	}
	receipt := protocol.OpaqueCapacityReceipt{
		Kind: "opaque-capacity-published-v1", MasterID: master.ID, OwnerID: owner, RelationshipID: relation, RelationshipBinding: peerBinding,
		Generation: scope.Generation, OperationID: intent.OperationID, StageID: scope.StageID, BlobID: intent.BlobID,
		Digest: intent.Digest, Challenge: scope.PublishChallenge, Bytes: intent.Bytes, State: "published",
	}
	payload, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	scope.PublishedSignature, err = protocol.Sign(ownerSeed, payload)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO sealed_tree_capacity_ids VALUES(?),(?)`, capacityChallengeIndex(key, scope.PublishChallenge), capacityChallengeIndex(key, scope.CleanupChallenge))
	scopeID, sealedScope := sealJSON(index, scope)
	exec(`INSERT INTO sealed_tree_capacity_scopes VALUES(?,?,?)`, index, scopeID, sealedScope)

	// The read-only coordinator supplies the real completion MAC checker.
	// This isolated fixture tests business discovery, pairing and signature.
	checkCompletion := func(_ context.Context, gotUser, gotRecording, operation, blob string) error {
		if gotUser != user || gotRecording != id || operation != intent.OperationID || blob != intent.BlobID {
			return store.ErrRecordingState
		}
		return nil
	}
	scan := func(visit func(RecoveryRecordingPlacement) error) (RecoveryRecordingInventory, error) {
		t.Helper()
		tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		return r.visitRecoveryRecordingsTx(ctx, tx, key, nodeVault, checkCompletion, visit)
	}
	got, err := scan(func(v RecoveryRecordingPlacement) error {
		if v.RecordingID != id || v.UserID != user || v.OwnerID != owner || v.BlobID != intent.BlobID || v.SHA256 != intent.Digest ||
			v.Publication != receipt || v.PublicationSignature != scope.PublishedSignature || v.Bytes != intent.Bytes ||
			v.ReadAlias != recordingAudioDirectAlias(key, intent.OperationID) || v.AliasRevision == "" || v.Descriptor == "" ||
			v.UserUsedBytes != intent.Bytes || v.UserQuotaBytes != 2048 || v.OwnerUsedBytes != intent.Bytes+1 ||
			v.OwnerReservedBytes != 0 || v.OwnerAllocationBytes != 4096 {
			t.Fatal("incorrect hidden recording placement")
		}
		raw, err := json.Marshal(v)
		if err != nil || strings.Contains(string(raw), title) || strings.Contains(string(raw), credential) || strings.Contains(string(raw), "private-fixture.bin") {
			t.Fatal("inventory exposed private recording metadata", err)
		}
		return nil
	})
	if err != nil || got.Recordings != 1 || got.Bytes != intent.Bytes {
		t.Fatalf("hidden recording not inventoried: %+v %v", got, err)
	}
	stop := errors.New("stop inventory visitor")
	if got, err := scan(func(RecoveryRecordingPlacement) error { return stop }); !errors.Is(err, stop) || got != (RecoveryRecordingInventory{}) {
		t.Fatal("visitor interruption did not invalidate scan", got, err)
	}
	blocked := func(RecoveryRecordingPlacement) error {
		t.Fatal("invalid recording reached the visitor")
		return nil
	}
	exec(`UPDATE karaoke_users SET used_bytes=used_bytes+1 WHERE user_id=?`, user)
	if _, err = scan(blocked); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("inconsistent account quota admitted", err)
	}
	exec(`UPDATE karaoke_users SET used_bytes=used_bytes-1 WHERE user_id=?`, user)
	exec(`UPDATE cluster_storage_members SET used_bytes=? WHERE member_id=?`, intent.Bytes-1, owner)
	if _, err = scan(blocked); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("Owner used counter below recording usage admitted", err)
	}
	exec(`UPDATE cluster_storage_members SET used_bytes=? WHERE member_id=?`, intent.Bytes+1, owner)
	exec(`UPDATE karaoke_recordings SET state='deleting' WHERE recording_id=?`, id)
	if _, err = scan(blocked); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("unfinished deletion admitted", err)
	}
	exec(`UPDATE karaoke_recordings SET state='ready' WHERE recording_id=?`, id)
	ownerSignature := scope.PublishedSignature
	scope.PublishedSignature, err = protocol.Sign(masterSeed, payload)
	if err != nil {
		t.Fatal(err)
	}
	badID, badScope := sealJSON(index, scope)
	exec(`UPDATE sealed_tree_capacity_scopes SET encryption_id=?,sealed=? WHERE operation_index=?`, badID, badScope, index)
	if _, err = scan(blocked); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("wrong signer admitted", err)
	}
	scope.PublishedSignature = ownerSignature
	exec(`UPDATE sealed_tree_capacity_scopes SET encryption_id=?,sealed=? WHERE operation_index=?`, scopeID, sealedScope, index)
	intent.State = "ready"
	if err = r.transitionRecordingAudioTx(ctx, db, key, intent, "ready", "deleting"); err != nil {
		t.Fatal(err)
	}
	intent.State = "deleting"
	if err = r.transitionRecordingAudioTx(ctx, db, key, intent, "deleting", "deleted"); err != nil {
		t.Fatal(err)
	}
	intent.State = "deleted"
	exec(`UPDATE karaoke_recordings SET state='deleted' WHERE recording_id=?`, id)
	exec(`UPDATE karaoke_users SET used_bytes=0 WHERE user_id=?`, user)
	exec(`UPDATE cluster_storage_members SET used_bytes=1 WHERE member_id=?`, owner)
	if _, err = scan(blocked); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("deleted recording without cleanup history admitted", err)
	}
	cleanupClaim, err := recordingAudioCleanupClaim(key, intent, scope)
	if err != nil {
		t.Fatal(err)
	}
	marker, err := recordingAudioCleanupMarker(key, recordingAudioCleanupReceipt(cleanupClaim))
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO sealed_tree_capacity_ids VALUES(?)`, marker)
	if got, err := scan(blocked); err != nil || got != (RecoveryRecordingInventory{}) {
		t.Fatal("completed deletion was not treated as terminal", got, err)
	}

	cancelled := intent
	cancelled.RecordingID, cancelled.OperationID, cancelled.BlobID = strings.Repeat("6", 32), strings.Repeat("7", 64), strings.Repeat("8", 64)
	cancelled.Binding = "recording-audio:v1:" + user + ":" + strings.Repeat("d", 64) + ":" + cancelled.RecordingID
	cancelled.State = "pending"
	if err = r.insertRecordingAudioIntentTx(ctx, db, key, cancelled, title, nil); err != nil {
		t.Fatal(err)
	}
	if err = r.transitionRecordingAudioTx(ctx, db, key, cancelled, "pending", "cancel_pending"); err != nil {
		t.Fatal(err)
	}
	cancelled.State = "cancel_pending"
	exec(`INSERT INTO karaoke_recordings VALUES(?,?,?,'private-fixture.bin','audio/webm',?,NULL,'pending',?,'[]',1,1)`, cancelled.RecordingID, user, owner, cancelled.Bytes, title)
	if _, err = scan(blocked); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("unfinished cancellation admitted", err)
	}
	if err = r.transitionRecordingAudioTx(ctx, db, key, cancelled, "cancel_pending", "cancelled"); err != nil {
		t.Fatal(err)
	}
	cancelled.State = "cancelled"
	exec(`UPDATE karaoke_recordings SET state='deleted' WHERE recording_id=?`, cancelled.RecordingID)
	cancelScope := scope
	cancelScope.OperationID, cancelScope.Settled, cancelScope.CompletionBinding, cancelScope.PublishedSignature = cancelled.OperationID, false, "", ""
	for _, value := range []*string{&cancelScope.Generation, &cancelScope.StageID, &cancelScope.PublishChallenge, &cancelScope.CleanupChallenge} {
		*value, err = randomID()
		if err != nil {
			t.Fatal(err)
		}
	}
	claim, err := recordingAudioCleanupClaim(key, cancelled, cancelScope)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := recordingAudioCleanupReceipt(claim)
	cleanupPayload, err := cleanup.Payload()
	if err != nil {
		t.Fatal(err)
	}
	cancelScope.CleanupSignature, err = protocol.Sign(ownerSeed, cleanupPayload)
	if err != nil {
		t.Fatal(err)
	}
	cancelIndex := opaqueCapacityIndex(key, cancelled.OperationID)
	cancelScopeID, sealedCancelScope := sealJSON(cancelIndex, cancelScope)
	exec(`INSERT INTO sealed_tree_capacity_scopes VALUES(?,?,?)`, cancelIndex, cancelScopeID, sealedCancelScope)
	exec(`INSERT INTO sealed_tree_capacity_ids VALUES(?),(?)`, capacityChallengeIndex(key, cancelScope.PublishChallenge), capacityChallengeIndex(key, cancelScope.CleanupChallenge))
	cancelMarker, err := recordingAudioCleanupMarker(key, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO sealed_tree_capacity_ids VALUES(?)`, cancelMarker)
	if got, err := scan(blocked); err != nil || got != (RecoveryRecordingInventory{}) {
		t.Fatal("completed Direct cancellation was not treated as terminal", got, err)
	}

	// Including the two earlier terminals, 63 more records require a
	// second sealed-index page. The visitor still sees no physical objects.
	for n := 0; n < 63; n++ {
		expired := intent
		expired.RecordingID, expired.OperationID, expired.BlobID = fmt.Sprintf("%032x", n+100), fmt.Sprintf("%064x", n+200), fmt.Sprintf("%064x", n+300)
		expired.MemberID, expired.State = master.ID, "pending"
		expired.Binding = "recording-audio:v1:" + user + ":" + strings.Repeat("d", 64) + ":" + expired.RecordingID
		expired.Encryption, err = mediacrypto.NewMetadata(32)
		if err != nil {
			t.Fatal(err)
		}
		if err = r.insertRecordingAudioIntentTx(ctx, db, key, expired, title, nil); err != nil {
			t.Fatal(err)
		}
		if err = r.transitionRecordingAudioTx(ctx, db, key, expired, "pending", "cancelled"); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO karaoke_recordings VALUES(?,?,?,'private-fixture.bin','audio/webm',?,NULL,'deleted',?,'[]',1,1)`, expired.RecordingID, user, expired.MemberID, expired.Bytes, title)
		capacity := OpaqueCapacityIntent{OperationID: expired.OperationID, MasterID: master.ID, MemberID: master.ID, BlobID: expired.BlobID, Digest: expired.Digest, Bytes: expired.Bytes}
		encoded, err := json.Marshal(capacity)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO sealed_tree_capacity_ids VALUES(?)`, hex.EncodeToString(capacityMAC(key, "recording-audio-unstarted-expiry-v1", encoded)))
	}
	if got, err := scan(blocked); err != nil || got != (RecoveryRecordingInventory{}) {
		t.Fatal("terminal discovery did not consume both sealed-index pages", got, err)
	}

	exec(`DELETE FROM sealed_recording_audio WHERE recording_index=?`, recordingAudioIndex(key, cancelled.RecordingID))
	if _, err = scan(blocked); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("business-only recording admitted", err)
	}
	exec(`DELETE FROM karaoke_recordings`)
	if _, err = scan(blocked); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("orphan sealed recording admitted", err)
	}
}
