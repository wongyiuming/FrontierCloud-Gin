//go:build linux && ledger_fixture

package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	_ "modernc.org/sqlite"
)

// This development-only test exercises the real offline local history proof,
// durable pre-issuance file-ID reservation and transient Manager ticket.
// The explicit ledger_fixture tag is never enabled in deployed binaries.
func TestSelectedRealPreparationAndHistoricalReservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	dbPath, treeDir := filepath.Join(dir, "business.sqlite"), filepath.Join(dir, "tree")
	if err := os.Mkdir(treeDir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	data, err := os.ReadFile("../../../migrations/sqlite/0011-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		Generation int      `json:"generation"`
		Statements []string `json:"statements"`
	}
	if json.Unmarshal(data, &old) != nil || old.Generation != 11 {
		t.Fatal("legacy schema")
	}
	for _, statement := range old.Statements {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		gen       int
		name, sum string
	}{{8, migrations.S3Name, migrations.S3Checksum}, {9, migrations.PublicRoutingName, migrations.PublicRoutingChecksum}, {10, migrations.SealedTreeName, migrations.SealedTreeChecksum}, {11, migrations.LegacyReadIntentName, migrations.LegacyReadIntentChecksum}} {
		if _, err = db.ExecContext(ctx, `INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES(?,?,?,123)`, item.gen, item.name, item.sum); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO frontiercloud_schema(singleton,generation,created_at) VALUES(1,11,123)`); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	conf := config.Config{DataRoot: dir, SQLitePath: dbPath, DatabaseType: config.DatabaseSQLite, SecretsDirectory: filepath.Join(dir, "secrets")}
	if err = deployment.Bind(ctx, conf, nil); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(conf.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	masterPrivate, err := v.Seal(protocol.Encode(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	master, owner, relation := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	if _, err = db.ExecContext(ctx, `INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','https://master.test',?,123)`, master, masterPrivate); err != nil {
		t.Fatal(err)
	}
	if err = schema.Initialize(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.New(bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID := strings.Repeat("a", 64)
	if err = sealedtree.FixtureInitializeExisting(ctx, conf, gate, tree, rootID, treeDir); err != nil {
		t.Fatal(err)
	}
	ts, err := sealedtree.OpenSQLite(ctx, db, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(treeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = sealedtree.OpenFence(ctx, ts, root, treeDir); err != nil {
		t.Fatal(err)
	}
	scope, err := sealedtree.FixtureImportLocalHistoryIDs(ctx, gate, dir, dbPath, ts, root, v, master)
	if err != nil {
		t.Fatal(err)
	}
	if err = gate.Resume(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	musicID, categoryID := strings.Repeat("8", 64), strings.Repeat("9", 64)
	for _, e := range []sealedtree.Entry{{ParentID: rootID, ObjectID: musicID, Kind: "directory", Name: "music"}, {ParentID: musicID, ObjectID: categoryID, Kind: "directory", Name: "category"}} {
		if err = ts.CreateDirectoryWithFacts(ctx, e, sealedtree.Facts{ObjectID: e.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	r := New(db, "sqlite")
	ownerDir := filepath.Join(dir, "owner")
	if err = os.Mkdir(ownerDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(ownerDir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	ownerRoot, err := os.OpenRoot(ownerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerRoot.Close()
	fence, err := ownerfence.Create(ownerRoot, ownerDir, selectedCoordinatorCodec{})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = r.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	peerKey, err := protocol.PublicKey(protocol.Encode(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := v.Seal(protocol.Encode(bytes.Repeat([]byte{6}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	summary := `{"native_resource_origin":"https://owner.test","_local_native_transport_receipt":{"transport":"Direct","revision":1,"origin":"https://owner.test"}}`
	if _, err = db.ExecContext(ctx, `INSERT INTO node_relationships(relationship_id,peer_id,peer_endpoint,peer_key,credential,direction,mode,state,status,last_heartbeat,rtt_ms,failures,recoveries,peer_version,protocol,summary,created_at) VALUES(?,?,'https://owner.test',?,?,'downstream','Direct','active','online',?,1,0,0,'test',2,?,1)`, relation, owner, peerKey, credential, time.Now().Unix(), summary); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES(?,?,'Follower','Direct',1,?,0,0,?,'online',1,1)`, owner, relation, 2*store.GiB, 10*store.GiB); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO native_transport_policy(member_id,configured_transport,revision,updated_at) VALUES(?,'Direct',1,1)`, owner); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err = r.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	manager, err := mediacrypto.New(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	session := strings.Repeat("5", 64)
	if err = ts.ReserveMediaPreparation(ctx, meta, "admin:"+session, scope); err != nil {
		t.Fatal("real reservation", err)
	}
	token, err := manager.SignTransientPreparation("admin:"+session, meta)
	if err != nil {
		t.Fatal(err)
	}
	entry := sealedtree.Entry{ParentID: categoryID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "selected.mp3"}
	placement := sealedtree.Placement{ObjectID: entry.ObjectID, NativeObjectID: entry.ObjectID, OwnerID: owner, Bytes: meta.CiphertextSize, SHA256: strings.Repeat("d", 64), Encryption: &meta}
	facts := sealedtree.Facts{ObjectID: entry.ObjectID, PendingSelectedUpload: &sealedtree.SelectedUploadFact{UploadID: strings.Repeat("4", 32), AdminBinding: session, Policy: "Direct", Revision: 1, Origin: "https://owner.test"}}
	parentPath := []string{"music", "category"}
	if _, _, err = r.prepareAuthorizedSelected(ctx, ts, key, manager, strings.Repeat("6", 64), token, parentPath, entry, placement, facts, 10*store.GiB, nil); err == nil {
		t.Fatal("other Admin session accepted")
	}
	if _, _, err = r.prepareAuthorizedSelected(ctx, ts, key, manager, session, token+"x", parentPath, entry, placement, facts, 10*store.GiB, nil); err == nil {
		t.Fatal("forged preparation accepted")
	}
	unreserved, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	unreservedToken, err := manager.SignTransientPreparation("admin:"+session, unreserved)
	if err != nil {
		t.Fatal(err)
	}
	unreservedPlacement := placement
	unreservedPlacement.Encryption = &unreserved
	if _, _, err = r.prepareAuthorizedSelected(ctx, ts, key, manager, session, unreservedToken, parentPath, entry, unreservedPlacement, facts, 10*store.GiB, nil); err == nil {
		t.Fatal("unreserved file ID accepted")
	}
	var count int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected preparation leaked pending", count, err)
	}
	if _, _, err = r.prepareAuthorizedSelected(ctx, ts, key, manager, session, token, []string{"music", "other"}, entry, placement, facts, 10*store.GiB, nil); err == nil {
		t.Fatal("changed target directory accepted")
	}
	prepared, already, err := r.prepareAuthorizedSelected(ctx, ts, key, manager, session, token, parentPath, entry, placement, facts, 10*store.GiB, nil)
	if err != nil || already {
		t.Fatal("actual preparation", already, err)
	}
	retry, already, err := r.prepareAuthorizedSelected(ctx, ts, key, manager, session, token, parentPath, entry, placement, facts, 10*store.GiB, nil)
	if err != nil || !already || retry != prepared {
		t.Fatal("actual preparation retry", already, err)
	}
	if err = manager.ResetTransientPreparations(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.prepareAuthorizedSelected(ctx, ts, key, manager, session, token, parentPath, entry, placement, facts, 10*store.GiB, nil); err == nil {
		t.Fatal("old manager token accepted")
	}
	// The fixture gate below is a test substitute; it does not prove that a
	// production runtime has imported and reconciled its historical Owner data.
	if _, e := NewSelectedUploadRuntime(r, ts, key, manager, v, "https://master.test", nil); e == nil {
		t.Fatal("missing readiness gate accepted")
	}
	ready := &fixtureSelectedRuntimeGate{ready: true}
	runtime, err := NewSelectedUploadRuntime(r, ts, key, manager, v, "https://master.test", ready)
	if err != nil {
		t.Fatal(err)
	}
	newMeta, err := mediacrypto.NewMetadata(8)
	if err != nil {
		t.Fatal(err)
	}
	ready.ready = false
	if err = runtime.ReservePreparation(ctx, session, newMeta); err == nil {
		t.Fatal("closed gate reserved a media key")
	}
	ready.ready = true
	if err = runtime.ReservePreparation(ctx, session, newMeta); err != nil {
		t.Fatal(err)
	}
	newPreparation, err := manager.SignTransientPreparation("admin:"+session, newMeta)
	if err != nil {
		t.Fatal(err)
	}
	req := SelectedPrepareRequest{UploadID: strings.Repeat("b", 32), ParentPath: "music/category", Filename: "runtime.mp3", MemberID: owner, CipherSHA256: strings.Repeat("e", 64), Encryption: newMeta, Preparation: newPreparation}
	ready.ready = false
	if _, e := runtime.PrepareAndIssue(ctx, session, req); e == nil {
		t.Fatal("closed runtime gate accepted")
	}
	ready.ready = true
	ticket, err := runtime.PrepareAndIssue(ctx, session, req)
	if err != nil {
		t.Fatal("runtime prepare", err)
	}
	if ticket.UploadID != req.UploadID || ticket.MemberID != owner || ticket.URL != "https://owner.test/api/v1/node/selected-upload" || ticket.RecoveryURL != "https://owner.test/api/v1/node/selected-upload/recover" {
		t.Fatal("unsafe ticket", ticket.URL, ticket.MemberID)
	}
	credentialRaw, err := v.Unseal(credential)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := protocol.VerifySelectedStorageUpload(credentialRaw, ticket.Capability, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if claim.UploadID != req.UploadID || claim.Owner != owner || claim.ContentSHA256 != req.CipherSHA256 || claim.AdminOrigin != "https://master.test" {
		t.Fatal("wrong signed capability")
	}
	retried, err := runtime.PrepareAndIssue(ctx, session, req)
	if err != nil {
		t.Fatal("uncertain prepare retry", err)
	}
	retryClaim, err := protocol.VerifySelectedStorageUpload(credentialRaw, retried.Capability, time.Now().Unix())
	if err != nil || retryClaim.OperationID != claim.OperationID || retryClaim.ObjectID != claim.ObjectID || retryClaim.MediaID != claim.MediaID {
		t.Fatal("retry changed operation", err)
	}
	changed := req
	changed.CipherSHA256 = strings.Repeat("f", 64)
	if _, e := runtime.PrepareAndIssue(ctx, session, changed); e == nil {
		t.Fatal("retry changed ciphertext digest")
	}
	resumed, err := runtime.Resume(ctx, strings.Repeat("6", 64), req.UploadID)
	if err != nil || resumed.MemberID != owner {
		t.Fatal("new Admin could not resume", err)
	}
	resumeClaim, err := protocol.VerifySelectedStorageUpload(credentialRaw, resumed.Capability, time.Now().Unix())
	if err != nil || resumeClaim.OperationID != claim.OperationID || resumeClaim.ObjectID != claim.ObjectID || resumeClaim.AdminBinding == claim.AdminBinding {
		t.Fatal("resume changed operation or reused session", err)
	}
	status, err := runtime.Status(ctx, session, req.UploadID)
	if err != nil || status.State != "pending" {
		t.Fatal("pending status", status, err)
	}
	published := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: claim.Master, OwnerID: claim.Owner, RelationshipID: claim.Relationship, RelationshipBinding: claim.RelationshipBinding, Generation: claim.Generation, OperationID: claim.OperationID, StageID: claim.StageID, BlobID: claim.ObjectID, Digest: claim.ContentSHA256, Challenge: claim.PublishChallenge, Bytes: claim.Size, State: "published"}
	payload, err := published.Payload()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.Sign(protocol.Encode(bytes.Repeat([]byte{7}, 32)), payload)
	if err != nil {
		t.Fatal(err)
	}
	if already, e := runtime.Complete(ctx, session, req.UploadID, published, sig); e != nil || already {
		t.Fatal("runtime completion", already, e)
	}
	if already, e := runtime.Complete(ctx, session, req.UploadID, published, sig); e != nil || !already {
		t.Fatal("runtime completion retry", already, e)
	}
	status, err = runtime.Status(ctx, session, req.UploadID)
	if err != nil || status.State != "completed" {
		t.Fatal("completed status", status, err)
	}
	readLease, err := ts.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	visible, err := ts.ReadVisibleObjectByAliasWithLease(ctx, readLease, claim.MediaID)
	readLease.Release()
	if err != nil || visible.Entry.Name != req.Filename || visible.Placement.Encryption == nil || *visible.Placement.Encryption != newMeta {
		t.Fatal("completed tree metadata", err)
	}
	cancelMeta, err := mediacrypto.NewMetadata(9)
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.ReservePreparation(ctx, session, cancelMeta); err != nil {
		t.Fatal(err)
	}
	cancelPreparation, err := manager.SignTransientPreparation("admin:"+session, cancelMeta)
	if err != nil {
		t.Fatal(err)
	}
	cancelReq := SelectedPrepareRequest{UploadID: strings.Repeat("d", 32), ParentPath: "music/category", Filename: "cancel.mp3", MemberID: owner, CipherSHA256: strings.Repeat("f", 64), Encryption: cancelMeta, Preparation: cancelPreparation}
	if _, err = runtime.PrepareAndIssue(ctx, session, cancelReq); err != nil {
		t.Fatal("prepare cancel", err)
	}
	cleanup, err := runtime.BeginCancel(ctx, session, cancelReq.UploadID)
	if err != nil {
		t.Fatal("begin cancel", err)
	}
	cleanupRetry, err := runtime.BeginCancel(ctx, strings.Repeat("6", 64), cancelReq.UploadID)
	if err != nil {
		t.Fatal("retry cancel", err)
	}
	cc, err := protocol.VerifySelectedStorageCleanup(credentialRaw, cleanup.Capability, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	rcc, err := protocol.VerifySelectedStorageCleanup(credentialRaw, cleanupRetry.Capability, time.Now().Unix())
	if err != nil || rcc.OperationID != cc.OperationID || rcc.ObjectID != cc.ObjectID {
		t.Fatal("cancel changed operation", err)
	}
	cleaned := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-cleaned-v1", MasterID: cc.Master, OwnerID: cc.Owner, RelationshipID: cc.Relationship, RelationshipBinding: cc.RelationshipBinding, Generation: cc.Generation, OperationID: cc.OperationID, StageID: cc.StageID, BlobID: cc.ObjectID, Digest: cc.ContentSHA256, Challenge: cc.CleanupChallenge, Bytes: cc.Size, State: "cleaned"}
	payload, err = cleaned.Payload()
	if err != nil {
		t.Fatal(err)
	}
	sig, err = protocol.Sign(protocol.Encode(bytes.Repeat([]byte{7}, 32)), payload)
	if err != nil {
		t.Fatal(err)
	}
	if already, e := runtime.FinishCancel(ctx, session, cancelReq.UploadID, cleaned, sig); e != nil || already {
		t.Fatal("cancel completion", already, e)
	}
	if already, e := runtime.FinishCancel(ctx, session, cancelReq.UploadID, cleaned, sig); e != nil || !already {
		t.Fatal("cancel completion retry", already, e)
	}
	status, err = runtime.Status(ctx, session, cancelReq.UploadID)
	if err != nil || status.State != "cancelled" {
		t.Fatal("cancel status", status, err)
	}
	checkSelectedNativeDeletionSettlement(t, ctx, runtime, visible, master, relation, session)
	status, err = runtime.Status(ctx, session, req.UploadID)
	if err != nil || status.State != "completed" {
		t.Fatal("deletion rewrote historical upload settlement", status, err)
	}
}

func checkSelectedNativeDeletionSettlement(t *testing.T, ctx context.Context, runtime *SelectedUploadRuntime, visible sealedtree.VisibleObject, master, relation, session string) {
	t.Helper()
	ts, db := runtime.tree, runtime.repo.db
	object := visible.Entry.ObjectID
	owner, bytesUsed := visible.Placement.OwnerID, visible.Placement.Bytes
	usage := func() (used, reserved int64) {
		t.Helper()
		if err := db.QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, owner).Scan(&used, &reserved); err != nil {
			t.Fatal(err)
		}
		return
	}
	used, reserved := usage()
	audit := store.AdminAudit{SourceSummary: visible.Path, Detail: visible.Path}
	target := store.SelectedMediaDeleteTarget{Path: visible.Path, ResourceID: object}
	if _, err := runtime.QueueFollowerMediaDeletions(ctx, session, []store.SelectedMediaDeleteTarget{
		target, {Path: "music/category/missing.mp3", ResourceID: strings.Repeat("e", 64)},
	}, audit); err == nil {
		t.Fatal("stale selection did not roll back the batch")
	}
	guard, err := ts.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, visibleErr := ts.ReadVisibleObjectWithLease(ctx, guard, object)
	guard.Release()
	if visibleErr != nil {
		t.Fatal("rolled-back queue hid the first selection", visibleErr)
	}
	queued, err := runtime.QueueFollowerMediaDeletions(ctx, session, []store.SelectedMediaDeleteTarget{target}, audit)
	if err != nil || len(queued.Items) != 1 || queued.Items[0].State != store.SelectedMediaDeletePending {
		t.Fatal("failed to queue exact selection", queued, err)
	}
	retry, err := runtime.QueueFollowerMediaDeletions(ctx, session, []store.SelectedMediaDeleteTarget{target}, audit)
	if err != nil || len(retry.Items) != 1 || retry.Items[0] != queued.Items[0] {
		t.Fatal("lost reply changed operation", retry, err)
	}
	read, err := ts.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	intent, found, err := ts.RecoverOpaqueRevocationWithLease(ctx, read, object)
	if err != nil || !found || !intent.SelectedDelete || intent.OperationID != queued.Items[0].OperationID {
		read.Release()
		t.Fatal("queued operation not durably recoverable", found, err)
	}
	rows, _, err := ts.ListCatalogPageWithLease(ctx, read, visible.Entry.ParentID, "", 10, true)
	read.Release()
	if err != nil {
		t.Fatal("pending deletion made the directory unreadable", err)
	}
	for _, row := range rows {
		if row.Entry.ObjectID == object {
			t.Fatal("pending deletion stayed in the directory")
		}
	}
	finish := func(operation string) (bool, error) {
		return runtime.FinishNativeMediaDeletion(ctx, session, object, operation, audit)
	}
	if _, err = finish(intent.OperationID); err == nil {
		t.Fatal("finalized without signed Owner proof")
	}
	proof := protocol.OpaqueRevocationReceipt{Kind: "opaque-alias-revoke-v1", OperationID: intent.OperationID, MasterID: master,
		OwnerID: owner, RelationshipID: relation, Alias: intent.Alias, Blob: intent.BlobID, Revision: intent.Revision, State: "revoked"}
	sign := func(payload map[string]any, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		signature, err := protocol.Sign(protocol.Encode(bytes.Repeat([]byte{7}, 32)), payload)
		if err != nil {
			t.Fatal(err)
		}
		return signature
	}
	if err = ts.RecordOpaqueRevocationAck(ctx, object, proof, sign(proof.Payload())); err != nil {
		t.Fatal(err)
	}
	if _, err = finish(intent.OperationID); err == nil {
		t.Fatal("revocation ACK was accepted as unlink proof")
	}
	proof.Kind, proof.State = "opaque-blob-delete-v1", "deleted"
	deletion := protocol.OpaqueDeletionReceipt(proof)
	if intent.FollowerPublication == "" {
		t.Fatal("selected delete did not bind its exact completed publication")
	}
	if err = ts.RecordOpaqueDeletionReceipt(ctx, object, deletion, sign(deletion.Payload())); err == nil {
		t.Fatal("deletion accepted a receipt without the bound publication")
	}
	deletion.PublicationOperation = intent.FollowerPublication
	if err = ts.RecordOpaqueDeletionReceipt(ctx, object, deletion, sign(deletion.Payload())); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TRIGGER reject_media_delete_audit BEFORE INSERT ON admin_audit_log WHEN NEW.action='opaque-media-delete' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = finish(intent.OperationID); err == nil {
		t.Fatal("deletion committed without its audit")
	}
	if actualUsed, actualReserved := usage(); actualUsed != used || actualReserved != reserved {
		t.Fatal("rolled-back deletion changed quota", actualUsed, actualReserved)
	}
	if _, err = db.ExecContext(ctx, `DROP TRIGGER reject_media_delete_audit`); err != nil {
		t.Fatal(err)
	}
	if already, err := finish(intent.OperationID); err != nil || already {
		t.Fatal("failed to settle deletion after rollback", already, err)
	}
	if already, err := finish(intent.OperationID); err != nil || !already {
		t.Fatal("exact retry was not idempotent", already, err)
	}
	if _, err = finish(strings.Repeat("f", 32)); err == nil {
		t.Fatal("different operation was accepted")
	}
	done, err := runtime.QueueFollowerMediaDeletions(ctx, session, []store.SelectedMediaDeleteTarget{target}, audit)
	if err != nil || len(done.Items) != 1 || done.Items[0].State != store.SelectedMediaDeleteDeleted || done.Items[0].OperationID != intent.OperationID {
		t.Fatal("completion was not recognized after a lost reply", done, err)
	}
	wrongPath := target
	wrongPath.Path, wrongPath.OperationID = "music/category/replacement.mp3", intent.OperationID
	if _, err = runtime.QueueFollowerMediaDeletions(ctx, session, []store.SelectedMediaDeleteTarget{wrongPath}, audit); err == nil {
		t.Fatal("terminal receipt accepted a different path")
	}
	if actualUsed, actualReserved := usage(); actualUsed != used-bytesUsed || actualReserved != reserved {
		t.Fatal("delete did not refund committed bytes exactly once", actualUsed, actualReserved)
	}
	if _, err = ts.ResolvePath(ctx, object); err == nil {
		t.Fatal("removed object still resolves in the catalog")
	}
	read, err = ts.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer read.Release()
	if _, err = ts.ReadVisibleObjectByAliasWithLease(ctx, read, visible.Placement.ReadAlias); err == nil {
		t.Fatal("deleted alias still opens the catalog")
	}
	var audits int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_audit_log WHERE action='opaque-media-delete' AND (source_summary IS NULL OR source_summary='') AND (detail IS NULL OR detail='')`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("missing or unredacted deletion audit", audits, err)
	}
}

type fixtureSelectedRuntimeGate struct{ ready bool }
type fixtureSelectedRuntimeLease struct{ gate *fixtureSelectedRuntimeGate }

func (g *fixtureSelectedRuntimeGate) AcquireSelectedUpload(ctx context.Context, _ *sealedtree.SQLStore) (SelectedUploadRuntimeLease, error) {
	if !g.ready || ctx.Err() != nil {
		return nil, store.ErrNodeState
	}
	return &fixtureSelectedRuntimeLease{gate: g}, nil
}
func (l *fixtureSelectedRuntimeLease) Check(ctx context.Context) error {
	if !l.gate.ready || ctx.Err() != nil {
		return store.ErrNodeState
	}
	return nil
}
func (l *fixtureSelectedRuntimeLease) Release() {}
