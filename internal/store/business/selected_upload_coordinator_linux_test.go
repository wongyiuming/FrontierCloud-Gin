//go:build linux

package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	_ "modernc.org/sqlite"
)

type selectedCoordinatorCodec struct{}

func (selectedCoordinatorCodec) SealOpaqueOwnerRecord(_ string, v []byte) (string, error) {
	return base64.StdEncoding.EncodeToString(v), nil
}
func (selectedCoordinatorCodec) OpenOpaqueOwnerRecord(_ string, v string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(v)
}

func TestSelectedCoordinatorRealLocksRollbackAndBoundedWait(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "coordinator.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p)+"?_pragma=busy_timeout(1000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tree, err := sealedtree.New(bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID := strings.Repeat("a", 64)
	ts, err := sealedtree.InitializeSQLite(ctx, db, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	statements, err := migrations.Statements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	treeDir := t.TempDir()
	if err = os.Chmod(treeDir, 0700); err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(treeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	if _, err = sealedtree.InitializeFence(ctx, ts, treeRoot, treeDir); err != nil {
		t.Fatal(err)
	}
	musicID, categoryID, nestedID := strings.Repeat("8", 64), strings.Repeat("9", 64), strings.Repeat("f", 64)
	for _, dir := range []sealedtree.Entry{
		{ParentID: rootID, ObjectID: musicID, Kind: "directory", Name: "music"},
		{ParentID: musicID, ObjectID: categoryID, Kind: "directory", Name: "category"},
		{ParentID: categoryID, ObjectID: nestedID, Kind: "directory", Name: "empty-subdirectory"},
	} {
		if err = ts.CreateDirectoryWithFacts(ctx, dir, sealedtree.Facts{ObjectID: dir.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	r := New(db, "sqlite")
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	called := false
	if err = r.withSelectedMutation(bounded, ts, func(context.Context, queryer, *sealedtree.CoordinatedMutation) error { called = true; return nil }); !errors.Is(err, store.ErrNodeState) || called {
		t.Fatal("unconfigured owner admitted", err)
	}
	ownerDir := t.TempDir()
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
	if err = r.ConfigureOwnerControlFence(func(ctx context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(ctx, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = r.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	master, owner, relation := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	nodeVault, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	masterPrivate, err := nodeVault.Seal(protocol.Encode(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','https://master.test',?,1)", master, masterPrivate); err != nil {
		t.Fatal(err)
	}
	ownerPrivate := protocol.Encode(bytes.Repeat([]byte{4}, 32))
	peerKey, err := protocol.PublicKey(ownerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	summary := `{"native_resource_origin":"https://owner.test","_local_native_transport_receipt":{"transport":"Direct","revision":1,"origin":"https://owner.test"}}`
	credential := protocol.Encode(bytes.Repeat([]byte{6}, 48))
	sealedCredential, err := nodeVault.Seal(credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO node_relationships(relationship_id,peer_id,peer_endpoint,peer_key,credential,direction,mode,state,status,last_heartbeat,rtt_ms,failures,recoveries,peer_version,protocol,summary,created_at) VALUES(?,?, 'https://owner.test',?,?,'downstream','Direct','active','online',?,1,0,0,'test',2,?,1)", relation, owner, peerKey, sealedCredential, time.Now().Unix(), summary); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES(?,?,'Follower','Direct',1,?,0,0,?,'online',1,1)", owner, relation, 2*store.GiB, 10*store.GiB); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO native_transport_policy(member_id,configured_transport,revision,updated_at) VALUES(?,'Direct',1,1)", owner); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err = r.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	entry := sealedtree.Entry{ParentID: rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "fixture.mp3"}
	place := sealedtree.Placement{ObjectID: entry.ObjectID, NativeObjectID: entry.ObjectID, OwnerID: strings.Repeat("2", 32), Bytes: 7, SHA256: strings.Repeat("9", 64)}
	fail := errors.New("rollback fixture")
	bounded2, cancel2 := context.WithTimeout(ctx, time.Second)
	defer cancel2()
	err = r.withSelectedMutation(bounded2, ts, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if _, e := m.PrepareFileTx(c, q, entry, place, sealedtree.Facts{ObjectID: entry.ObjectID, PendingSelectedUpload: &sealedtree.SelectedUploadFact{UploadID: strings.Repeat("4", 32), AdminBinding: strings.Repeat("5", 64), Policy: "Direct", Revision: 1, Origin: "https://owner.test"}}); e != nil {
			return e
		}
		return fail
	})
	if !errors.Is(err, fail) {
		t.Fatal("transaction did not return injected failure", err)
	}
	var n int
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 0 {
		t.Fatal("rollback leaked pending", n, err)
	}
	shared, err := r.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blocked, stop := context.WithTimeout(ctx, 150*time.Millisecond)
	err = r.withSelectedMutation(blocked, ts, func(context.Context, queryer, *sealedtree.CoordinatedMutation) error { return nil })
	stop()
	shared.Release()
	if err == nil {
		t.Fatal("owner lock contention admitted")
	}
	// A caller holding tree first cannot block the coordinator forever: both the
	// tree wait and a competing ingress acquisition have bounded contexts.
	treeRead, err := ts.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		c, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		defer cancel()
		result <- r.withSelectedMutation(c, ts, func(context.Context, queryer, *sealedtree.CoordinatedMutation) error { return nil })
	}()
	select {
	case err = <-result:
		if err == nil {
			t.Fatal("tree contention admitted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tree contention did not time out")
	}
	treeRead.Release()
	retry, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if err = r.withSelectedMutation(retry, ts, func(context.Context, queryer, *sealedtree.CoordinatedMutation) error { return nil }); err != nil {
		t.Fatal("locks leaked after timeout", err)
	}
	metadata, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	selectedEntry := sealedtree.Entry{ParentID: categoryID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "selected.mp3"}
	selectedPlace := sealedtree.Placement{ObjectID: selectedEntry.ObjectID, NativeObjectID: selectedEntry.ObjectID, OwnerID: owner, Bytes: metadata.CiphertextSize, SHA256: strings.Repeat("9", 64), Encryption: &metadata}
	selectedFacts := sealedtree.Facts{ObjectID: selectedEntry.ObjectID, PendingSelectedUpload: &sealedtree.SelectedUploadFact{UploadID: strings.Repeat("4", 32), AdminBinding: strings.Repeat("5", 64), Policy: "Direct", Revision: 1, Origin: "https://owner.test"}}
	// This callback is synthetic: production Admin authorization, file-ID
	// preparation and committed-directory affinity are not implemented here.
	check := func(_ context.Context, _ queryer, _ *sealedtree.CoordinatedMutation, p sealedtree.SelectedPending) error {
		if p.Placement.Encryption == nil || *p.Placement.Encryption != metadata {
			return store.ErrNodeState
		}
		return nil
	}
	failCheck := func(context.Context, queryer, *sealedtree.CoordinatedMutation, sealedtree.SelectedPending) error {
		return fail
	}
	prepareCtx, done := context.WithTimeout(ctx, 8*time.Second)
	defer done()
	if _, _, err = r.prepareSelectedCoordinated(prepareCtx, ts, key, selectedEntry, selectedPlace, selectedFacts, 10*store.GiB, failCheck); !errors.Is(err, fail) {
		t.Fatal("failed admission did not roll back", err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 0 {
		t.Fatal("failed selected admission left pending", n, err)
	}
	first, already, err := r.prepareSelectedCoordinated(prepareCtx, ts, key, selectedEntry, selectedPlace, selectedFacts, 10*store.GiB, check)
	if err != nil || already {
		t.Fatal("selected composition", already, err)
	}
	second, already, err := r.prepareSelectedCoordinated(prepareCtx, ts, key, selectedEntry, selectedPlace, selectedFacts, 10*store.GiB, check)
	if err != nil || !already || second != first {
		t.Fatal("selected retry changed operation", already, err)
	}
	if _, _, err = r.bindSelectedCapacityScope(prepareCtx, ts, key, selectedFacts.PendingSelectedUpload.UploadID, failCheck); !errors.Is(err, fail) {
		t.Fatal("failed scope admission did not roll back", err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_capacity_scopes").Scan(&n); err != nil || n != 0 {
		t.Fatal("failed scope admission left state", n, err)
	}
	scope, existed, err := r.bindSelectedCapacityScope(prepareCtx, ts, key, selectedFacts.PendingSelectedUpload.UploadID, check)
	if err != nil || existed || scope.OperationID != first.OperationID {
		t.Fatal("selected scope", existed, err)
	}
	replayedScope, existed, err := r.bindSelectedCapacityScope(prepareCtx, ts, key, selectedFacts.PendingSelectedUpload.UploadID, check)
	if err != nil || !existed || replayedScope != scope {
		t.Fatal("selected scope replay changed identity", existed, err)
	}
	adminCheck := func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation, p sealedtree.SelectedPending, session string) error {
		if session != selectedFacts.PendingSelectedUpload.AdminBinding {
			return store.ErrNodeState
		}
		return check(c, q, m, p)
	}
	token, err := r.issueSelectedDirectCapability(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, selectedFacts.PendingSelectedUpload.AdminBinding, "https://master.test", adminCheck)
	if err != nil {
		t.Fatal("issue selected capability", err)
	}
	claim, err := protocol.VerifySelectedStorageUpload(credential, token, time.Now().Unix())
	if err != nil || claim.RelationshipBinding != scope.RelationshipBinding || claim.Generation != scope.Generation || claim.StageID != scope.StageID || claim.PublishChallenge != scope.PublishChallenge || claim.CleanupChallenge != scope.CleanupChallenge || claim.OperationID != first.OperationID || claim.ObjectID != first.BlobID {
		t.Fatal("capability did not bind durable scope", err)
	}
	if token, err = r.issueSelectedDirectCapability(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, strings.Repeat("6", 64), "https://master.test", adminCheck); err == nil || token != "" {
		t.Fatal("unauthenticated session issued capability", err)
	}
	status, err := r.selectedStatus(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, func(context.Context) error { return nil })
	if err != nil || status.State != "pending" || status.OperationID != first.OperationID {
		t.Fatal("pending status", status, err)
	}
	if status, err = r.selectedStatus(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, func(context.Context) error { return fail }); !errors.Is(err, fail) || status.State != "" {
		t.Fatal("unauthorized status", status, err)
	}
	if _, _, err = r.BindOpaqueCapacityScope(prepareCtx, key, first.OperationID, scope.Generation, scope.StageID); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("generic migration scope accepted selected operation", err)
	}
	if retried, existed, e := r.prepareSelectedCoordinated(prepareCtx, ts, key, selectedEntry, selectedPlace, selectedFacts, 10*store.GiB, check); e != nil || !existed || retried != first {
		t.Fatal("bound selected scope broke exact retry", existed, e)
	}
	err = r.withSelectedMutation(prepareCtx, ts, func(c context.Context, q queryer, _ *sealedtree.CoordinatedMutation) error {
		selected, found, e := r.recoverSelectedOpaqueCapacityTx(c, q, key, selectedFacts.PendingSelectedUpload.UploadID)
		if e != nil || !found {
			return errors.New("selected intent missing")
		}
		wrongOwner := selected
		wrongOwner.Capacity.MemberID = strings.Repeat("6", 32)
		if _, _, e = r.selectedScopeTx(c, q, key, wrongOwner); !errors.Is(e, store.ErrNodeState) {
			return errors.New("scope accepted another owner")
		}
		wrongOperation := selected
		wrongOperation.Capacity.OperationID = strings.Repeat("e", 64)
		if _, found, e = r.selectedScopeTx(c, q, key, wrongOperation); e != nil || found {
			return errors.New("scope attached to another operation")
		}
		conflict := scope
		conflict.CleanupChallenge = conflict.PublishChallenge
		raw, e := json.Marshal(conflict)
		if e != nil {
			return e
		}
		index := opaqueCapacityIndex(key, scope.OperationID)
		id, sealed, e := sealCapacityRecord(key, index, raw)
		clear(raw)
		if e != nil {
			return e
		}
		if _, e = q.ExecContext(c, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", id); e != nil {
			return e
		}
		if _, e = q.ExecContext(c, "UPDATE sealed_tree_capacity_scopes SET encryption_id=?,sealed=? WHERE operation_index=?", id, sealed, index); e != nil {
			return e
		}
		if _, _, e = r.selectedScopeTx(c, q, key, selected); !errors.Is(e, store.ErrNodeState) {
			return errors.New("scope accepted duplicate challenges")
		}
		return fail // Roll back the injected corruption.
	})
	if !errors.Is(err, fail) {
		t.Fatal("scope corruption test did not roll back", err)
	}
	if replayedScope, existed, err = r.bindSelectedCapacityScope(prepareCtx, ts, key, selectedFacts.PendingSelectedUpload.UploadID, check); err != nil || !existed || replayedScope != scope {
		t.Fatal("scope changed after rollback", existed, err)
	}
	// Even a durable exact retry must revalidate the current applied policy;
	// the preflight proof itself provides no transport authorization.
	proof, err := ts.PreflightCategoryAndOwner(prepareCtx, selectedEntry.ParentID, selectedPlace.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.WithOwnerControlExclusive(prepareCtx, func(c context.Context) error {
		_, e := db.ExecContext(c, "UPDATE native_transport_policy SET revision=2 WHERE member_id=?", owner)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.prepareSelectedAfterPreflight(prepareCtx, ts, proof, key, selectedEntry, selectedPlace, selectedFacts, 10*store.GiB, check); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("policy changed after preflight was accepted", err)
	}
	if _, _, err = r.prepareSelectedAfterPreflight(prepareCtx, ts, proof, key, selectedEntry, selectedPlace, selectedFacts, 10*store.GiB, check); !errors.Is(err, sealedtree.ErrFenceChanged) {
		t.Fatal("consumed preflight was reused", err)
	}
	if err = r.WithOwnerControlExclusive(prepareCtx, func(c context.Context) error {
		_, e := db.ExecContext(c, "UPDATE native_transport_policy SET revision=1 WHERE member_id=?", owner)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	proof, err = ts.PreflightCategoryAndOwner(prepareCtx, selectedEntry.ParentID, selectedPlace.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	newDir := sealedtree.Entry{ParentID: categoryID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "new-empty-directory"}
	if err = ts.CreateDirectoryWithFacts(prepareCtx, newDir, sealedtree.Facts{ObjectID: newDir.ObjectID}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.prepareSelectedAfterPreflight(prepareCtx, ts, proof, key, selectedEntry, selectedPlace, selectedFacts, 10*store.GiB, check); !errors.Is(err, sealedtree.ErrFenceChanged) {
		t.Fatal("tree changed after preflight was accepted", err)
	}
	proofCtx, cancelProof := context.WithTimeout(ctx, time.Second)
	proof, err = ts.PreflightCategoryAndOwner(proofCtx, selectedEntry.ParentID, selectedPlace.OwnerID)
	if err != nil {
		cancelProof()
		t.Fatal(err)
	}
	cancelProof()
	if _, _, err = r.prepareSelectedAfterPreflight(prepareCtx, ts, proof, key, selectedEntry, selectedPlace, selectedFacts, 10*store.GiB, check); !errors.Is(err, sealedtree.ErrFenceChanged) {
		t.Fatal("canceled preflight was accepted", err)
	}
	otherTree, err := sealedtree.OpenSQLite(ctx, db, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sealedtree.OpenFence(ctx, otherTree, treeRoot, treeDir); err != nil {
		t.Fatal(err)
	}
	proof, err = otherTree.PreflightCategoryAndOwner(prepareCtx, selectedEntry.ParentID, selectedPlace.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.prepareSelectedAfterPreflight(prepareCtx, ts, proof, key, selectedEntry, selectedPlace, selectedFacts, 10*store.GiB, check); !errors.Is(err, sealedtree.ErrFenceChanged) {
		t.Fatal("different tree instance proof was accepted", err)
	}
	// The pending record itself fences this immediate parent, even before the
	// first Owner has published any bytes. A different requested Owner cannot
	// cause a silent reallocation or create a second pending object.
	otherEntry := selectedEntry
	otherEntry.ObjectID = strings.Repeat("d", 64)
	otherEntry.Name = "other-owner.mp3"
	otherPlace := selectedPlace
	otherPlace.ObjectID, otherPlace.NativeObjectID = otherEntry.ObjectID, otherEntry.ObjectID
	otherPlace.OwnerID = strings.Repeat("6", 32)
	otherFacts := selectedFacts
	otherFacts.ObjectID = otherEntry.ObjectID
	otherFacts.PendingSelectedUpload = &sealedtree.SelectedUploadFact{UploadID: strings.Repeat("7", 32), AdminBinding: strings.Repeat("5", 64), Policy: "Direct", Revision: 1, Origin: "https://other.test"}
	if _, _, err = r.prepareSelectedCoordinated(prepareCtx, ts, key, otherEntry, otherPlace, otherFacts, 10*store.GiB, check); !errors.Is(err, sealedtree.ErrConflict) {
		t.Fatal("conflicting pending owner was accepted", err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 1 {
		t.Fatal("conflicting owner left pending state", n, err)
	}
	// Concurrent admissions are serialized by the real coordination fences.
	// The already pending Owner may reserve another object, while a different
	// Owner must not obtain capacity or a pending file in that same parent.
	concurrentEntry := selectedEntry
	concurrentEntry.ObjectID = strings.Repeat("e", 64)
	concurrentEntry.Name = "same-owner.mp3"
	concurrentPlace := selectedPlace
	concurrentPlace.ObjectID, concurrentPlace.NativeObjectID = concurrentEntry.ObjectID, concurrentEntry.ObjectID
	concurrentFacts := selectedFacts
	concurrentFacts.ObjectID = concurrentEntry.ObjectID
	concurrentFacts.PendingSelectedUpload = &sealedtree.SelectedUploadFact{UploadID: strings.Repeat("8", 32), AdminBinding: strings.Repeat("5", 64), Policy: "Direct", Revision: 1, Origin: "https://owner.test"}
	type admissionResult struct {
		owner string
		err   error
	}
	start := make(chan struct{})
	results := make(chan admissionResult, 2)
	go func() {
		<-start
		_, _, e := r.prepareSelectedCoordinated(prepareCtx, ts, key, concurrentEntry, concurrentPlace, concurrentFacts, 10*store.GiB, check)
		results <- admissionResult{owner: "same", err: e}
	}()
	go func() {
		<-start
		_, _, e := r.prepareSelectedCoordinated(prepareCtx, ts, key, otherEntry, otherPlace, otherFacts, 10*store.GiB, check)
		results <- admissionResult{owner: "other", err: e}
	}()
	close(start)
	for range 2 {
		outcome := <-results
		if outcome.owner == "same" && outcome.err != nil || outcome.owner == "other" && !errors.Is(outcome.err, sealedtree.ErrConflict) {
			t.Fatal("concurrent owner admission", outcome.owner, outcome.err)
		}
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 2 {
		t.Fatal("concurrent admission changed pending count", n, err)
	}
	nestedEntry := selectedEntry
	nestedEntry.ParentID, nestedEntry.ObjectID, nestedEntry.Name = nestedID, strings.Repeat("7", 64), "nested.mp3"
	nestedPlace := selectedPlace
	nestedPlace.ObjectID, nestedPlace.NativeObjectID = nestedEntry.ObjectID, nestedEntry.ObjectID
	nestedFacts := selectedFacts
	nestedFacts.ObjectID = nestedEntry.ObjectID
	nestedFacts.PendingSelectedUpload = &sealedtree.SelectedUploadFact{UploadID: strings.Repeat("9", 32), AdminBinding: strings.Repeat("5", 64), Policy: "Direct", Revision: 1, Origin: "https://owner.test"}
	if _, _, err = r.prepareSelectedCoordinated(prepareCtx, ts, key, nestedEntry, nestedPlace, nestedFacts, 10*store.GiB, check); !errors.Is(err, sealedtree.ErrConflict) {
		t.Fatal("direct and nested category media mixed", err)
	}
	stopped, cancelStopped := context.WithTimeout(ctx, time.Second)
	cancelStopped()
	if _, _, err = r.prepareSelectedCoordinated(stopped, ts, key, nestedEntry, nestedPlace, nestedFacts, 10*store.GiB, check); err == nil {
		t.Fatal("canceled admission was accepted")
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 2 {
		t.Fatal("canceled or conflicting admission changed pending state", n, err)
	}
	var reservedBefore, reservedAfter int64
	if err = db.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&reservedBefore); err != nil {
		t.Fatal(err)
	}
	cancelEntry := selectedEntry
	cancelEntry.ObjectID, cancelEntry.Name = strings.Repeat("2", 64), "canceled.mp3"
	cancelPlace := selectedPlace
	cancelPlace.ObjectID, cancelPlace.NativeObjectID = cancelEntry.ObjectID, cancelEntry.ObjectID
	cancelFacts := selectedFacts
	cancelFacts.ObjectID = cancelEntry.ObjectID
	cancelFacts.PendingSelectedUpload = &sealedtree.SelectedUploadFact{UploadID: strings.Repeat("2", 32), AdminBinding: strings.Repeat("5", 64), Policy: "Direct", Revision: 1, Origin: "https://owner.test"}
	requestCtx, cancelRequest := context.WithTimeout(ctx, time.Second)
	defer cancelRequest()
	if _, _, err = r.prepareSelectedCoordinated(requestCtx, ts, key, cancelEntry, cancelPlace, cancelFacts, 10*store.GiB, func(context.Context, queryer, *sealedtree.CoordinatedMutation, sealedtree.SelectedPending) error {
		cancelRequest() // The proof has been consumed; the SQL transaction must roll back.
		return nil
	}); err == nil {
		t.Fatal("request canceled before commit was accepted")
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 2 {
		t.Fatal("request cancellation left pending state", n, err)
	}
	if err = db.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&reservedAfter); err != nil || reservedBefore != reservedAfter {
		t.Fatal("request cancellation changed reserved quota", reservedBefore, reservedAfter, err)
	}
	originCtx, cancelOrigin := context.WithTimeout(ctx, time.Second)
	defer cancelOrigin()
	proof, err = ts.PreflightCategoryAndOwner(originCtx, cancelEntry.ParentID, cancelPlace.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.prepareSelectedAfterPreflight(prepareCtx, ts, proof, key, cancelEntry, cancelPlace, cancelFacts, 10*store.GiB, func(context.Context, queryer, *sealedtree.CoordinatedMutation, sealedtree.SelectedPending) error {
		cancelOrigin() // The caller context remains live; the proof's request does not.
		return nil
	}); err == nil {
		t.Fatal("original proof request canceled before commit was accepted")
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 2 {
		t.Fatal("original proof cancellation left pending state", n, err)
	}
	if err = db.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&reservedAfter); err != nil || reservedBefore != reservedAfter {
		t.Fatal("original proof cancellation changed reserved quota", reservedBefore, reservedAfter, err)
	}
	changed := metadata
	changed.NoncePrefix = "AQIDBAUGBwg="
	selectedPlace.Encryption = &changed
	if _, _, err = r.prepareSelectedCoordinated(prepareCtx, ts, key, selectedEntry, selectedPlace, selectedFacts, 10*store.GiB, check); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("changed descriptor accepted", err)
	}
	// This test signs a synthetic Owner publication claim; it does not assert
	// that any physical Owner bytes were actually transferred or published.
	receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: master, OwnerID: owner, RelationshipID: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding, Generation: scope.Generation, OperationID: first.OperationID, StageID: scope.StageID, BlobID: first.BlobID, Digest: selectedPlace.SHA256, Challenge: scope.PublishChallenge, Bytes: metadata.CiphertextSize, State: "published"}
	payload, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := protocol.Sign(ownerPrivate, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.WithOwnerControlExclusive(prepareCtx, func(c context.Context) error {
		_, e := r.RecordOpaquePublishedReceipt(c, key, nodeVault, receipt, signature)
		return e
	}); err != nil {
		t.Fatal("record synthetic Owner receipt", err)
	}
	if _, err = r.finalizeSelectedSigned(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, receipt, signature, func(context.Context) error { return fail }); !errors.Is(err, fail) {
		t.Fatal("failed finalize authorization", err)
	}
	if _, err = r.finalizeSelectedSigned(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, receipt, signature+"x", func(context.Context) error { return nil }); err == nil {
		t.Fatal("incorrect Owner signature accepted")
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 2 {
		t.Fatal("failed finalize changed pending state", n, err)
	}
	// Force failure after tree publication and quota settlement, at the final
	// selected-state update. All mutations must roll back together.
	if _, err = db.Exec(`CREATE TRIGGER fixture_selected_terminal_abort BEFORE UPDATE OF state ON selected_upload_intents WHEN NEW.state='completed' BEGIN SELECT RAISE(ABORT,'fixture terminal failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = r.finalizeSelectedSigned(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, receipt, signature, func(context.Context) error { return nil }); err == nil {
		t.Fatal("injected terminal update failure was ignored")
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 2 {
		t.Fatal("terminal update failure leaked tree completion", n, err)
	}
	var beforeUsed, beforeReserved int64
	if err = db.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&beforeUsed, &beforeReserved); err != nil || beforeUsed != 0 || beforeReserved != 2*metadata.CiphertextSize {
		t.Fatal("terminal update failure leaked quota settlement", beforeUsed, beforeReserved, err)
	}
	if _, err = db.Exec("DROP TRIGGER fixture_selected_terminal_abort"); err != nil {
		t.Fatal(err)
	}
	if done, e := r.finalizeSelectedSigned(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, receipt, signature, func(context.Context) error { return nil }); e != nil || done {
		t.Fatal("finalize selected", done, e)
	}
	if done, e := r.finalizeSelectedSigned(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, receipt, signature, func(context.Context) error { return nil }); e != nil || !done {
		t.Fatal("finalize retry", done, e)
	}
	status, err = r.selectedStatus(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, func(context.Context) error { return nil })
	if err != nil || status.State != "completed" || status.OperationID != first.OperationID {
		t.Fatal("committed status recovery", status, err)
	}
	var used, reserved int64
	if err = db.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&used, &reserved); err != nil || used != metadata.CiphertextSize || reserved != metadata.CiphertextSize {
		t.Fatal("finalize quota mismatch or duplicate settlement", used, reserved, err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 1 {
		t.Fatal("finalize pending mismatch", n, err)
	}
	var state string
	if err = db.QueryRow("SELECT state FROM selected_upload_intents WHERE upload_index=?", selectedUploadIndex(key, selectedFacts.PendingSelectedUpload.UploadID)).Scan(&state); err != nil || state != "completed" {
		t.Fatal("terminal state missing", state, err)
	}
	cancelUpload := concurrentFacts.PendingSelectedUpload.UploadID
	cancelScope, _, err := r.bindSelectedCapacityScope(prepareCtx, ts, key, cancelUpload, check)
	if err != nil {
		t.Fatal("cancel scope", err)
	}
	wrongVault, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if cleanup, e := r.beginSelectedCancel(prepareCtx, ts, key, wrongVault, cancelUpload, concurrentFacts.PendingSelectedUpload.AdminBinding, "https://master.test", adminCheck); e == nil || cleanup != "" {
		t.Fatal("invalid vault signed cleanup", e)
	}
	status, err = r.selectedStatus(prepareCtx, ts, key, nodeVault, cancelUpload, func(context.Context) error { return nil })
	if err != nil || status.State != "pending" {
		t.Fatal("failed cancellation leaked state", status, err)
	}
	cleanupToken, err := r.beginSelectedCancel(prepareCtx, ts, key, nodeVault, cancelUpload, concurrentFacts.PendingSelectedUpload.AdminBinding, "https://master.test", adminCheck)
	if err != nil {
		t.Fatal("begin cancellation", err)
	}
	cleanupClaim, err := protocol.VerifySelectedStorageCleanup(credential, cleanupToken, time.Now().Unix())
	if err != nil || cleanupClaim.OperationID != cancelScope.OperationID || cleanupClaim.CleanupChallenge != cancelScope.CleanupChallenge {
		t.Fatal("cleanup ticket scope", err)
	}
	if _, err = protocol.VerifySelectedStorageUpload(credential, cleanupToken, time.Now().Unix()); err == nil {
		t.Fatal("cleanup ticket authorized upload")
	}
	status, err = r.selectedStatus(prepareCtx, ts, key, nodeVault, cancelUpload, func(context.Context) error { return nil })
	if err != nil || status.State != "cancelling" {
		t.Fatal("cancellation status", status, err)
	}
	if _, err = r.issueSelectedDirectCapability(prepareCtx, ts, key, nodeVault, cancelUpload, concurrentFacts.PendingSelectedUpload.AdminBinding, "https://master.test", adminCheck); err == nil {
		t.Fatal("cancelled operation issued upload ticket")
	}
	if _, err = r.beginSelectedCancel(prepareCtx, ts, key, nodeVault, cancelUpload, concurrentFacts.PendingSelectedUpload.AdminBinding, "https://master.test", adminCheck); err != nil {
		t.Fatal("cancellation retry", err)
	}
	if err = db.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&used, &reserved); err != nil || used != metadata.CiphertextSize || reserved != metadata.CiphertextSize {
		t.Fatal("cancellation prematurely released quota", used, reserved, err)
	}
	latePublished := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: master, OwnerID: owner, RelationshipID: cancelScope.RelationshipID, RelationshipBinding: cancelScope.RelationshipBinding, Generation: cancelScope.Generation, OperationID: cancelScope.OperationID, StageID: cancelScope.StageID, BlobID: cleanupClaim.ObjectID, Digest: cleanupClaim.ContentSHA256, Challenge: cancelScope.PublishChallenge, Bytes: metadata.CiphertextSize, State: "published"}
	latePayload, err := latePublished.Payload()
	if err != nil {
		t.Fatal(err)
	}
	lateSignature, err := protocol.Sign(ownerPrivate, latePayload)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.WithOwnerControlExclusive(prepareCtx, func(c context.Context) error {
		_, e := r.RecordOpaquePublishedReceipt(c, key, nodeVault, latePublished, lateSignature)
		return e
	}); err != nil {
		t.Fatal("record in-flight late receipt", err)
	}
	if _, err = r.finalizeSelectedSigned(prepareCtx, ts, key, nodeVault, cancelUpload, latePublished, lateSignature, func(context.Context) error { return nil }); err == nil {
		t.Fatal("publication finalized after cancellation")
	}
	cleanReceipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-cleaned-v1", MasterID: master, OwnerID: owner, RelationshipID: cancelScope.RelationshipID, RelationshipBinding: cancelScope.RelationshipBinding, Generation: cancelScope.Generation, OperationID: cancelScope.OperationID, StageID: cancelScope.StageID, BlobID: cleanupClaim.ObjectID, Digest: cleanupClaim.ContentSHA256, Challenge: cancelScope.CleanupChallenge, Bytes: metadata.CiphertextSize, State: "cleaned"}
	cleanPayload, err := cleanReceipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	cleanSignature, err := protocol.Sign(ownerPrivate, cleanPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.finishSelectedCancel(prepareCtx, ts, key, cancelUpload, cleanReceipt, cleanSignature, func(context.Context) error { return nil }, nil); err == nil {
		t.Fatal("unrecorded cleanup authorized refund")
	}
	if err = r.WithOwnerControlExclusive(prepareCtx, func(c context.Context) error {
		_, e := r.RecordOpaqueCleanedReceipt(c, key, nodeVault, cleanReceipt, cleanSignature)
		return e
	}); err != nil {
		t.Fatal("record cleanup receipt", err)
	}
	if _, err = db.Exec(`CREATE TRIGGER fixture_cancel_abort BEFORE UPDATE OF state ON selected_upload_intents WHEN NEW.state='cancelled' BEGIN SELECT RAISE(ABORT,'fixture cancellation failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = r.finishSelectedCancel(prepareCtx, ts, key, cancelUpload, cleanReceipt, cleanSignature, func(context.Context) error { return nil }, nil); err == nil {
		t.Fatal("cancellation fault ignored")
	}
	if err = db.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&used, &reserved); err != nil || used != metadata.CiphertextSize || reserved != metadata.CiphertextSize {
		t.Fatal("failed cancellation changed quota", used, reserved, err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM selected_upload_cancellations WHERE operation_id=?", cancelScope.OperationID).Scan(&n); err != nil || n != 0 {
		t.Fatal("failed cancellation leaked tombstone", n, err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files WHERE operation_id=?", cancelScope.OperationID).Scan(&n); err != nil || n != 1 {
		t.Fatal("failed cancellation removed pending", n, err)
	}
	if _, err = db.Exec("DROP TRIGGER fixture_cancel_abort"); err != nil {
		t.Fatal(err)
	}
	if already, err := r.finishSelectedCancel(prepareCtx, ts, key, cancelUpload, cleanReceipt, cleanSignature, func(context.Context) error { return nil }, nil); err != nil || already {
		t.Fatal("finish cancellation", already, err)
	}
	if already, err := r.finishSelectedCancel(prepareCtx, ts, key, cancelUpload, cleanReceipt, cleanSignature, func(context.Context) error { return nil }, nil); err != nil || !already {
		t.Fatal("finish cancellation retry", already, err)
	}
	status, err = r.selectedStatus(prepareCtx, ts, key, nodeVault, cancelUpload, func(context.Context) error { return nil })
	if err != nil || status.State != "cancelled" {
		t.Fatal("cancelled status", status, err)
	}
	if err = db.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&used, &reserved); err != nil || used != metadata.CiphertextSize || reserved != 0 {
		t.Fatal("cleanup refund mismatch", used, reserved, err)
	}
	if _, err = ts.Check(prepareCtx); err != nil {
		t.Fatal("tree rejected authenticated cancellation", err)
	}
	var cancelMAC string
	if err = db.QueryRow("SELECT cancellation_mac FROM selected_upload_cancellations WHERE operation_id=?", cancelScope.OperationID).Scan(&cancelMAC); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE selected_upload_cancellations SET cancellation_mac=? WHERE operation_id=?", strings.Repeat("0", 64), cancelScope.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err = ts.Check(prepareCtx); err == nil {
		t.Fatal("tree accepted tampered cancellation")
	}
	if _, err = db.Exec("UPDATE selected_upload_cancellations SET cancellation_mac=? WHERE operation_id=?", cancelMAC, cancelScope.OperationID); err != nil {
		t.Fatal(err)
	}
	if token, err = r.beginSelectedCancel(prepareCtx, ts, key, nodeVault, selectedFacts.PendingSelectedUpload.UploadID, selectedFacts.PendingSelectedUpload.AdminBinding, "https://master.test", adminCheck); err == nil || token != "" {
		t.Fatal("completed upload authorized deletion", err)
	}

	// The two state transitions race on the same real Owner/ingress/tree/SQL
	// fences. Exactly one may win; the loser must never create authority for
	// both an already-committed placement and its Owner cleanup.
	raceEntry := concurrentEntry
	raceEntry.ObjectID, raceEntry.Name = strings.Repeat("6", 64), "racing.mp3"
	racePlace := concurrentPlace
	racePlace.ObjectID, racePlace.NativeObjectID = raceEntry.ObjectID, raceEntry.ObjectID
	raceFacts := concurrentFacts
	raceFacts.ObjectID = raceEntry.ObjectID
	raceFacts.PendingSelectedUpload = &sealedtree.SelectedUploadFact{UploadID: strings.Repeat("a", 32), AdminBinding: strings.Repeat("5", 64), Policy: "Direct", Revision: 1, Origin: "https://owner.test"}
	raceCapacity, _, err := r.prepareSelectedCoordinated(prepareCtx, ts, key, raceEntry, racePlace, raceFacts, 10*store.GiB, check)
	if err != nil {
		t.Fatal("racing reservation", err)
	}
	raceScope, _, err := r.bindSelectedCapacityScope(prepareCtx, ts, key, raceFacts.PendingSelectedUpload.UploadID, check)
	if err != nil {
		t.Fatal("racing scope", err)
	}
	raceReceipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: master, OwnerID: owner, RelationshipID: raceScope.RelationshipID, RelationshipBinding: raceScope.RelationshipBinding, Generation: raceScope.Generation, OperationID: raceCapacity.OperationID, StageID: raceScope.StageID, BlobID: raceCapacity.BlobID, Digest: racePlace.SHA256, Challenge: raceScope.PublishChallenge, Bytes: metadata.CiphertextSize, State: "published"}
	racePayload, err := raceReceipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	raceSignature, err := protocol.Sign(ownerPrivate, racePayload)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.WithOwnerControlExclusive(prepareCtx, func(c context.Context) error {
		_, e := r.RecordOpaquePublishedReceipt(c, key, nodeVault, raceReceipt, raceSignature)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	type raceResult struct {
		action string
		err    error
	}
	raceStart, raceResults := make(chan struct{}), make(chan raceResult, 2)
	go func() {
		<-raceStart
		_, e := r.beginSelectedCancel(prepareCtx, ts, key, nodeVault, raceFacts.PendingSelectedUpload.UploadID, raceFacts.PendingSelectedUpload.AdminBinding, "https://master.test", adminCheck)
		raceResults <- raceResult{"cancel", e}
	}()
	go func() {
		<-raceStart
		_, e := r.finalizeSelectedSigned(prepareCtx, ts, key, nodeVault, raceFacts.PendingSelectedUpload.UploadID, raceReceipt, raceSignature, func(context.Context) error { return nil })
		raceResults <- raceResult{"finalize", e}
	}()
	close(raceStart)
	a, b := <-raceResults, <-raceResults
	if (a.err == nil) == (b.err == nil) {
		t.Fatal("cancel/finalize did not choose exactly one winner", a, b)
	}
	winner := a.action
	if a.err != nil {
		winner = b.action
	}
	raceStatus, err := r.selectedStatus(prepareCtx, ts, key, nodeVault, raceFacts.PendingSelectedUpload.UploadID, func(context.Context) error { return nil })
	if err != nil || winner == "cancel" && raceStatus.State != "cancelling" || winner == "finalize" && raceStatus.State != "completed" {
		t.Fatal("racing terminal state", winner, raceStatus, err)
	}
}
