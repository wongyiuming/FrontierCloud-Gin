//go:build linux

package business

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSelectedPreflightFinalAdmissionScale(t *testing.T) {
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
	if _, err = db.Exec("INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','https://master.test','fixture',1)", master); err != nil {
		t.Fatal(err)
	}
	peerKey := protocol.Encode(bytes.Repeat([]byte{4}, 32))
	summary := `{"native_resource_origin":"https://owner.test","_local_native_transport_receipt":{"transport":"Direct","revision":1,"origin":"https://owner.test"}}`
	if _, err = db.Exec("INSERT INTO node_relationships(relationship_id,peer_id,peer_endpoint,peer_key,credential,direction,mode,state,status,last_heartbeat,rtt_ms,failures,recoveries,peer_version,protocol,summary,created_at) VALUES(?,?, 'https://owner.test',?,'fixture','downstream','Direct','active','online',?,1,0,0,'test',2,?,1)", relation, owner, peerKey, time.Now().Unix(), summary); err != nil {
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

	// Synthetic fixture: existing pending records model scan volume but do not
	// claim to represent live capacity ledger history or production load.
	for i := 0; i < 512; i++ {
		id := fmt.Sprintf("%064x", 1000+i)
		e := sealedtree.Entry{ParentID: categoryID, ObjectID: id, Kind: "audio", Name: fmt.Sprintf("song-%04d.mp3", i)}
		p := sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: owner, Bytes: 7, SHA256: strings.Repeat("9", 64)}
		if _, err := ts.PrepareFileWithFreshLocators(ctx, e, p, sealedtree.Facts{ObjectID: id}); err != nil {
			t.Fatal(err)
		}
	}
	metadata, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	e := sealedtree.Entry{ParentID: categoryID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "new.mp3"}
	newPlacement := sealedtree.Placement{ObjectID: e.ObjectID, NativeObjectID: e.ObjectID, OwnerID: owner, Bytes: metadata.CiphertextSize, SHA256: strings.Repeat("9", 64), Encryption: &metadata}
	facts := sealedtree.Facts{ObjectID: e.ObjectID, PendingSelectedUpload: &sealedtree.SelectedUploadFact{UploadID: strings.Repeat("4", 32), AdminBinding: strings.Repeat("5", 64), Policy: "Direct", Revision: 1, Origin: "https://owner.test"}}
	bounded3, stop3 := context.WithTimeout(ctx, 10*time.Second)
	defer stop3()
	proof, err := ts.PreflightCategoryAndOwner(bounded3, categoryID, owner)
	if err != nil {
		t.Fatal(err)
	}
	check := func(_ context.Context, _ queryer, _ *sealedtree.CoordinatedMutation, p sealedtree.SelectedPending) error {
		if p.Placement.Encryption == nil || *p.Placement.Encryption != metadata {
			return store.ErrNodeState
		}
		return nil
	}
	var before, after syscall.Rusage
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, already, err := r.prepareSelectedAfterPreflight(bounded3, ts, proof, key, e, newPlacement, facts, 10*store.GiB, check)
	duration := time.Since(started)
	if e := syscall.Getrusage(syscall.RUSAGE_SELF, &after); e != nil {
		t.Fatal(e)
	}
	if err != nil || already {
		t.Fatal("admission failed", err, already)
	}
	cpu := time.Duration(after.Utime.Sec+after.Stime.Sec-before.Utime.Sec-before.Stime.Sec)*time.Second + time.Duration(after.Utime.Usec+after.Stime.Usec-before.Utime.Usec-before.Stime.Usec)*time.Microsecond
	t.Logf("synthetic 512 pending final admission call=%s process_cpu=%s; includes Owner/ingress/tree acquisitions, policy and capacity commit; elapsed is an upper bound for ingress lock holding, not production SLA", duration, cpu)
}
