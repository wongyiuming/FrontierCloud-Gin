//go:build linux

package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	storeSQLite "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestSelectedDirectAdmissionUsesRealPairAndPolicyFence(t *testing.T) {
	if os.Getenv("FC_SELECTED_OWNER_RECOVERY_CHILD") == "1" {
		testSelectedRecoveryChild(t)
		return
	}
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, _ := testNode(t, "Master", "https://master.test", transport)
	follower, db := testNode(t, "Follower", "https://owner.test", transport)
	transport.nodes["https://master.test"], transport.nodes["https://owner.test"] = master, follower
	pair, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relationID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	mr, err := master.repo.Relationship(ctx, relationID)
	if err != nil {
		t.Fatal(err)
	}
	if err = master.ConfigureSelectedAdminOrigin(ctx, "https://master.test"); err != nil {
		t.Fatal(err)
	}
	probe := &selectedProbeControl{localControl: transport}
	follower.transport = probe
	credential, err := master.identity.vault.Unseal(mr.Credential)
	if err != nil {
		t.Fatal(err)
	}
	masterID, err := master.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := follower.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Mkdir(filepath.Join(dir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	registry := &selectedRegistryFixture{testVolume: &testVolume{}, root: root}
	follower.volume = registry
	fence, err := ownerfence.Create(root, dir, follower.identity)
	if err != nil {
		t.Fatal(err)
	}
	coord := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcceptNativeDirectApplication(context.Context, string, int64, string) error
		AcceptNativeTransportApplication(context.Context, string, int64, string) error
	})
	if err = coord.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = coord.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	if err = coord.AcceptNativeDirectApplication(ctx, relationID, 7, "https://owner.test"); err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := protocol.SelectedStorageAdminBinding(credential, relationID, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	data := bytes.Repeat([]byte{42}, int(meta.CiphertextSize))
	digest := sha256.Sum256(data)
	claim := protocol.SelectedStorageUpload{Relationship: relationID, Master: masterID.ID, Owner: ownerID.ID, MediaID: strings.Repeat("1", 64), ObjectID: strings.Repeat("2", 64), UploadID: strings.Repeat("3", 32), OperationID: strings.Repeat("4", 64), ContentSHA256: hex.EncodeToString(digest[:]), RelationshipBinding: strings.Repeat("9", 64), Generation: strings.Repeat("a", 64), StageID: strings.Repeat("b", 64), PublishChallenge: strings.Repeat("c", 64), CleanupChallenge: strings.Repeat("d", 64), Size: meta.CiphertextSize, Policy: "Direct", Revision: 7, ResourceOrigin: "https://owner.test", AdminOrigin: "https://master.test", AdminBinding: binding, ExpiresAt: now + 90, Encryption: &meta}
	token, err := protocol.SignSelectedStorageUpload(credential, claim, now)
	if err != nil {
		t.Fatal(err)
	}

	if follower.selectedOriginAuthorized(ctx, claim, "https://public-ingress.test") || follower.selectedOriginAuthorized(ctx, protocol.SelectedStorageUpload{Relationship: claim.Relationship, AdminOrigin: "https://public-ingress.test"}, "https://master.test") || !follower.selectedOriginAuthorized(ctx, claim, "https://master.test") {
		t.Fatal("browser origin, signed origin, and authenticated observation must match")
	}
	if _, lease, e := follower.AdmitSelectedDirectUpload(ctx, token); !errors.Is(e, ErrCapability) || lease != nil {
		t.Fatal("unbounded admission", e)
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, lease, e := follower.AdmitSelectedDirectUpload(bounded, token+"x"); !errors.Is(e, ErrCapability) || lease != nil {
		t.Fatal("invalid signature", e)
	}
	// A token must still be fresh after the Master origin roundtrip; an
	// already admitted long stream may then outlive the short token TTL.
	expiring := claim
	expiring.ExpiresAt = time.Now().Unix() + 2
	expiringToken, e := protocol.SignSelectedStorageUpload(credential, expiring, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	beforeProbes := probe.probes
	probe.delay = 2100 * time.Millisecond
	_, _, e = follower.receiveSelectedDirect(bounded, expiringToken, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(data)), time.Second, root)
	probe.delay = 0
	if e == nil || probe.probes != beforeProbes+1 {
		t.Fatal("expired ticket accepted after origin roundtrip", e)
	}
	// Cancel while awaiting the Master origin proof. The operation must return
	// and release its Owner lease before a policy writer can proceed.
	probe.delay = 5 * time.Second
	probe.started = make(chan struct{}, 1)
	probeCtx, cancelProbe := context.WithCancel(bounded)
	finishedProbe := make(chan error, 1)
	go func() {
		_, _, e := follower.receiveSelectedDirect(probeCtx, token, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(data)), time.Second, root)
		finishedProbe <- e
	}()
	select {
	case <-probe.started:
	case <-time.After(time.Second):
		t.Fatal("origin probe did not start")
	}
	cancelProbe()
	select {
	case e := <-finishedProbe:
		if e == nil {
			t.Fatal("cancelled origin probe accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled origin probe did not terminate")
	}
	probe.delay, probe.started = 0, nil
	writerCtx, stopWriter := context.WithTimeout(ctx, time.Second)
	writerLease, e := fence.Acquire(writerCtx, true)
	stopWriter()
	if e != nil {
		t.Fatal("cancelled origin probe retained Owner lease", e)
	}
	writerLease.Release()
	if _, _, err := follower.receiveSelectedDirect(bounded, token, "https://public-ingress.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(data)), time.Second, root); err == nil {
		t.Fatal("untrusted browser origin accepted")
	}
	if _, err := root.Lstat("staging/" + claim.OperationID + ".part"); !os.IsNotExist(err) {
		t.Fatal("rejected origin created stage", err)
	}
	receipt, signature, err := follower.receiveSelectedDirect(bounded, token, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(data)), time.Second, root)
	if err != nil || receipt.OperationID != claim.OperationID || receipt.StageID != claim.StageID || receipt.RelationshipBinding != claim.RelationshipBinding || receipt.Challenge != claim.PublishChallenge {
		t.Fatal("paired Owner receive", err)
	}
	payload, err := receipt.Payload()
	if err != nil || protocol.Verify(mr.PublicKey, payload, signature) != nil {
		t.Fatal("Owner receipt signature", err)
	}
	blobPath, err := sealedtree.BlobPath(claim.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := root.ReadFile(blobPath)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("Owner blob bytes", err)
	}
	// The receiver may have committed and signed while the response was lost.
	// A newly authorized retry verifies the original saved stage and returns
	// the exact same signed binding, without trusting the old response.
	retryToken, err := protocol.SignSelectedStorageUpload(credential, claim, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	var sequence int
	var databaseName, databasePath string
	if err = db.Database().QueryRowContext(ctx, "PRAGMA database_list").Scan(&sequence, &databaseName, &databasePath); err != nil {
		t.Fatal(err)
	}
	reopenedIdentity, err := OpenExisting(ctx, db.Nodes(), filepath.Join(filepath.Dir(databasePath), "secrets"))
	if err != nil {
		t.Fatal("reopen Owner identity", err)
	}
	reopened := NewService(db.Nodes(), reopenedIdentity, transport)
	reopened.transport = probe
	reopened.volume = registry
	recovered, recoveredSignature, err := reopened.recoverSelectedDirect(bounded, retryToken, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(nil)), time.Second, root)
	if err != nil || recovered != receipt || recoveredSignature != signature {
		t.Fatal("lost receipt recovery", err)
	}
	childCtx, stopChild := context.WithTimeout(ctx, 10*time.Second)
	defer stopChild()
	child := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestSelectedDirectAdmissionUsesRealPairAndPolicyFence$")
	child.Env = append(os.Environ(), "FC_SELECTED_OWNER_RECOVERY_CHILD=1", "FC_SELECTED_OWNER_DB="+databasePath, "FC_SELECTED_OWNER_ROOT="+dir, "FC_SELECTED_OWNER_RELATION="+relationID, "FC_SELECTED_OWNER_TOKEN="+retryToken, "FC_SELECTED_OWNER_SIGNATURE="+signature)
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatalf("Owner process recovery: %v %s", e, out)
	}
	stage, err := root.OpenFile("staging/"+claim.OperationID+".part", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stage.WriteAt([]byte{0}, 0); err != nil {
		t.Fatal(err)
	}
	if err = stage.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = stage.Close(); err != nil {
		t.Fatal(err)
	}
	corruptReceipt, corruptSignature, err := reopened.recoverSelectedDirect(bounded, retryToken, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(nil)), time.Second, root)
	if err == nil || corruptSignature != "" || corruptReceipt.OperationID != "" {
		t.Fatal("corrupted stage produced a recovered receipt", err)
	}
	broken := claim
	broken.OperationID, broken.ObjectID, broken.ContentSHA256 = strings.Repeat("e", 64), strings.Repeat("f", 64), strings.Repeat("5", 64)
	badToken, err := protocol.SignSelectedStorageUpload(credential, broken, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	badReceipt, badSignature, err := follower.receiveSelectedDirect(bounded, badToken, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(data)), time.Second, root)
	if err == nil || badSignature != "" || badReceipt.OperationID != "" {
		t.Fatal("bad bytes produced a receipt", err)
	}
	badPath, err := sealedtree.BlobPath(broken.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = root.Stat(badPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bad bytes became visible", err)
	}
	badReceipt, badSignature, err = follower.recoverSelectedDirect(bounded, badToken, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(nil)), time.Second, root)
	if err == nil || badSignature != "" || badReceipt.OperationID != "" {
		t.Fatal("incomplete stage produced recovered receipt", err)
	}
	interrupted := claim
	interrupted.OperationID, interrupted.ObjectID = strings.Repeat("0", 64), strings.Repeat("5", 64)
	interruptedToken, err := protocol.SignSelectedStorageUpload(credential, interrupted, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	blockedBody := &selectedBlockingBody{closed: make(chan struct{})}
	cancelReceipt, cancelSignature, err := follower.receiveSelectedDirect(bounded, interruptedToken, "https://master.test", &selectedFixtureDeadline{}, blockedBody, 120*time.Millisecond, root)
	if err == nil || cancelSignature != "" || cancelReceipt.OperationID != "" {
		t.Fatal("cancelled stream produced a receipt", err)
	}
	cancelPath, err := sealedtree.BlobPath(interrupted.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = root.Stat(cancelPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled stream published a blob", err)
	}
	// This test-only HTTP server exercises the real Follower Service. The
	// production HTTP route and Master Admin integration remain unregistered.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, stop := context.WithTimeout(r.Context(), 5*time.Second)
		defer stop()
		var received protocol.OpaqueCapacityReceipt
		var sig string
		var e error
		if r.URL.Path == "/recover" {
			received, sig, e = follower.recoverSelectedDirect(c, r.Header.Get("X-Fixture-Grant"), "https://master.test", http.NewResponseController(w), r.Body, 4*time.Second, root)
		} else {
			received, sig, e = follower.receiveSelectedDirect(c, r.Header.Get("X-Fixture-Grant"), "https://master.test", http.NewResponseController(w), r.Body, 4*time.Second, root)
		}
		if e != nil {
			http.Error(w, "rejected", http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
			Signature string                         `json:"signature"`
		}{received, sig})
	}))
	defer server.Close()
	httpClaim := claim
	httpClaim.OperationID, httpClaim.ObjectID, httpClaim.UploadID = strings.Repeat("6", 64), strings.Repeat("7", 64), strings.Repeat("8", 32)
	httpClaim.Generation, httpClaim.StageID = strings.Repeat("8", 64), strings.Repeat("0", 64)
	httpClaim.PublishChallenge, httpClaim.CleanupChallenge = strings.Repeat("e", 64), strings.Repeat("f", 64)
	httpToken, err := protocol.SignSelectedStorageUpload(credential, httpClaim, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, server.URL+"/upload", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Fixture-Grant", httpToken)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatal("real Follower HTTP receive", response.StatusCode)
	}
	// Discard the response to simulate a receipt lost after the Owner committed.
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	request, err = http.NewRequest(http.MethodPost, server.URL+"/recover", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Fixture-Grant", httpToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
		Signature string                         `json:"signature"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&wire) != nil {
		t.Fatal("real Follower HTTP recovery", response.StatusCode)
	}
	_ = response.Body.Close()
	wirePayload, err := wire.Receipt.Payload()
	if err != nil || wire.Receipt.OperationID != httpClaim.OperationID || protocol.Verify(mr.PublicKey, wirePayload, wire.Signature) != nil {
		t.Fatal("recovered HTTP receipt", err)
	}
	if _, _, err = follower.cleanupSelectedDirect(bounded, httpToken, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(nil)), time.Second, root); err == nil {
		t.Fatal("upload ticket authorized cleanup")
	}
	cleanupToken, err := protocol.SignSelectedStorageCleanup(credential, httpClaim, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	cleanReceipt, cleanSignature, err := follower.cleanupSelectedDirect(bounded, cleanupToken, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(nil)), time.Second, root)
	if err != nil || cleanReceipt.Challenge != httpClaim.CleanupChallenge || cleanReceipt.OperationID != httpClaim.OperationID {
		t.Fatal("Owner cleanup", err)
	}
	cleanPayload, err := cleanReceipt.Payload()
	if err != nil || protocol.Verify(mr.PublicKey, cleanPayload, cleanSignature) != nil {
		t.Fatal("Owner cleanup signature", err)
	}
	cleanBlob, _ := sealedtree.BlobPath(httpClaim.ObjectID)
	if _, err = root.Stat(cleanBlob); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cleanup left blob visible", err)
	}
	if _, err = root.Stat("staging/" + httpClaim.OperationID + ".part"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cleanup left stage", err)
	}
	if _, _, err = follower.receiveSelectedDirect(bounded, httpToken, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(data)), time.Second, root); err == nil {
		t.Fatal("stale upload ticket bypassed cancellation tombstone")
	}
	reclean, resignature, err := follower.cleanupSelectedDirect(bounded, cleanupToken, "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(nil)), time.Second, root)
	if err != nil || reclean != cleanReceipt || resignature != cleanSignature {
		t.Fatal("cleanup retry", err)
	}
	got, lease, err := follower.AdmitSelectedDirectUpload(bounded, token)
	if err != nil || lease == nil || got.OperationID != claim.OperationID || got.Encryption == nil || *got.Encryption != meta {
		t.Fatal("valid paired admission", err)
	}
	changed := make(chan error, 1)
	writer, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	go func() { changed <- coord.AcceptNativeTransportApplication(writer, relationID, 8, "Relay") }()
	select {
	case err = <-changed:
		lease.Release()
		t.Fatal("policy changed before held operation drained", err)
	case <-time.After(120 * time.Millisecond):
	}
	lease.Release()
	if err = <-changed; err != nil {
		t.Fatal("policy change after drain", err)
	}
	if _, lease, e := follower.AdmitSelectedDirectUpload(bounded, token); !errors.Is(e, ErrCapability) || lease != nil {
		t.Fatal("stale Direct grant", e)
	}
}

type selectedFixtureDeadline struct{}

// This unit fixture exercises policy admission; registry durability and
// ciphertext verification are tested through the real media-backed HTTP path.
type selectedRegistryFixture struct {
	*testVolume
	root *os.Root
}

func (f *selectedRegistryFixture) InventoryRoot() *os.Root { return f.root }
func (*selectedRegistryFixture) PublishSelectedOwnerBinding(context.Context, protocol.SelectedStorageUpload) error {
	return nil
}
func (*selectedRegistryFixture) CancelSelectedOwnerBinding(context.Context, protocol.SelectedStorageUpload) error {
	return nil
}

func (*selectedFixtureDeadline) SetReadDeadline(time.Time) error { return nil }

type selectedBlockingBody struct {
	closed chan struct{}
	once   sync.Once
}

func (b *selectedBlockingBody) Read([]byte) (int, error) { <-b.closed; return 0, io.ErrClosedPipe }
func (b *selectedBlockingBody) Close() error             { b.once.Do(func() { close(b.closed) }); return nil }

func testSelectedRecoveryChild(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dbPath, dir := os.Getenv("FC_SELECTED_OWNER_DB"), os.Getenv("FC_SELECTED_OWNER_ROOT")
	db, err := storeSQLite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	identity, err := OpenExisting(ctx, db.Nodes(), filepath.Join(filepath.Dir(dbPath), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := ownerfence.Open(root, dir, identity)
	if err != nil {
		t.Fatal(err)
	}
	coord := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
	})
	if err = coord.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	service := NewService(db.Nodes(), identity, nil)
	_, sig, err := service.recoverSelectedDirect(ctx, os.Getenv("FC_SELECTED_OWNER_TOKEN"), "https://master.test", &selectedFixtureDeadline{}, io.NopCloser(bytes.NewReader(nil)), time.Second, root)
	if err == nil || sig != "" {
		t.Fatal("reopened Owner recovered without reachable Master", err)
	}
}
