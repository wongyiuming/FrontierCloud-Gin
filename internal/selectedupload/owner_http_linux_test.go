//go:build linux

package selectedupload_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// These are synthetic HTTP fixtures, not a registered product route. The
// session checker and capacity/intent are test-only and prove no deployment
// readiness; only the owner policy lease and opaque filesystem are real.
type fixtureCodec struct{}

func (fixtureCodec) SealOpaqueOwnerRecord(_ string, raw []byte) (string, error) {
	return base64.StdEncoding.EncodeToString(raw), nil
}
func (fixtureCodec) OpenOpaqueOwnerRecord(_ string, raw string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(raw)
}

func TestSelectedUploadSyntheticOwnerHTTPPolicyDrainAndOpaqueBlob(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "owner.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	owner, master, relationID := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	if _, err = db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: owner, Role: "Standalone", PrivateKey: "fixture"}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().Exec("UPDATE node_identity SET `role`='Follower',endpoint='https://owner.test' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	pair := store.PairPackage{Nonce: strings.Repeat("4", 32), TokenHash: strings.Repeat("a", 64), ExpiresAt: now + 300}
	if _, err = db.Nodes().IssuePair(ctx, pair, now, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	relation := store.Relationship{ID: relationID, PeerID: master, Endpoint: "https://master.test", PublicKey: strings.Repeat("A", 43), Credential: "fixture", Direction: "upstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: now}
	if err = db.Nodes().ConsumePair(ctx, pair, relation, now, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = db.Nodes().ActivateRelationship(ctx, relationID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(dir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := ownerfence.Create(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcceptNativeDirectApplication(context.Context, string, int64, string) error
		AcceptNativeTransportApplication(context.Context, string, int64, string) error
	})
	if err = coordinator.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = coordinator.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	if err = coordinator.AcceptNativeDirectApplication(ctx, relationID, 7, "https://owner.test"); err != nil {
		t.Fatal(err)
	}
	pub, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	journalVault, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	cred := protocol.Encode(bytes.Repeat([]byte{9}, 48))
	binding, err := protocol.SelectedStorageAdminBinding(cred, relationID, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	var adminLive atomic.Bool
	adminLive.Store(true)
	admitted := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claim, err := protocol.VerifySelectedStorageUpload(cred, r.Header.Get("X-Fixture-Grant"), time.Now().Unix())
		// In production the authenticated Master session, durable reservation,
		// intent, CORS and current relationship must be independently verified.
		if err != nil || !adminLive.Load() || claim.AdminBinding != binding || claim.Owner != owner || claim.Master != master || claim.Policy != "Direct" || claim.ResourceOrigin != "https://owner.test" || r.ContentLength != claim.Size {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		lease, err := db.Nodes().(store.SelectedUploadOwnerPolicyRepository).AcquireSelectedUploadOwnerPolicy(r.Context(), store.SelectedUploadPolicy{RelationshipID: claim.Relationship, MasterID: claim.Master, OwnerID: claim.Owner, Transport: claim.Policy, Revision: claim.Revision, ResourceOrigin: claim.ResourceOrigin})
		if err != nil {
			http.Error(w, "policy changed", http.StatusConflict)
			return
		}
		admitted <- struct{}{}
		var prepared *sealedtree.PreparedBlob
		err = selectedupload.RunOperationStaged(r.Context(), lease, http.NewResponseController(w), r.Body, time.Second, root, journalVault, claim, false, func(c context.Context) (func(), error) {
			prepared, err = pub.Prepare(c, claim.OperationID, claim.ObjectID, claim.Size, claim.ContentSHA256, r.Body)
			if err != nil {
				return nil, err
			}
			return func() { _ = prepared.Close() }, nil
		}, func(c context.Context) error { return prepared.Publish(c) })
		if err != nil {
			http.Error(w, "not published", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	data := []byte("synthetic opaque encrypted bytes")
	sum := sha256.Sum256(data)
	claim := protocol.SelectedStorageUpload{Relationship: relationID, Master: master, Owner: owner, MediaID: strings.Repeat("5", 64), ObjectID: strings.Repeat("6", 64), UploadID: strings.Repeat("7", 32), OperationID: strings.Repeat("8", 64), ContentSHA256: hex.EncodeToString(sum[:]), RelationshipBinding: strings.Repeat("9", 64), Generation: strings.Repeat("a", 64), StageID: strings.Repeat("b", 64), PublishChallenge: strings.Repeat("c", 64), CleanupChallenge: strings.Repeat("d", 64), Size: int64(len(data)), Policy: "Direct", Revision: 7, ResourceOrigin: "https://owner.test", AdminOrigin: "https://master.test", AdminBinding: binding, ExpiresAt: now + 120}
	token, err := protocol.SignSelectedStorageUpload(cred, claim, now)
	if err != nil {
		t.Fatal(err)
	}
	request := func(token string, body []byte) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPut, server.URL, bytes.NewReader(body))
		req.Header.Set("X-Fixture-Grant", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	adminLive.Store(false)
	if resp := request(token, data); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("fixture-revoked session accepted", resp.StatusCode)
	}
	adminLive.Store(true)
	if resp := request(token, data); resp.StatusCode != http.StatusCreated {
		t.Fatal("valid synthetic upload rejected", resp.StatusCode)
	}
	<-admitted
	blobPath, err := sealedtree.BlobPath(claim.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := root.ReadFile(blobPath)
	if err != nil || !bytes.Equal(stored, data) || strings.Contains(blobPath, "music") {
		t.Fatal("opaque object mismatch", err)
	}

	// A second, incomplete stream holds the old policy fence until it exits.
	claim.ObjectID, claim.OperationID, claim.UploadID = strings.Repeat("e", 64), strings.Repeat("f", 64), strings.Repeat("c", 32)
	token, err = protocol.SignSelectedStorageUpload(cred, claim, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fmt.Fprintf(conn, "PUT / HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: %d\r\nX-Fixture-Grant: %s\r\n\r\nx", len(data), token); err != nil {
		t.Fatal(err)
	}
	select {
	case <-admitted:
	case <-time.After(3 * time.Second):
		t.Fatal("partial request was not admitted")
	}
	changed := make(chan error, 1)
	go func() { changed <- coordinator.AcceptNativeTransportApplication(ctx, relationID, 8, "Relay") }()
	select {
	case err := <-changed:
		conn.Close()
		t.Fatal("policy changed with upload still admitted", err)
	case <-time.After(100 * time.Millisecond):
	}
	conn.Close()
	select {
	case err := <-changed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("policy change remained blocked after client disconnect")
	}
	incompletePath, _ := sealedtree.BlobPath(claim.ObjectID)
	if _, err = root.Stat(incompletePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("interrupted object became visible", err)
	}
	if resp := request(token, data); resp.StatusCode != http.StatusConflict {
		t.Fatal("old Direct policy token accepted after change", resp.StatusCode)
	}
}

// This negative control proves a stream guard is not a publication authority:
// an uncooperative callback can ignore the expired context and publish before
// the guard reports the failure. Product wiring must use a separate fenced
// commit that validates context, policy and session at the publication point.
func TestSelectedUploadGuardAloneCannotAuthorizePublication(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pub, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := []byte("fixture")
		sum := sha256.Sum256(data)
		lease := &fixtureLease{}
		serverResult <- selectedupload.RunStream(r.Context(), lease, http.NewResponseController(w), r.Body, 100*time.Millisecond, func(c context.Context) error {
			<-c.Done()
			return pub.Publish(context.Background(), strings.Repeat("a", 64), strings.Repeat("b", 64), int64(len(data)), hex.EncodeToString(sum[:]), bytes.NewReader(data))
		})
	}))
	defer server.Close()
	resp, err := http.Post(server.URL, "application/octet-stream", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// The socket deadline may cancel the HTTP request context before the
	// bounded context reports its own deadline; both are failed admissions.
	if err = <-serverResult; !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatal("expired stream did not report cancellation", err)
	}
	name, _ := sealedtree.BlobPath(strings.Repeat("b", 64))
	if _, err := root.Stat(name); err != nil {
		t.Fatal("negative control failed to demonstrate the unsafe publication", err)
	}
}

type fixtureLease struct{}

func (*fixtureLease) Check(context.Context) error             { return nil }
func (*fixtureLease) Binding(context.Context) (string, error) { return "fixture", nil }
func (*fixtureLease) Release()                                {}

// The safe staged path must never publish after cancellation and must keep
// its policy lease until the synchronous writer has actually exited.
func TestSelectedUploadCancellationCannotPublishAfterDrain(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pub, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	writerDone := make(chan struct{})
	lease := &drainLease{writerDone: writerDone}
	result := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := []byte("fixture")
		sum := sha256.Sum256(data)
		result <- selectedupload.RunStaged(r.Context(), lease, http.NewResponseController(w), r.Body, 100*time.Millisecond, func(c context.Context) error {
			defer close(writerDone)
			<-c.Done()
			return nil
		}, func(c context.Context) error {
			return pub.Publish(c, strings.Repeat("a", 64), strings.Repeat("b", 64), int64(len(data)), hex.EncodeToString(sum[:]), bytes.NewReader(data))
		})
	}))
	defer server.Close()
	resp, err := http.Post(server.URL, "application/octet-stream", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err = <-result; !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled stream unexpectedly succeeded", err)
	}
	name, _ := sealedtree.BlobPath(strings.Repeat("b", 64))
	if _, err := root.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled stream published an object", err)
	}
	if !lease.released.Load() || lease.releasedBeforeWriter.Load() {
		t.Fatal("policy lease was released before writer exit")
	}
}

type drainLease struct {
	writerDone                     chan struct{}
	released, releasedBeforeWriter atomic.Bool
}

func (*drainLease) Check(context.Context) error             { return nil }
func (*drainLease) Binding(context.Context) (string, error) { return "fixture", nil }
func (l *drainLease) Release() {
	select {
	case <-l.writerDone:
	default:
		l.releasedBeforeWriter.Store(true)
	}
	l.released.Store(true)
}
