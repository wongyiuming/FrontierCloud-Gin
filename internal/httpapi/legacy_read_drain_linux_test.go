//go:build linux

package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type blockingLegacyWriter struct {
	*httptest.ResponseRecorder
	ctx     context.Context
	started chan struct{}
	once    sync.Once
}

// The Owner processes and signs the request, but the response is lost before
// the Master can persist it. A retry must reuse the durable pending intent.
type dropLegacyResponse struct{ base http.RoundTripper }

func (d dropLegacyResponse) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := d.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	response.Body.Close()
	return nil, errors.New("injected lost owner response")
}

func (w *blockingLegacyWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.ctx.Done()
	return 0, w.ctx.Err()
}

// Real SQLite, vaults, pairing, owner flock and Gin handlers. Control uses a
// loopback TLS server with its test certificate; the held read is in-process.
func TestLegacyReadDrainAuthenticatedOwnerHTTP(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, masterDB, _, masterPublic, master := clusterFixture(t, "https://master.test", transport, false)
	_, ownerDB, ownerDir, ownerPublic, owner := clusterFixture(t, "https://follower.test", transport, true)
	masterID, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := owner.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := owner.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relationID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := masterDB.Nodes().Relationship(ctx, relationID)
	if err != nil {
		t.Fatal(err)
	}
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 5*store.GiB
	if err = masterDB.Pool().ConfigureMember(ctx, ownerID.ID, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = master.Tick(ctx, relation); err != nil {
		t.Fatal(err)
	}
	if err = masterDB.Nodes().SetRelationshipMode(ctx, relationID, "Direct", false, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(10)
	if err != nil {
		t.Fatal(err)
	}
	var tickets []store.UploadReservation
	for _, encrypted := range []bool{false, true} {
		var encryption *mediacrypto.Metadata
		payload := []byte("ID3payload")
		name := "plain.mp3"
		if encrypted {
			encryption, payload, name = &meta, bytes.Repeat([]byte{'x'}, int(meta.CiphertextSize)), "cipher.mp3"
		}
		ticket, e := masterPublic.media.ReserveMasterEncryptedUpload(ctx, name, "music/Drain", "", "direct", int64(len(payload)), 255, store.AdminAudit{}, encryption)
		if e != nil {
			t.Fatal(e)
		}
		reservation, e := masterDB.Pool().Upload(ctx, ticket.ID)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = master.UploadStorage(ctx, reservation, bytes.NewReader(payload)); e != nil {
			t.Fatal(e)
		}
		if _, e = masterPublic.media.FinalizeMasterUpload(ctx, ticket.ID, store.AdminAudit{}); e != nil {
			t.Fatal(e)
		}
		tickets = append(tickets, reservation)
	}
	legacyToken, err := master.MediaCapability(ctx, relationID, ownerID.ID, tickets[0].MediaID, tickets[0].MediaID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := "browser:v2:" + strings.Repeat("c", 64)
	session, err := masterPublic.crypto.NewSession(binding, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: ownerID.ID, Generation: 1, PublicOrigin: "https://entry.test", ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	admitted, admission := network.WithPublicAdmission(verified)
	defer admission.Abort()
	admitted, err = masterPublic.crypto.WithDirectSession(admitted, binding, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	newToken, err := master.MediaIngressCapability(admitted, relationID, ownerID.ID, tickets[1].MediaID, tickets[1].MediaID, meta.CiphertextSize, time.Now().Unix()+60, &meta)
	if err != nil {
		t.Fatal(err)
	}
	remoteIngress, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: strings.Repeat("4", 32), Generation: 2, PublicOrigin: "https://remote-entry.test", ClientIP: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	remoteAdmitted, remoteAdmission := network.WithPublicAdmission(remoteIngress)
	defer remoteAdmission.Abort()
	remoteAdmitted, err = masterPublic.crypto.WithDirectSession(remoteAdmitted, binding, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	remoteToken, err := master.MediaIngressCapability(remoteAdmitted, relationID, ownerID.ID, tickets[1].MediaID, tickets[1].MediaID, meta.CiphertextSize, time.Now().Unix()+60, &meta)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(ownerDir, "media")
	if err = os.Chmod(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(rootPath, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	identity, err := node.Initialize(ctx, ownerDB.Nodes(), ownerPublic.settings.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := ownerfence.Create(root, rootPath, identity)
	if err != nil {
		t.Fatal(err)
	}
	repository := ownerDB.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
	})
	if err = repository.ConfigureOwnerControlFence(func(ctx context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(ctx, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = repository.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	scope, err := owner.LegacyReadScope(ctx, relationID)
	if err != nil {
		t.Fatal(err)
	}
	if err = fence.InitializeLegacyReadState(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if _, err = node.NewLegacyReadGuard(owner, fence, true); err == nil {
		t.Fatal("Nginx X-Accel accepted")
	}
	guard, err := node.NewLegacyReadGuard(owner, fence, false)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := node.NewSelectedDirectReceiver(ctx, owner, fence)
	if err != nil || !selected.ReadyFor(owner, ownerPublic.media) || selected.ReadyFor(master, ownerPublic.media) || selected.ReadyFor(nil, ownerPublic.media) {
		t.Fatal("selected receiver volume or identity binding", err)
	}
	if err = ownerPublic.media.VerifyLegacyOwnerVolume(ctx, masterDB.Nodes(), identity, fence); err == nil {
		t.Fatal("foreign database accepted")
	}
	masterVault, err := node.Initialize(ctx, masterDB.Nodes(), masterPublic.settings.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err = ownerPublic.media.VerifyLegacyOwnerVolume(ctx, ownerDB.Nodes(), masterVault, fence); err == nil {
		t.Fatal("foreign node vault accepted")
	}
	otherRootPath := t.TempDir()
	if err = os.Mkdir(filepath.Join(otherRootPath, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	otherRoot, err := os.OpenRoot(otherRootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer otherRoot.Close()
	otherFence, err := ownerfence.Create(otherRoot, otherRootPath, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = ownerPublic.media.VerifyLegacyOwnerVolume(ctx, ownerDB.Nodes(), identity, otherFence); err == nil {
		t.Fatal("foreign data root accepted")
	}
	if _, err = node.NewSelectedDirectReceiver(ctx, owner, otherFence); err == nil {
		t.Fatal("selected receiver accepted foreign data root")
	}
	resolver, _ := network.New(nil)
	router := gin.New()
	if err = RegisterNodeMediaGuarded(gin.New(), ownerPublic.settings, resolver, owner, ownerPublic.media, &node.LegacyReadGuard{}); err == nil {
		t.Fatal("zero guard accepted")
	}
	if err = RegisterNodeMediaGuarded(gin.New(), ownerPublic.settings, resolver, master, ownerPublic.media, guard); err == nil {
		t.Fatal("guard bound to another node accepted")
	}
	if err = RegisterNodeMediaGuarded(gin.New(), ownerPublic.settings, resolver, owner, masterPublic.media, guard); err == nil {
		t.Fatal("foreign volume accepted")
	}
	badSettings := ownerPublic.settings
	badSettings.NginxMedia = true
	if err = RegisterNodeMediaGuarded(gin.New(), badSettings, resolver, owner, ownerPublic.media, guard); err == nil {
		t.Fatal("Nginx handler accepted")
	}
	if err = RegisterNodeMediaGuarded(router, ownerPublic.settings, resolver, owner, ownerPublic.media, guard); err != nil {
		t.Fatal(err)
	}
	if err = RegisterLegacyReadDrainControl(router, ownerPublic.settings, resolver, owner, ownerPublic.media, guard); err != nil {
		t.Fatal(err)
	}
	transport.routers["https://follower.test"] = router
	tlsServer := httptest.NewTLSServer(router)
	defer tlsServer.Close()
	transport.legacyTLSClient, transport.legacyTLSURL = tlsServer.Client(), tlsServer.URL
	transport.legacyTLSClient.Timeout = 10 * time.Second
	read := func(token, id, origin string) *httptest.ResponseRecorder {
		readCtx, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		r := httptest.NewRequest(http.MethodGet, "https://follower.test/internal/v1/media/"+id, nil).WithContext(readCtx)
		r.Header.Set("X-Media-Capability", token)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := read(legacyToken, tickets[0].MediaID, ""); w.Code != 200 {
		t.Fatal("legacy v2 unavailable", w.Code, w.Body.String())
	}
	if w := read(newToken, tickets[1].MediaID, "https://entry.test"); w.Code != 200 {
		t.Fatal("legacy v3 unavailable", w.Code, w.Body.String())
	}
	if w := read(remoteToken, tickets[1].MediaID, "https://remote-entry.test"); w.Code != 200 {
		t.Fatal("remote legacy v3 unavailable", w.Code, w.Body.String())
	}
	owner.ConfigureVolumes(ownerDB.Pool(), masterPublic.media, nil)
	if w := read(legacyToken, tickets[0].MediaID, ""); w.Code == 200 {
		t.Fatal("guard accepted changed control volume")
	}
	owner.ConfigureVolumes(ownerDB.Pool(), ownerPublic.media, nil)
	ownerLease, err := fence.Acquire(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	fenceBinding, err := ownerLease.Binding(ctx)
	ownerLease.Release()
	if err != nil {
		t.Fatal(err)
	}
	intentVault, err := vault.OpenExisting(masterPublic.settings.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	masterRow, err := masterDB.Nodes().ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	masterRepo := masterDB.Nodes().(*business.Repository)
	coordinator, err := node.NewLegacyReadCoordinator(master)
	if err != nil {
		t.Fatal(err)
	}
	adminHTTP := newS3HTTP(t, "Master")
	// Bind both the Admin audit repository and the control intent repository
	// to this fixture's actual Master database, then create a fresh session.
	cache := &s3HTTPTestCache{sessions: map[string]map[string]string{}, attempts: map[string]int64{}}
	adminAuth, err := admin.New(adminHTTP.admin.settings, cache, masterDB.Admin())
	if err != nil {
		t.Fatal(err)
	}
	adminHTTP.admin.auth = adminAuth
	if w := adminHTTP.call("POST", "/api/v1/media/admin/elevate", "token=s3-http-test-admin-key", false, false, true); w.Code != http.StatusOK {
		t.Fatal("master admin login", w.Code, w.Body.String())
	}
	if err = RegisterLegacyReadAdmin(adminHTTP.router, adminHTTP.admin, coordinator); err != nil {
		t.Fatal(err)
	}
	adminBody := `{"relationship_id":"` + relationID + `"}`
	adminPath := "/api/v1/media/admin/legacy-read/"
	for _, auth := range []struct{ session, csrf bool }{{false, true}, {true, false}} {
		w := adminHTTP.call("POST", adminPath+"enroll", adminBody, auth.session, auth.csrf, true)
		if w.Code == http.StatusOK {
			t.Fatal("unauthorized enrollment accepted")
		}
		if _, e := masterRepo.CurrentLegacyReadControl(ctx, masterRow, intentVault, relationID); e == nil {
			t.Fatal("unauthorized request created intent")
		}
	}
	adminCall := func(operation string) (string, error) {
		w := adminHTTP.call("POST", adminPath+operation, adminBody, true, true, true)
		if w.Code != http.StatusOK {
			return "", fmt.Errorf("admin %s: %d", operation, w.Code)
		}
		var result struct {
			Status string `json:"status"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
			return "", e
		}
		return result.Status, nil
	}
	baseTransport := transport.legacyTLSClient.Transport
	if baseTransport == nil {
		t.Fatal("missing test TLS transport")
	}
	transport.legacyTLSClient.Transport = dropLegacyResponse{base: baseTransport}
	if state, e := adminCall("enroll"); e == nil || state != "" {
		t.Fatal("lost enrollment response accepted")
	}
	transport.legacyTLSClient.Transport = baseTransport
	pending, err := masterRepo.CurrentLegacyReadControl(ctx, masterRow, intentVault, relationID)
	if err != nil || pending.Enrollment.State != "pending" {
		t.Fatal("missing pending enrollment", err)
	}
	if state, e := adminCall("enroll"); e != nil || state != "active" {
		t.Fatal("enrollment", state, e)
	}
	current, err := masterRepo.CurrentLegacyReadControl(ctx, masterRow, intentVault, relationID)
	if err != nil || current.Enrollment.State != "confirmed" || current.Enrollment.Receipt == nil {
		t.Fatal("persisted enrollment", err)
	}
	recovered := current.Enrollment
	if recovered.OperationID != pending.Enrollment.OperationID || recovered.Challenge != pending.Enrollment.Challenge {
		t.Fatal("retry replaced pending enrollment")
	}
	enrollment := *recovered.Receipt
	if enrollment.MasterID != masterID.ID || enrollment.OwnerID != ownerID.ID || enrollment.RelationshipBinding != scope.RelationshipBinding || enrollment.OwnerBinding != scope.OwnerBinding || enrollment.FenceBinding != fenceBinding {
		t.Fatal("incorrect enrolled scope")
	}
	// The recovery anchor and cross-protocol challenge uniqueness remain
	// separate activation requirements despite this durable fixture record.
	receipt := protocol.LegacyReadDrainReceipt{Kind: "legacy-media-drain-v1", OperationID: strings.Repeat("f", 32), Challenge: strings.Repeat("9", 64), ExpiresAt: recovered.ExpiresAt, MasterID: enrollment.MasterID, OwnerID: enrollment.OwnerID, RelationshipID: enrollment.RelationshipID, RelationshipBinding: enrollment.RelationshipBinding, OwnerBinding: enrollment.OwnerBinding, FenceBinding: enrollment.FenceBinding, State: "revoked"}
	statusRequest := protocol.LegacyReadStatusRequest{Action: "status", RequestID: strings.Repeat("1", 32), Challenge: strings.Repeat("2", 64), OriginalOperationID: receipt.OperationID, OriginalChallenge: receipt.Challenge, OriginalExpiresAt: receipt.ExpiresAt, ExpiresAt: time.Now().Unix() + 60, MasterID: enrollment.MasterID, OwnerID: enrollment.OwnerID, RelationshipID: enrollment.RelationshipID, RelationshipBinding: enrollment.RelationshipBinding, OwnerBinding: enrollment.OwnerBinding, FenceBinding: enrollment.FenceBinding}
	expiredReceipt := receipt
	expiredReceipt.ExpiresAt = time.Now().Unix()
	if signed, err := guard.Drain(ctx, expiredReceipt, func(context.Context) (store.Relationship, error) {
		t.Error("expired request reached auth")
		return store.Relationship{}, nil
	}); err == nil || signed.Signature != "" {
		t.Fatal("expired Owner drain signed", err)
	}
	expiredStatus := statusRequest
	expiredStatus.ExpiresAt = time.Now().Unix()
	if signed, err := guard.ObserveStatus(ctx, expiredStatus, func(context.Context) (store.Relationship, error) {
		t.Error("expired status reached auth")
		return store.Relationship{}, nil
	}); err == nil || signed.Signature != "" {
		t.Fatal("expired Owner status signed", err)
	}
	if _, err = adminCall("status"); err == nil {
		t.Fatal("active owner signed drain status")
	}
	if w := read(legacyToken, tickets[0].MediaID, ""); w.Code != 200 {
		t.Fatal("failed request changed state", w.Code)
	}
	payload, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := protocol.Canonical(payload)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := httptest.NewRequest(http.MethodPost, "https://follower.test"+protocol.LegacyReadDrainPath, bytes.NewReader(raw))
	unsignedW := httptest.NewRecorder()
	router.ServeHTTP(unsignedW, unsigned)
	if unsignedW.Code == 200 {
		t.Fatal("unauthenticated request accepted")
	}
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	streamRequest := httptest.NewRequest(http.MethodGet, "https://follower.test/internal/v1/media/"+tickets[0].MediaID, nil).WithContext(streamCtx)
	streamRequest.Header.Set("X-Media-Capability", legacyToken)
	writer := &blockingLegacyWriter{ResponseRecorder: httptest.NewRecorder(), ctx: streamCtx, started: make(chan struct{})}
	streamDone := make(chan struct{})
	go func() { defer close(streamDone); router.ServeHTTP(writer, streamRequest) }()
	select {
	case <-writer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not start")
	}
	type capturedRequest struct {
		header http.Header
		body   []byte
	}
	captured := make(chan capturedRequest, 1)
	transport.controlHook = func(route string, header http.Header, body []byte) {
		if route == protocol.LegacyReadDrainPath {
			select {
			case captured <- capturedRequest{header, body}:
			default:
			}
		}
	}
	type drainResult struct {
		state string
		err   error
	}
	drained := make(chan drainResult, 1)
	go func() {
		state, e := adminCall("drain")
		drained <- drainResult{state, e}
	}()
	var replay capturedRequest
	select {
	case replay = <-captured:
	case <-time.After(5 * time.Second):
		t.Fatal("drain request absent")
	}
	if err = json.Unmarshal(replay.body, &receipt); err != nil {
		t.Fatal("invalid drain wire", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		probeCtx, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		probe, e := fence.AcquireLegacyRead(probeCtx, scope)
		stop()
		if e != nil {
			break
		}
		probe.Release()
		if time.Now().After(deadline) {
			t.Fatal("draining did not block new readers")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case result := <-drained:
		t.Fatal("receipt before stream drained", result.err)
	default:
	}
	status, err := adminCall("status")
	if err != nil || status != "draining" {
		t.Fatal("draining status invalid", err)
	}
	resumeStarted := make(chan struct{}, 1)
	transport.controlHook = func(route string, _ http.Header, body []byte) {
		var request protocol.LegacyReadStatusRequest
		if route == protocol.LegacyReadStatusPath && json.Unmarshal(body, &request) == nil && request.Action == "resume" {
			select {
			case resumeStarted <- struct{}{}:
			default:
			}
		}
	}
	resumed := make(chan drainResult, 1)
	go func() { state, e := adminCall("resume"); resumed <- drainResult{state, e} }()
	select {
	case <-resumeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("fresh resume absent")
	}
	select {
	case result := <-resumed:
		t.Fatal("resume returned before stream drained", result.err)
	default:
	}
	if w := read(newToken, tickets[1].MediaID, "https://entry.test"); w.Code == 200 {
		t.Fatal("new legacy request admitted while draining")
	}
	// Simulate loss of the database anchor after draining starts. The old
	// stream can finish, but no receipt may be returned against a missing tag.
	if _, err = ownerDB.Database().ExecContext(ctx, `DELETE FROM sealed_tree_owner_fence WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-streamDone:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled stream did not close")
	}
	var result drainResult
	select {
	case result = <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not finish")
	}
	if result.err == nil || result.state != "" {
		t.Fatal("missing marker produced receipt", result.err)
	}
	select {
	case result = <-resumed:
	case <-time.After(5 * time.Second):
		t.Fatal("resume did not finish")
	}
	if result.err == nil || result.state != "" {
		t.Fatal("missing marker produced resume receipt", result.err)
	}
	retainedState := ""
	if err = fence.ObserveLegacyReadStatus(ctx, scope, receipt.OperationID, receipt.Challenge, receipt.ExpiresAt, func(context.Context, *ownerfence.Lease) error { return nil }, func(_ context.Context, _ *ownerfence.Lease, state string) error { retainedState = state; return nil }); err != nil || retainedState != "draining" {
		t.Fatal("marker loss changed state", retainedState, err)
	}
	// Restore the synthetic tag only inside this isolated fault fixture. Real
	// recovery cannot recreate a missing marker without an external anchor.
	if _, err = ownerDB.Database().ExecContext(ctx, `INSERT INTO sealed_tree_owner_fence(singleton,fence_tag) VALUES(1,?)`, fenceBinding); err != nil {
		t.Fatal(err)
	}
	state, err := adminCall("resume")
	if err != nil || state != "revoked" {
		t.Fatal("fresh resume failed after exact retry", err)
	}
	state, err = adminCall("drain")
	if err != nil || state != "revoked" {
		t.Fatal("signed receipt invalid after exact retry", err)
	}
	current, err = masterRepo.CurrentLegacyReadControl(ctx, masterRow, intentVault, relationID)
	if err != nil || current.Drain == nil || current.Drain.Receipt == nil || *current.Drain.Receipt != receipt {
		t.Fatal("drain not persisted", err)
	}
	verifiedPayload, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	signed := node.Envelope{Payload: verifiedPayload, Signature: current.Drain.Signature}
	if err = master.VerifyLegacyReadDrainReceipt(ctx, receipt, signed); err != nil {
		t.Fatal("invalid stored receipt", err)
	}
	for _, mutate := range []func(*protocol.LegacyReadDrainReceipt){func(r *protocol.LegacyReadDrainReceipt) { r.OperationID = strings.Repeat("a", 32) }, func(r *protocol.LegacyReadDrainReceipt) { r.OwnerID = "wrong-owner" }, func(r *protocol.LegacyReadDrainReceipt) { r.Kind = "wrong-kind" }} {
		changed := receipt
		mutate(&changed)
		if master.VerifyLegacyReadDrainReceipt(ctx, changed, signed) == nil {
			t.Fatal("tampered receipt accepted")
		}
	}
	if w := read(legacyToken, tickets[0].MediaID, ""); w.Code == 200 {
		t.Fatal("v2 token reopened")
	}
	if w := read(newToken, tickets[1].MediaID, "https://entry.test"); w.Code == 200 {
		t.Fatal("v3 token reopened")
	}
	if w := read(remoteToken, tickets[1].MediaID, "https://remote-entry.test"); w.Code == 200 {
		t.Fatal("remote v3 token reopened")
	}
	// Simulate a browser losing the successful response after the durable
	// commit. Repeating the action may report a still-fresh verified result,
	// but must not send a second drain request to the Owner.
	controlCalls := 0
	transport.controlHook = func(string, http.Header, []byte) { controlCalls++ }
	state, err = adminCall("drain")
	if err != nil || state != "revoked" || controlCalls != 0 {
		t.Fatal("committed drain recovery failed", state, err, controlCalls)
	}
	state, err = adminCall("resume")
	if err != nil || state != "revoked" || controlCalls != 0 {
		t.Fatal("committed resume recovery failed", state, err, controlCalls)
	}
	replayRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, tlsServer.URL+protocol.LegacyReadDrainPath, bytes.NewReader(replay.body))
	if err != nil {
		t.Fatal(err)
	}
	replayRequest.Header = replay.header
	replayResponse, err := transport.legacyTLSClient.Do(replayRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer replayResponse.Body.Close()
	if replayResponse.StatusCode == 200 {
		t.Fatal("replayed authenticated nonce accepted")
	}
	if err = os.Remove(filepath.Join(rootPath, ".opaque-aliases", ".legacy-read-state")); err != nil {
		t.Fatal(err)
	}
	// A previously confirmed fresh result is only a historical response; do
	// not treat its cached response as a new Owner attestation or activation.
	statusRequest.OriginalOperationID, statusRequest.OriginalChallenge, statusRequest.OriginalExpiresAt = receipt.OperationID, receipt.Challenge, receipt.ExpiresAt
	statusRequest.RequestID, statusRequest.Challenge, statusRequest.ExpiresAt = strings.Repeat("5", 32), strings.Repeat("a", 64), time.Now().Unix()+60
	if signed, e := guard.ObserveStatus(ctx, statusRequest, func(held context.Context) (store.Relationship, error) {
		return ownerDB.Nodes().Relationship(held, relationID)
	}); e == nil || signed.Signature != "" {
		t.Fatal("missing owner state attested")
	}
	if _, err = fence.AcquireLegacyRead(ctx, scope); !errors.Is(err, ownerfence.ErrUnsafe) {
		t.Fatal("missing state admitted", err)
	}
}
