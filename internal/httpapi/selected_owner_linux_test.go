//go:build linux

package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestSelectedOwnerActualHTTPFreshMasterProof(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	masterRouter, masterDB, _, masterPublic, master := clusterFixture(t, "https://master.test", transport, false)
	ownerRouter, ownerDB, ownerDir, ownerPublic, owner := clusterFixture(t, "https://follower.test", transport, true)
	masterID, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := owner.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err = master.ConfigureSelectedAdminOrigin(ctx, "https://master.test"); err != nil {
		t.Fatal(err)
	}
	unauth := request(masterRouter, "POST", "https://master.test/internal/v1/selected-admin-origin", `{"challenge":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatal("unpaired request received Master proof", unauth.Code)
	}

	pair, err := owner.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	rid, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := masterDB.Nodes().Relationship(ctx, rid)
	if err != nil {
		t.Fatal(err)
	}
	private, err := vault.OpenExisting(masterPublic.settings.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := private.Unseal(relation.Credential)
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
	repo := ownerDB.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcceptNativeDirectApplication(context.Context, string, int64, string) error
		AcceptNativeTransportApplication(context.Context, string, int64, string) error
	})
	if err = repo.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = repo.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	if err = repo.AcceptNativeDirectApplication(ctx, rid, 7, "https://follower.test"); err != nil {
		t.Fatal(err)
	}
	receiver, err := node.NewSelectedDirectReceiver(ctx, owner, fence)
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := network.New(nil)
	if !registerSelectedOwnerHTTP(ownerRouter, ownerPublic.settings, resolver, owner, ownerPublic.media, receiver) {
		t.Fatal("register rejected")
	}
	if !RegisterSelectedRelayOwnerHTTP(ownerRouter, ownerPublic.settings, resolver, owner, ownerPublic.media, receiver) {
		t.Fatal("relay register rejected")
	}
	RegisterOpaqueNodeMedia(ownerRouter, ownerPublic.settings, resolver, owner, ownerPublic.media)
	server := httptest.NewTLSServer(ownerRouter)
	defer server.Close()
	client := server.Client()
	count := 0
	transport.controlHook = func(route string, _ http.Header, _ []byte) {
		if route == "/internal/v1/selected-admin-origin" {
			count++
		}
	}
	call := func(method, path, origin, token string, body []byte) *http.Response {
		t.Helper()
		r, e := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Origin", origin)
		if method == "OPTIONS" {
			r.Header.Set("Access-Control-Request-Method", "PUT")
			r.Header.Set("Access-Control-Request-Headers", "content-type, x-fc-selected-upload")
		}
		if token != "" {
			r.Header.Set("X-Fc-Selected-Upload", token)
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		return resp
	}
	base := "/api/v1/node/selected-upload"
	bad := call("PUT", base, "https://master.test", "bad", []byte("x"))
	bad.Body.Close()
	if bad.StatusCode != 503 || count != 0 {
		t.Fatal("invalid capability caused Master request", bad.StatusCode, count)
	}
	pre := call("OPTIONS", base, "https://master.test", "", nil)
	pre.Body.Close()
	if pre.StatusCode != 204 || pre.Header.Get("Access-Control-Allow-Origin") != "https://master.test" || count != 1 {
		t.Fatal("preflight", pre.StatusCode, count)
	}
	data := []byte("opaque encrypted bytes")
	hash := sha256.Sum256(data)
	now := time.Now().Unix()
	binding, err := protocol.SelectedStorageAdminBinding(credential, rid, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	claim := protocol.SelectedStorageUpload{Relationship: rid, Master: masterID.ID, Owner: ownerID.ID, MediaID: strings.Repeat("1", 64), ObjectID: strings.Repeat("2", 64), UploadID: strings.Repeat("3", 32), OperationID: strings.Repeat("4", 64), ContentSHA256: hex.EncodeToString(hash[:]), RelationshipBinding: strings.Repeat("9", 64), Generation: strings.Repeat("a", 64), StageID: strings.Repeat("b", 64), PublishChallenge: strings.Repeat("c", 64), CleanupChallenge: strings.Repeat("d", 64), Size: int64(len(data)), Policy: "Direct", Revision: 7, ResourceOrigin: "https://follower.test", AdminOrigin: "https://master.test", AdminBinding: binding, ExpiresAt: now + 60}
	plainToken, err := protocol.SignSelectedStorageUpload(credential, claim, now)
	if err != nil {
		t.Fatal(err)
	}
	plain := call("PUT", base, "https://master.test", plainToken, data)
	plain.Body.Close()
	if plain.StatusCode != 503 || count != 1 {
		t.Fatal("unencrypted ticket accepted or reached Master", plain.StatusCode, count)
	}
	meta, err := mediacrypto.NewMetadata(int64(len(data) - 16))
	if err != nil {
		t.Fatal(err)
	}
	claim.Encryption = &meta
	token, err := protocol.SignSelectedStorageUpload(credential, claim, now)
	if err != nil {
		t.Fatal(err)
	}
	response := call("PUT", base, "https://master.test", token, data)
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
		Signature string                         `json:"signature"`
	}
	if response.StatusCode != 200 || response.Header.Get("Access-Control-Allow-Origin") != "https://master.test" || count != 2 || json.Unmarshal(raw, &result) != nil {
		t.Fatalf("upload status=%d controls=%d body=%s", response.StatusCode, count, raw)
	}
	payload, err := result.Receipt.Payload()
	if err != nil || protocol.Verify(relation.PublicKey, payload, result.Signature) != nil {
		t.Fatal("owner receipt invalid", err)
	}
	readSelected := func(v protocol.SelectedStorageUpload, origin string) *http.Response {
		t.Helper()
		now := time.Now().Unix()
		readToken, e := protocol.OpaqueIngressMediaToken(credential, rid, masterID.ID, ownerID.ID, v.MediaID, masterID.ID, "https://master.test", strings.Repeat("a", 32), v.ObjectID, 1, now, now+60, v.Size, v.ContentSHA256, v.Encryption)
		if e != nil {
			t.Fatal(e)
		}
		r, e := http.NewRequest("GET", server.URL+"/internal/v1/opaque-media/"+v.MediaID, nil)
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("X-Media-Capability", readToken)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		return resp
	}
	read := readSelected(claim, "https://master.test")
	readData, e := io.ReadAll(read.Body)
	read.Body.Close()
	if e != nil || read.StatusCode != http.StatusOK || !bytes.Equal(readData, data) {
		t.Fatalf("Direct uploaded ciphertext unreadable: status=%d err=%v", read.StatusCode, e)
	}
	// Discarding the upload response is ambiguous; a fresh authorized request
	// recovers the same signed receipt from the durable Owner intent.
	recovered := call("POST", base+"/recover", "https://master.test", token, nil)
	recoveredRaw, e := io.ReadAll(recovered.Body)
	recovered.Body.Close()
	var retry struct {
		Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
		Signature string                         `json:"signature"`
	}
	if e != nil || recovered.StatusCode != 200 || json.Unmarshal(recoveredRaw, &retry) != nil || retry.Receipt != result.Receipt || retry.Signature != result.Signature || count != 3 {
		t.Fatalf("recovery status=%d calls=%d err=%v", recovered.StatusCode, count, e)
	}
	// This synthetic cleanup ticket tests the Owner endpoint only; production
	// Master must first durably fence cancellation in its own transaction.
	cleanupToken, e := protocol.SignSelectedStorageCleanup(credential, claim, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	cleanup := call("POST", base+"/cleanup", "https://master.test", cleanupToken, nil)
	cleanupRaw, e := io.ReadAll(cleanup.Body)
	cleanup.Body.Close()
	var cleaned struct {
		Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
		Signature string                         `json:"signature"`
	}
	if e != nil || cleanup.StatusCode != 200 || json.Unmarshal(cleanupRaw, &cleaned) != nil || cleaned.Receipt.State != "cleaned" || count != 4 {
		t.Fatalf("cleanup status=%d calls=%d err=%v", cleanup.StatusCode, count, e)
	}
	cleanPayload, e := cleaned.Receipt.Payload()
	if e != nil || protocol.Verify(relation.PublicKey, cleanPayload, cleaned.Signature) != nil {
		t.Fatal("cleanup signature", e)
	}
	directAfterCleanup := readSelected(claim, "https://master.test")
	directAfterCleanup.Body.Close()
	if directAfterCleanup.StatusCode == http.StatusOK {
		t.Fatal("cancelled Direct object remained readable")
	}
	stale := call("PUT", base, "https://master.test", token, data)
	stale.Body.Close()
	if stale.StatusCode != 503 {
		t.Fatal("cancelled operation accepted old upload ticket", stale.StatusCode)
	}
	wrong := call("OPTIONS", base, "https://ingress.test", "", nil)
	wrong.Body.Close()
	if wrong.StatusCode != 403 || wrong.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("public ingress origin accepted", wrong.StatusCode)
	}
	if err := repo.AcceptNativeTransportApplication(ctx, rid, 8, "Relay"); err != nil {
		t.Fatal(err)
	}
	claim.Policy, claim.ResourceOrigin, claim.Revision = "Relay", "", 8
	claim.OperationID = strings.Repeat("e", 64)
	claim.ObjectID = strings.Repeat("f", 64)
	// Each upload receives a fresh random read alias; the Direct alias was
	// permanently tombstoned by its preceding cancellation.
	claim.MediaID = strings.Repeat("8", 64)
	relayToken, err := protocol.SignSelectedStorageUpload(credential, claim, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	relayPath := "/internal/v1/selected-upload/relay"
	headers, err := protocol.AuthHeaders(credential, rid, "PUT", relayPath, []byte(relayToken), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	relayCall := func(path, tok string, payload []byte, origin string, auth map[string]string) *http.Response {
		t.Helper()
		r, e := http.NewRequest("PUT", server.URL+path, bytes.NewReader(payload))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("X-Fc-Selected-Upload", tok)
		for k, v := range auth {
			r.Header.Set(k, v)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		return response
	}
	for _, bad := range []*http.Response{
		relayCall(relayPath, relayToken, data, "https://master.test", headers),
		relayCall(relayPath+"?x=1", relayToken, data, "", headers),
		relayCall(relayPath, token, data, "", headers),
	} {
		bad.Body.Close()
		if bad.StatusCode == http.StatusOK || bad.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("invalid relay accepted", bad.StatusCode)
		}
	}
	relay := relayCall(relayPath, relayToken, data, "", headers)
	relayRaw, e := io.ReadAll(relay.Body)
	relay.Body.Close()
	var relayResult struct {
		Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
		Signature string                         `json:"signature"`
	}
	if e != nil || relay.StatusCode != http.StatusOK || relay.Header.Get("Access-Control-Allow-Origin") != "" || json.Unmarshal(relayRaw, &relayResult) != nil {
		t.Fatalf("relay status=%d err=%v body=%s", relay.StatusCode, e, relayRaw)
	}
	if payload, e := relayResult.Receipt.Payload(); e != nil || protocol.Verify(relation.PublicKey, payload, relayResult.Signature) != nil {
		t.Fatal("relay receipt invalid", e)
	}
	relayRead := readSelected(claim, "")
	relayReadData, e := io.ReadAll(relayRead.Body)
	relayRead.Body.Close()
	if e != nil || relayRead.StatusCode != http.StatusOK || !bytes.Equal(relayReadData, data) {
		t.Fatalf("Relay uploaded ciphertext unreadable: status=%d err=%v", relayRead.StatusCode, e)
	}
	replayed := relayCall(relayPath, relayToken, data, "", headers)
	replayed.Body.Close()
	if replayed.StatusCode == http.StatusOK {
		t.Fatal("relay nonce replay accepted")
	}
	directAuth, err := protocol.AuthHeaders(credential, rid, "PUT", relayPath, []byte(token), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	directRelay := relayCall(relayPath, token, data, "", directAuth)
	directRelay.Body.Close()
	if directRelay.StatusCode == http.StatusOK {
		t.Fatal("Direct capability accepted on Relay")
	}
	corruptClaim := claim
	corruptClaim.OperationID = strings.Repeat("6", 64)
	corruptClaim.ObjectID = strings.Repeat("7", 64)
	corruptToken, err := protocol.SignSelectedStorageUpload(credential, corruptClaim, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	corruptAuth, err := protocol.AuthHeaders(credential, rid, "PUT", relayPath, []byte(corruptToken), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), data...)
	corrupt[0] ^= 1
	badBytes := relayCall(relayPath, corruptToken, corrupt, "", corruptAuth)
	badBytes.Body.Close()
	if badBytes.StatusCode == http.StatusOK {
		t.Fatal("corrupted stream accepted")
	}
	control := func(path, tok string) *http.Response {
		t.Helper()
		auth, e := protocol.AuthHeaders(credential, rid, "POST", path, []byte(tok), time.Now().Unix())
		if e != nil {
			t.Fatal(e)
		}
		r, e := http.NewRequest("POST", server.URL+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("X-Fc-Selected-Upload", tok)
		for k, v := range auth {
			r.Header.Set(k, v)
		}
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		return response
	}
	recovery := control(relayPath+"/recover", relayToken)
	recoveryRaw, e := io.ReadAll(recovery.Body)
	recovery.Body.Close()
	var relayRetry struct {
		Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
		Signature string                         `json:"signature"`
	}
	if e != nil || recovery.StatusCode != http.StatusOK || json.Unmarshal(recoveryRaw, &relayRetry) != nil || relayRetry != relayResult {
		t.Fatalf("relay recovery status=%d err=%v", recovery.StatusCode, e)
	}
	wrongCleanup := control(relayPath+"/cleanup", relayToken)
	wrongCleanup.Body.Close()
	if wrongCleanup.StatusCode == http.StatusOK {
		t.Fatal("upload ticket accepted for cleanup")
	}
	relayCleanupToken, err := protocol.SignSelectedStorageCleanup(credential, claim, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	relayCleanup := control(relayPath+"/cleanup", relayCleanupToken)
	cleanupBytes, e := io.ReadAll(relayCleanup.Body)
	relayCleanup.Body.Close()
	var relayClean struct {
		Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
		Signature string                         `json:"signature"`
	}
	if e != nil || relayCleanup.StatusCode != http.StatusOK || json.Unmarshal(cleanupBytes, &relayClean) != nil || relayClean.Receipt.State != "cleaned" {
		t.Fatalf("relay cleanup status=%d err=%v", relayCleanup.StatusCode, e)
	}
	if payload, e := relayClean.Receipt.Payload(); e != nil || protocol.Verify(relation.PublicKey, payload, relayClean.Signature) != nil {
		t.Fatal("relay cleanup receipt invalid", e)
	}
	afterCleanup := readSelected(claim, "")
	afterCleanup.Body.Close()
	if afterCleanup.StatusCode == http.StatusOK {
		t.Fatal("cancelled Relay object remained readable")
	}
	beforeUpload := claim
	beforeUpload.MediaID, beforeUpload.ObjectID, beforeUpload.OperationID = strings.Repeat("5", 64), strings.Repeat("6", 64), strings.Repeat("7", 64)
	beforeCleanup, err := protocol.SignSelectedStorageCleanup(credential, beforeUpload, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	preCancelled := control(relayPath+"/cleanup", beforeCleanup)
	preCancelled.Body.Close()
	if preCancelled.StatusCode != http.StatusOK {
		t.Fatal("cancel before upload failed", preCancelled.StatusCode)
	}
	beforeToken, err := protocol.SignSelectedStorageUpload(credential, beforeUpload, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	beforeAuth, err := protocol.AuthHeaders(credential, rid, "PUT", relayPath, []byte(beforeToken), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	lateUpload := relayCall(relayPath, beforeToken, data, "", beforeAuth)
	lateUpload.Body.Close()
	if lateUpload.StatusCode == http.StatusOK {
		t.Fatal("pre-cancelled upload was accepted")
	}
	delete(transport.routers, "https://master.test")
	offline := call("OPTIONS", base, "https://master.test", "", nil)
	offline.Body.Close()
	if offline.StatusCode != 403 {
		t.Fatal("offline Master returned cached proof", offline.StatusCode)
	}
}

func TestSelectedMasterOriginProofGateDoesNotLimitHeartbeat(t *testing.T) {
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, _, _, _, _ := clusterFixture(t, "https://master.test", transport, false)
	for i := 0; i < 8; i++ {
		got := request(router, "POST", "https://master.test/internal/v1/selected-admin-origin", `{"challenge":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
		if got.Code != http.StatusUnauthorized {
			t.Fatalf("proof request %d status %d", i, got.Code)
		}
	}
	limited := request(router, "POST", "https://master.test/internal/v1/selected-admin-origin", `{"challenge":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("proof rate not bounded: %d", limited.Code)
	}
	heartbeat := request(router, "POST", "https://master.test/internal/v1/heartbeat", `{}`)
	if heartbeat.Code != http.StatusUnauthorized {
		t.Fatalf("proof gate affected heartbeat: %d", heartbeat.Code)
	}
}
