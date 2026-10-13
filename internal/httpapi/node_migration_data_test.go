package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestAuthenticatedDirectPeerBytesWithoutMasterRelay(t *testing.T) {
	authenticatedDirectBytes(t, false)
}
func TestAuthenticatedCancellationRefundsStagingUnitAfterLostReceipt(t *testing.T) {
	authenticatedDirectBytes(t, true)
}
func authenticatedDirectBytes(t *testing.T, cancelUnit bool) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, mdb, _, _, master := clusterFixture(t, "https://master.test", transport, true)
	_, _, _, _, source := clusterFixture(t, "https://source.test", transport, true)
	trouter, tdb, tdir, _, target := clusterFixture(t, "https://target.test", transport, true)
	for _, entry := range []struct {
		s          *node.Service
		role, url  string
		allocation int64
	}{{master, "Master", "https://master.test", 5 * store.GiB}, {source, "Follower", "https://source.test", 0}, {target, "Follower", "https://target.test", 0}} {
		if _, e := entry.s.Promote(ctx, entry.role, entry.url, entry.allocation, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	pair, e := source.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	srid, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	pair, e = target.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	trid, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{srid, trid} {
		rel, e := mdb.Nodes().Relationship(ctx, id)
		if e != nil {
			t.Fatal(e)
		}
		cfg := store.ResourceConfiguration{}
		cfg.Storage.Enabled = true
		cfg.Storage.Allocation = 5 * store.GiB
		if e = mdb.Pool().ConfigureMember(ctx, rel.PeerID, cfg, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if id == srid {
			if e = mdb.Nodes().SetRelationshipMode(ctx, id, "Direct", false, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
		}
		rel, _ = mdb.Nodes().Relationship(ctx, id)
		if e = master.Tick(ctx, rel); e != nil {
			t.Fatal(e)
		}
	}
	srel, e := mdb.Nodes().Relationship(ctx, srid)
	if e != nil {
		t.Fatal(e)
	}
	trel, e := mdb.Nodes().Relationship(ctx, trid)
	if e != nil {
		t.Fatal(e)
	}
	payload := bytes.Repeat([]byte{0x51}, 2*migrationdata.ChunkBytes+19)
	copy(payload, []byte("ID3"))
	name := "music/ActualMigration/track.mp3"
	u, e := mdb.Pool().ReserveUpload(ctx, name, "direct", int64(len(payload)), 10*store.GiB, store.AdminAudit{})
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := master.UploadStorage(ctx, u, bytes.NewReader(payload))
	if e != nil {
		t.Fatal(e)
	}
	object, _ := receipt["object_id"].(string)
	etag, _ := receipt["etag"].(string)
	if _, e = mdb.Pool().FinalizeUpload(ctx, u.ID, object, u.ExpectedBytes, etag, store.AdminAudit{}); e != nil {
		t.Fatal(e)
	}
	mid, e := mdb.Nodes().ReadIdentity(ctx)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	task := strings.Repeat("d", 32)
	h := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: task, MasterID: mid.ID, SourceID: srel.PeerID, TargetID: trel.PeerID, SourceRelationship: srid, TargetRelationship: trid, PlanSHA: strings.Repeat("1", 64), ObjectCount: 1, Bytes: int64(len(payload))}
	l := store.MigrationLease{TaskID: task, RunnerID: strings.Repeat("e", 32), Epoch: 1, ExpiresAt: time.Now().Unix() + 60}
	o := store.MigrationObject{ID: u.MediaID, ObjectID: object, Path: name, TargetPath: name, Parent: "music/ActualMigration", Kind: "audio", Resource: "media", Bytes: u.ExpectedBytes, Version: strings.Repeat("2", 64), ETag: etag}
	v := store.MigrationPeerObject{Object: o, Proof: store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: digest}}
	call := func(rel store.Relationship, route string, value any) (map[string]any, error) {
		raw, e := json.Marshal(value)
		if e != nil {
			return nil, e
		}
		var body map[string]any
		if e = controlJSON(raw, &body); e != nil {
			return nil, e
		}
		return master.Call(ctx, rel, route, body)
	}
	for _, rel := range []store.Relationship{srel, trel} {
		if _, e = call(rel, "/internal/v1/resource-migration/register", map[string]any{"header": h, "lease": l, "state": "queued"}); e != nil {
			t.Fatal(e)
		}
		if _, e = call(rel, "/internal/v1/resource-migration/object", map[string]any{"lease": l, "object": v}); e != nil {
			t.Fatal(e)
		}
	}
	spec := migrationdata.Spec{TaskID: task, MasterID: mid.ID, SourceID: srel.PeerID, TargetID: trel.PeerID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: "media", TargetPath: name, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: digest}
	request := migrationDataRequest{Lease: l, Spec: spec}
	prefix := "/internal/v1/resource-migration/data/"
	wrong := request
	wrong.Spec.SourceVersion = strings.Repeat("4", 64)
	if _, e = call(trel, prefix+"begin", wrong); !errors.Is(e, node.ErrRemoteConflict) {
		t.Fatal("wrong source version accepted", e)
	}
	wrong = request
	wrong.Length = migrationdata.ChunkBytes + 1
	if _, e = call(srel, prefix+"read", wrong); !errors.Is(e, node.ErrRemoteConflict) {
		t.Fatal("oversized read accepted", e)
	}
	if w := migrationUnsignedStatus(trouter, prefix+"begin"); w != 401 {
		t.Fatal("unsigned bytes command", w)
	}
	if _, e = call(trel, prefix+"begin", request); e != nil {
		t.Fatal(e)
	}
	request.TargetPublicKey = trel.PublicKey
	grantReply, e := call(srel, prefix+"delegate", request)
	if e != nil {
		t.Fatal(e)
	}
	var directGrant migrationdata.Signed
	if e = migrationDecodePeer(grantReply, &directGrant); e != nil {
		t.Fatal(e)
	}
	request.TargetPublicKey = ""
	request.SourcePublicKey = srel.PublicKey
	request.SourceEndpoint = srel.Endpoint
	request.TransferGrant = &directGrant
	// These checks occur before any bytes are received. A valid source grant
	// cannot be redirected to Master, another key, another object or offset.
	request.Offset = 0
	request.Length = migrationdata.ChunkBytes
	for _, change := range []func(*migrationDataRequest){
		func(v *migrationDataRequest) { v.SourceEndpoint = "https://master.test" },
		func(v *migrationDataRequest) { v.SourceEndpoint = "http://source.test" },
		func(v *migrationDataRequest) { v.SourcePublicKey = trel.PublicKey },
		func(v *migrationDataRequest) { v.Offset = 1 },
		func(v *migrationDataRequest) { v.Length = migrationdata.ChunkBytes + 1 },
		func(v *migrationDataRequest) { v.Spec.SourceVersion = strings.Repeat("5", 64) },
		func(v *migrationDataRequest) { v.TransferGrant = nil },
	} {
		bad := request
		change(&bad)
		if _, e = call(trel, prefix+"pull", bad); e == nil {
			t.Fatal("unbound direct transfer was accepted")
		}
	}
	// An unreachable source cannot trigger a relay fallback, advance a target
	// checkpoint, or alter the authoritative source owner.
	sourceRouter := transport.routers[srel.Endpoint]
	delete(transport.routers, srel.Endpoint)
	_, directError := call(trel, prefix+"pull", request)
	transport.routers[srel.Endpoint] = sourceRouter
	if !errors.Is(directError, node.ErrRemoteConflict) {
		t.Fatal("direct connectivity failure not rejected", directError)
	}
	statusReply, e := call(trel, prefix+"status", request)
	if e != nil {
		t.Fatal(e)
	}
	var initial struct {
		Checkpoint migrationdata.Checkpoint `json:"checkpoint"`
	}
	if migrationDecodePeer(statusReply, &initial) != nil || initial.Checkpoint.Offset != 0 {
		t.Fatal("offline source advanced the checkpoint")
	}
	owner, e := mdb.Pool().Resource(ctx, o.ID)
	if e != nil || owner.MemberID != srel.PeerID {
		t.Fatal("offline transfer changed source authority", e)
	}
	// Count an actual external response while source control/data routes stay
	// responsive. A peak stops the next chunk without failing or advancing it.
	clock := time.Now().Add(-businesstraffic.LowInterval)
	load := businesstraffic.New(func() time.Time { return clock })
	clock = time.Now()
	source.ConfigureBusinessTraffic(load)
	sourceRouter.Use(BusinessTrafficMiddleware(load))
	sourceRouter.GET("/load-fixture", func(c *gin.Context) {
		c.Writer.Write(bytes.Repeat([]byte("x"), int(businesstraffic.HighBytesPerSecond)))
	})
	loadReply := requestFixtureTraffic(sourceRouter)
	if loadReply != 200 || load.Snapshot().CanRun {
		t.Fatal("business byte peak not observed")
	}
	waitingReply, e := call(trel, prefix+"pull", request)
	if e != nil || waitingReply["waiting_traffic"] != true || waitingReply["waiting_node_id"] != srel.PeerID {
		t.Fatal("source peak failed instead of waiting", waitingReply, e)
	}
	var waiting struct {
		Checkpoint migrationdata.Checkpoint `json:"checkpoint"`
	}
	if migrationDecodePeer(waitingReply, &waiting) != nil || waiting.Checkpoint.Offset != 0 {
		t.Fatal("peak advanced migration bytes")
	}
	clock = clock.Add(businesstraffic.Window)
	load.Snapshot()
	clock = clock.Add(businesstraffic.LowInterval - time.Second)
	if load.Snapshot().CanRun {
		t.Fatal("resumed without sustained low traffic")
	}
	clock = clock.Add(time.Second)
	if !load.Snapshot().CanRun {
		t.Fatal("did not reopen after sustained low traffic")
	}
	var peerRequest any
	peerReads := 0
	transport.peerReadHook = func(origin string, value any) {
		if origin != srel.Endpoint {
			t.Fatal("migration bytes requested from a different node")
		}
		peerReads++
		peerRequest = value
	}
	for offset := 0; offset < len(payload); offset += migrationdata.ChunkBytes {
		request.Offset = int64(offset)
		request.Length = min(migrationdata.ChunkBytes, len(payload)-offset)
		if _, e = call(srel, prefix+"read", request); !errors.Is(e, node.ErrRemoteConflict) {
			t.Fatal("Master read relay was enabled", e)
		}
		if _, e = call(trel, prefix+"append", request); !errors.Is(e, node.ErrRemoteConflict) {
			t.Fatal("Master append relay was enabled", e)
		}
		response, err := call(trel, prefix+"pull", request)
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := response["data"]; exists {
			t.Fatal("Master received migration bytes")
		}
		var checkpoint migrationdata.Checkpoint
		if e = migrationDecodePeer(response, &checkpoint); e != nil || checkpoint.Offset != request.Offset+int64(request.Length) {
			t.Fatal(checkpoint, e)
		}
		if offset == 0 {
			reads := peerReads
			if _, e = call(trel, prefix+"pull", request); e != nil {
				t.Fatal("duplicate direct checkpoint", e)
			}
			if peerReads != reads {
				t.Fatal("duplicate control copied the same chunk again")
			}
			transport.peerReadHook = nil
			if _, e = transport.Request(ctx, srel.Endpoint, migrationdata.PeerReadRoute, "POST", peerRequest, "", ""); e == nil {
				t.Fatal("replayed target identity nonce accepted")
			}
			var signed migrationdata.Signed
			if e = migrationDecodePeer(peerRequest, &signed); e != nil {
				t.Fatal(e)
			}
			signed.Payload["offset"] = json.Number("262144")
			if _, e = transport.Request(ctx, srel.Endpoint, migrationdata.PeerReadRoute, "POST", map[string]any{"payload": signed.Payload, "signature": signed.Signature}, "", ""); e == nil {
				t.Fatal("tampered target range accepted")
			}
			// The grant is public routing authorization, not a bearer read token.
			if _, e = transport.Request(ctx, srel.Endpoint, migrationdata.PeerReadRoute, "POST", map[string]any{"payload": directGrant.Payload, "signature": directGrant.Signature}, "", ""); e == nil {
				t.Fatal("source grant alone returned bytes")
			}
			transport.peerReadHook = func(origin string, value any) { peerReads++; peerRequest = value }
		}
	}
	transport.peerReadHook = nil
	if peerReads != (len(payload)+migrationdata.ChunkBytes-1)/migrationdata.ChunkBytes {
		t.Fatal("unexpected actual peer reads", peerReads)
	}
	if protocol.Verify(srel.PublicKey, directGrant.Payload, directGrant.Signature) != nil {
		t.Fatal("source grant identity proof changed")
	}
	if _, e = call(trel, prefix+"verify", request); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	verified := false
	for time.Now().Before(deadline) {
		status, e := call(trel, prefix+"status", request)
		if e != nil {
			t.Fatal(e)
		}
		if status["peer_state"] == "verified" {
			verified = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !verified {
		t.Fatal("disk verification not durably registered")
	}
	if _, e = tdb.Media().ObjectByID(ctx, o.ID); e != nil {
		t.Fatal(e)
	}
	if found, _ := tdb.Media().ObjectByID(ctx, o.ID); found != nil {
		t.Fatal("staging became ordinary object")
	}
	if _, e = mdb.Pool().Resource(ctx, o.ID); e != nil {
		t.Fatal(e)
	}
	g, _ := mdb.Pool().Resource(ctx, o.ID)
	if g.MemberID != srel.PeerID {
		t.Fatal("byte receipt switched authority")
	}
	if cancelUnit {
		l.Epoch++
		request.Lease = l
		for _, rel := range []store.Relationship{srel, trel} {
			if _, e = call(rel, "/internal/v1/resource-migration/register", map[string]any{"header": h, "lease": l, "state": "cancelling"}); e != nil {
				t.Fatal(e)
			}
		}
		var unit string
		if e = tdb.Database().QueryRow("SELECT unit_id FROM migration_storage_journal WHERE task_id=?", task).Scan(&unit); e != nil {
			t.Fatal(e)
		}
		objectsSHA, e := store.MigrationUnitObjectsSHA([]store.MigrationPeerObject{v})
		if e != nil {
			t.Fatal(e)
		}
		grant := store.MigrationUnitFinishGrant{Header: h, Unit: store.MigrationUnit{ID: unit, Resource: o.Resource, Parent: o.Parent, State: "cancelled", ObjectCount: 1, Bytes: o.Bytes}, UnitVersion: strings.Repeat("1", 64), ObjectsSHA: objectsSHA}
		body := map[string]any{"lease": l, "grant": grant}
		if _, e = call(trel, "/internal/v1/resource-migration/cancel-unit", body); !errors.Is(e, node.ErrRemoteConflict) {
			t.Fatal("uncleaned staging unit refunded", e)
		}
		for range 2 {
			if _, e = call(trel, prefix+"abort", request); e != nil {
				t.Fatal("abort replay", e)
			}
		}
		for range 2 {
			for _, rel := range []store.Relationship{srel, trel} {
				response, e := call(rel, "/internal/v1/resource-migration/cancel-unit", body)
				if e != nil || response["complete"] != true {
					t.Fatal("lost receipt replay", response, e)
				}
			}
		}
		var used, reserved int64
		if e = tdb.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", trel.PeerID).Scan(&used, &reserved); e != nil || used != 0 || reserved != 0 {
			t.Fatal(used, reserved, e)
		}
		g, e = mdb.Pool().Resource(ctx, o.ID)
		if e != nil || g.MemberID != srel.PeerID {
			t.Fatal("Master source authority changed", g, e)
		}
		if _, e = call(trel, prefix+"begin", request); !errors.Is(e, node.ErrRemoteConflict) {
			t.Fatal("cancelled stage reopened", e)
		}
		unitsSHA, e := store.MigrationTaskUnitsSHA([]store.MigrationUnitFinishGrant{grant})
		if e != nil {
			t.Fatal(e)
		}
		finish := store.MigrationTaskFinishGrant{Outcome: "cancelled", Header: h, UnitCount: 1, UnitsSHA: unitsSHA}
		for _, rel := range []store.Relationship{srel, trel} {
			if _, e = call(rel, "/internal/v1/resource-migration/cancel-task", map[string]any{"lease": l, "grant": finish}); e != nil {
				t.Fatal(e)
			}
		}
		assertRetainedMigrationInventory(t, master, trel, tdir, request.Spec)
		t.Logf("cancelled actual staged bytes=%d; both authenticated receipts replayed; source authority retained; target used/reserved=0", len(payload))
		return
	}
	// Publishing is separately admitted and retried. It adopts the same logical
	// physical ID while Master still owns the source until whole-unit cutover.
	for range 2 {
		if _, e = call(trel, prefix+"publish", request); e != nil {
			t.Fatal(e)
		}
		deadline = time.Now().Add(5 * time.Second)
		published := false
		for time.Now().Before(deadline) {
			status, e := call(trel, prefix+"status", request)
			if e != nil {
				t.Fatal(e)
			}
			if status["peer_state"] == "published" {
				published = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !published {
			t.Fatal("publication not durably registered")
		}
	}
	read, e := master.ReadGlobalMedia(ctx, store.GlobalMedia{ID: o.ID, Path: name, Kind: "audio", MemberID: trel.PeerID, ObjectID: object, Bytes: o.Bytes, RelationshipID: &trid})
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(read)
	read.Close()
	if e != nil || !bytes.Equal(got, payload) {
		t.Fatal("published business read mismatch", e)
	}
	if _, e = call(trel, "/internal/v1/resource-migration/fence", map[string]any{"task_id": task, "epoch": l.Epoch, "state": "paused"}); e != nil {
		t.Fatal(e)
	}
	if _, e = call(trel, prefix+"begin", request); !errors.Is(e, node.ErrRemoteConflict) {
		t.Fatal("paused bytes command authorized", e)
	}
	var used, reserved int64
	tdb.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", trel.PeerID).Scan(&used, &reserved)
	if used != o.Bytes || reserved != 0 {
		t.Fatal("publication quota replay mismatch", used, reserved)
	}
	info, e := os.Stat(filepath.Join(tdir, "media", name))
	if e != nil {
		t.Fatal("published media path absent", e)
	}
	if info.Mode().Perm()&0044 != 0044 {
		t.Fatal("Direct readers cannot read published media", info.Mode())
	}
}

func requestFixtureTraffic(router *gin.Engine) int {
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "https://source.test/load-fixture", nil))
	return w.Code
}
func migrationUnsignedStatus(router *gin.Engine, path string) int {
	return request(router, "POST", "https://target.test"+path, `{}`).Code
}
