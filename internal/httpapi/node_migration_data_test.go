package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestAuthenticatedBytesRelayThroughMasterToPrivateTargetStage(t *testing.T) {
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
	for offset := 0; offset < len(payload); offset += migrationdata.ChunkBytes {
		request.Offset = int64(offset)
		request.Length = min(migrationdata.ChunkBytes, len(payload)-offset)
		response, e := call(srel, prefix+"read", request)
		if e != nil {
			t.Fatal(e)
		}
		encoded, _ := response["data"].(string)
		data, e := base64.StdEncoding.DecodeString(encoded)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(data, payload[offset:offset+request.Length]) {
			t.Fatal("source returned wrong actual bytes")
		}
		request.Data = data
		request.SHA, _ = response["chunk_sha256"].(string)
		if _, e = call(trel, prefix+"append", request); e != nil {
			t.Fatal(e)
		}
		if offset == 0 {
			if _, e = call(trel, prefix+"append", request); e != nil {
				t.Fatal("duplicate relay", e)
			}
		}
		request.Data = nil
		request.SHA = ""
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
func migrationUnsignedStatus(router *gin.Engine, path string) int {
	return request(router, "POST", "https://target.test"+path, `{}`).Code
}
