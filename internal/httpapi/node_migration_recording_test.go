package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedRecordingRelayPublicationPreservesBytesIdentityAndMasterQuota(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plain"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) { authenticatedRecordingPublication(t, encrypted) })
	}
}
func TestAuthenticatedRecordingCleanupPreservesTargetFooterAndPersonalQuota(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plain"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) { authenticatedRecordingPublication(t, encrypted, true) })
	}
}

func TestAuthenticatedRecordingPublishedShadowCancellation(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) { authenticatedRecordingPublication(t, encrypted, true, true) })
	}
}

func TestAuthenticatedRecordingInterruptedPublicationCancellation(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) { authenticatedRecordingPublication(t, encrypted, true, true, true) })
	}
}
func TestAuthenticatedRecordingAccountedPublicationCheckpointRecovery(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) { authenticatedRecordingPublication(t, encrypted, true, true, false, true) })
	}
}
func TestAuthenticatedRecordingNewReverseTaskPreservesCiphertextAndQuota(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) { authenticatedRecordingPublication(t, encrypted, true, false, false, false, true) })
	}
}
func TestAuthenticatedRecordingAnchorWorkerLossRequiresExplicitRetry(t *testing.T) {
	authenticatedRecordingPublication(t, true, true, false, false, false, false, true)
}
func authenticatedRecordingPublication(t *testing.T, encrypted bool, cleanup ...bool) {
	ctx := context.Background()
	unpublish := len(cleanup) > 2 && cleanup[2]
	checkpoint := len(cleanup) > 3 && cleanup[3]
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, mdb, _, _, master := clusterFixture(t, "https://master.test", transport, true, true)
	_, sdb, sourceDir, _, source := clusterFixture(t, "https://source.test", transport, true, true)
	targetRouter, tdb, targetDir, _, target := clusterFixture(t, "https://target.test", transport, true, true)
	for _, v := range []struct {
		s         *node.Service
		role, url string
	}{{master, "Master", "https://master.test"}, {source, "Follower", "https://source.test"}, {target, "Follower", "https://target.test"}} {
		allocation := int64(0)
		if v.role == "Master" {
			allocation = store.GiB
		}
		if _, e := v.s.Promote(ctx, v.role, v.url, allocation, store.NodeAudit{}); e != nil {
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
	configure := func(id string) {
		t.Helper()
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
		rel, _ = mdb.Nodes().Relationship(ctx, id)
		if e = master.Tick(ctx, rel); e != nil {
			t.Fatal(e)
		}
	}
	configure(srid)
	user := store.KaraokeUser{ID: strings.Repeat("a", 32), Username: "migration-user", NameKey: "migration-user", PasswordHash: "fixture", Quota: 3 * store.GiB}
	if e = mdb.Karaoke().RegisterUser(ctx, user, "192.0.2.241", "20261012", store.KaraokeAudit{}); e != nil {
		t.Fatal(e)
	}
	snapshot := store.RecordingMetadata{Title: "原始录音", Lyrics: []store.RecordingLyric{{Time: 1.5, Text: "原始歌词"}}}
	plaintext := []byte("original encrypted lyric snapshot")
	var aead cipher.AEAD
	if encrypted {
		meta, e := mediacrypto.NewMetadata(int64(len(plaintext)))
		if e != nil {
			t.Fatal(e)
		}
		block, e := aes.NewCipher(bytes.Repeat([]byte{0x51}, 32))
		if e != nil {
			t.Fatal(e)
		}
		aead, e = cipher.NewGCM(block)
		if e != nil {
			t.Fatal(e)
		}
		nonce, _ := meta.ChunkNonce(0)
		snapshot.Lyrics = []store.RecordingLyric{}
		snapshot.EncryptedLyrics = &store.RecordingEncryptedLyrics{Encryption: meta, Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, meta.ChunkAAD(0)))}
	}
	metadata, e := json.Marshal(map[string]any{"version": 1, "title": snapshot.Title, "lyrics": snapshot.Lyrics, "encrypted_lyrics": snapshot.EncryptedLyrics})
	if e != nil {
		t.Fatal(e)
	}
	payload := bytes.Repeat([]byte{0x51}, migrationdata.ChunkBytes+31)
	payload = append(payload, metadata...)
	tail := make([]byte, 8)
	binary.BigEndian.PutUint64(tail, uint64(len(metadata)))
	payload = append(payload, tail...)
	payload = append(payload, recording.TrailerMagic...)
	id := strings.Repeat("b", 32)
	v, member, e := mdb.Recordings().ReserveRecording(ctx, store.Recording{ID: id, UserID: user.ID, Filename: "voice.webm", ContentType: "audio/webm", Bytes: int64(len(payload)), Title: snapshot.Title, Lyrics: snapshot.Lyrics, EncryptedLyrics: snapshot.EncryptedLyrics}, 10*store.GiB, store.KaraokeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	srel, _ := mdb.Nodes().Relationship(ctx, srid)
	if member.ID != srel.PeerID {
		t.Fatal("ordinary allocation did not choose enabled source")
	}
	reply, e := master.UploadRecording(ctx, v, member, bytes.NewReader(payload))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(reply)
	var receipt store.RecordingReceipt
	if e = json.Unmarshal(raw, &receipt); e != nil {
		t.Fatal(e)
	}
	if e = mdb.Recordings().FinalizeRecording(ctx, user.ID, id, receipt, store.KaraokeAudit{}); e != nil {
		t.Fatal(e)
	}
	configure(trid)
	trel, _ := mdb.Nodes().Relationship(ctx, trid)
	mid, _ := mdb.Nodes().ReadIdentity(ctx)
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	if len(cleanup) > 0 && cleanup[0] {
		for _, rid := range []string{srid, trid} {
			if e = mdb.Nodes().RecordHeartbeat(ctx, rid, true, 1, map[string]any{"capabilities": []string{"storage-v2", store.MigrationCapability}, "storage": map[string]any{"physical_free_bytes": 10 * store.GiB}}, time.Now().Unix()); e != nil {
				t.Fatal(e)
			}
		}
		repo := mdb.Pool().(store.MigrationRepository)
		catalog, e := repo.MigrationCatalog(ctx, srel.PeerID, trel.PeerID)
		if e != nil || len(catalog.Blockers) != 0 || len(catalog.Objects) != 1 {
			t.Fatal(catalog, e)
		}
		o := catalog.Objects[0]
		plan := store.MigrationPlan{ID: strings.Repeat("c", 32), Catalog: catalog, TargetAbsent: true, TargetFree: 10 * store.GiB, CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 120, Proofs: []store.MigrationDiskProof{{ID: id, Version: o.Version, Bytes: o.Bytes, SHA256: sha}}}
		if _, e = repo.StartMigration(ctx, plan, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		fault := &runnerFaultCaller{client: master, reads: map[int64]int{}}
		engine := &resourcemigration.Runner{Repository: repo, Nodes: mdb.Nodes(), Client: fault}
		if len(cleanup) > 1 && cleanup[1] {
			if _, e = mdb.Database().Exec("CREATE TRIGGER block_record_shadow_cutover BEFORE UPDATE ON migration_units WHEN NEW.state='cleanup_pending' BEGIN SELECT RAISE(ABORT,'cutover unavailable'); END"); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { mdb.Database().Exec("DROP TRIGGER IF EXISTS block_record_shadow_cutover") })
			if unpublish {
				if _, e = tdb.Database().Exec("CREATE TRIGGER fail_record_publication BEFORE INSERT ON node_audit WHEN NEW.action='peer-migration-recording-published' BEGIN SELECT RAISE(ABORT,'publication commit unavailable'); END"); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { tdb.Database().Exec("DROP TRIGGER IF EXISTS fail_record_publication") })
				fault.stopPublishing = func() bool { _, e := os.Stat(filepath.Join(targetDir, "recordings", o.TargetPath)); return e == nil }
			}
			if checkpoint {
				fault.losePublicationCheckpoint = func() { loseMigrationPublicationCheckpoint(t, filepath.Join(targetDir, "recordings")) }
			}
			if e = engine.Run(ctx, plan.ID, strings.Repeat("d", 32)); e == nil {
				t.Fatal("recording cutover failure ignored")
			}
			if _, e = repo.ControlMigration(ctx, plan.ID, "cancel", store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			fault.lostShadow = !unpublish
			fault.lostUnpublish = unpublish
			fault.lostCancelUnit = true
			fault.lostCancelTask = true
			for attempt := 0; attempt < 4; attempt++ {
				e = engine.Run(ctx, plan.ID, strings.Repeat([]string{"e", "f", "1", "2"}[attempt], 32))
				if attempt < 3 {
					if e == nil {
						t.Fatal("record shadow receipt loss ignored", attempt)
					}
					if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
						t.Fatal(e)
					}
				} else if e != nil {
					t.Fatal("record shadow recovery", e)
				}
			}
			work, e := repo.MigrationWork(ctx, plan.ID)
			if e != nil || work.Task.State != "cancelled" || work.Task.CommittedBytes != 0 || work.Objects[0].State != "cancelled" {
				t.Fatal(work, e)
			}
			row, e := mdb.Recordings().Recording(ctx, id)
			if e != nil || row.MemberID != srel.PeerID || row.State != "ready" {
				t.Fatal("record cancellation changed source owner", row, e)
			}
			token, e := master.RecordingCapability(ctx, *row, store.StorageMember{ID: srel.PeerID, RelationshipID: &srid}, "download")
			if e != nil {
				t.Fatal(e)
			}
			request := httptest.NewRequest("GET", "https://source.test/internal/v1/recordings/"+id, nil)
			request.Header.Set("X-Recording-Capability", token)
			response := httptest.NewRecorder()
			transport.routers["https://source.test"].ServeHTTP(response, request)
			if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), payload) {
				t.Fatal("source recording bytes after cancellation", response.Code)
			}
			footer := recording.Metadata(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
			if encrypted {
				cipherBytes, e := base64.StdEncoding.DecodeString(footer.EncryptedLyrics.Ciphertext)
				if e != nil {
					t.Fatal(e)
				}
				meta := footer.EncryptedLyrics.Encryption
				nonce, _ := meta.ChunkNonce(0)
				decoded, e := aead.Open(nil, nonce, cipherBytes, meta.ChunkAAD(0))
				if e != nil || !bytes.Equal(decoded, plaintext) {
					t.Fatal("client encrypted footer after cancel", e)
				}
			}
			if _, e = os.Stat(filepath.Join(targetDir, "recordings", o.TargetPath)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("target recording shadow remains", e)
			}
			var used, reserved, personal int64
			if e = tdb.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", trel.PeerID).Scan(&used, &reserved); e != nil || used != 0 || reserved != 0 {
				t.Fatal(used, reserved, e)
			}
			if e = mdb.Database().QueryRow("SELECT used_bytes FROM karaoke_users WHERE user_id=?", user.ID).Scan(&personal); e != nil || personal != o.Bytes {
				t.Fatal("personal recording quota changed", personal, e)
			}
			t.Logf("recording shadow cancellation bytes=%d encrypted=%v; source business read/client decryption and lost receipts recovered", o.Bytes, encrypted)
			return
		}
		if e = engine.Run(ctx, plan.ID, strings.Repeat("d", 32)); e != nil {
			t.Fatal(e)
		}
		if e = engine.Run(ctx, plan.ID, strings.Repeat("e", 32)); e != nil {
			t.Fatal(e)
		}
		if _, e = os.Stat(filepath.Join(sourceDir, "recordings", o.Path)); e != nil {
			t.Fatal("source removed during grace", e)
		}
		now := time.Now().Unix()
		if _, e = mdb.Database().Exec("UPDATE migration_units SET committed_at=?,cleanup_after=? WHERE task_id=?", now-3601, now-1, plan.ID); e != nil {
			t.Fatal(e)
		}
		reads := sdb.Nodes().(store.MigrationReadRepository)
		readID, e := reads.AcquireMigrationRead(ctx, srid, id, id, "recording")
		if e != nil {
			t.Fatal(e)
		}
		if e = engine.Run(ctx, plan.ID, strings.Repeat("f", 32)); e == nil {
			t.Fatal("active recording read crossed cleanup")
		}
		if e = reads.ReleaseMigrationRead(ctx, readID); e != nil {
			t.Fatal(e)
		}
		if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if _, e = sdb.Database().Exec("CREATE TRIGGER block_record_cleanup BEFORE INSERT ON node_audit WHEN NEW.action='recording-deleted' BEGIN SELECT RAISE(FAIL,'record cleanup audit unavailable'); END"); e != nil {
			t.Fatal(e)
		}
		if e = engine.Run(ctx, plan.ID, strings.Repeat("1", 32)); e == nil {
			t.Fatal("unaudited recording cleanup accepted")
		}
		got, e := os.ReadFile(filepath.Join(sourceDir, "recordings", o.Path))
		if e != nil || !bytes.Equal(got, payload) {
			t.Fatal("failed recording cleanup did not restore bytes", e)
		}
		if _, e = sdb.Database().Exec("DROP TRIGGER block_record_cleanup"); e != nil {
			t.Fatal(e)
		}
		if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		fault.lostCleanup = true
		if e = engine.Run(ctx, plan.ID, strings.Repeat("2", 32)); e == nil {
			t.Fatal("lost recording cleanup receipt ignored")
		}
		if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if len(cleanup) > 5 && cleanup[5] {
			fault.droppedRetire = true
			started := time.Now()
			if e = engine.Run(ctx, plan.ID, strings.Repeat("3", 32)); e == nil || time.Since(started) > 10*time.Second {
				t.Fatal("lost worker was treated as success or polled indefinitely", e)
			}
			pending, e := repo.MigrationTask(ctx, plan.ID)
			if e != nil || pending.State != "cleanup_pending" || pending.ErrorCode == "" {
				t.Fatal("lost worker not recoverable", pending, e)
			}
			if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
		}
		if e = engine.Run(ctx, plan.ID, strings.Repeat("3", 32)); e != nil {
			t.Fatal(e)
		}
		if _, e = os.Stat(filepath.Join(sourceDir, "recordings", o.Path)); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("source recording remains", e)
		}
		sourceRow, e := sdb.Recordings().Recording(ctx, id)
		if e != nil || sourceRow.State != "deleted" {
			t.Fatal("missing source tombstone", sourceRow, e)
		}
		masterRow, e := mdb.Recordings().Recording(ctx, id)
		if e != nil || masterRow.MemberID != trel.PeerID || masterRow.State != "ready" {
			t.Fatal("cleanup changed master authority", masterRow, e)
		}
		targetMember := store.StorageMember{ID: trel.PeerID, RelationshipID: &trid}
		token, e := master.RecordingCapability(ctx, *masterRow, targetMember, "download")
		if e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest("GET", "https://target.test/internal/v1/recordings/"+id, nil)
		r.Header.Set("X-Recording-Capability", token)
		w := httptest.NewRecorder()
		targetRouter.ServeHTTP(w, r)
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), payload) {
			t.Fatal("post-cleanup recording bytes", w.Code)
		}
		footer := recording.Metadata(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
		if encrypted {
			cipherBytes, e := base64.StdEncoding.DecodeString(footer.EncryptedLyrics.Ciphertext)
			if e != nil {
				t.Fatal(e)
			}
			meta := footer.EncryptedLyrics.Encryption
			nonce, _ := meta.ChunkNonce(0)
			decoded, e := aead.Open(nil, nonce, cipherBytes, meta.ChunkAAD(0))
			if e != nil || !bytes.Equal(decoded, plaintext) {
				t.Fatal("client footer decryption after cleanup", e)
			}
		}
		var sourceUsed, personalUsed int64
		if e = sdb.Database().QueryRow("SELECT used_bytes FROM cluster_storage_members WHERE member_id=?", srel.PeerID).Scan(&sourceUsed); e != nil || sourceUsed != 0 {
			t.Fatal("source recording quota", sourceUsed, e)
		}
		if e = mdb.Database().QueryRow("SELECT used_bytes FROM karaoke_users WHERE user_id=?", user.ID).Scan(&personalUsed); e != nil || personalUsed != o.Bytes {
			t.Fatal("personal quota changed", personalUsed, e)
		}
		var audits int
		if e = sdb.Database().QueryRow("SELECT COUNT(*) FROM node_audit WHERE action='recording-deleted'").Scan(&audits); e != nil || audits != 1 {
			t.Fatal("duplicate recording refund", audits, e)
		}
		work, e := repo.MigrationWork(ctx, plan.ID)
		if e != nil || work.Objects[0].State != "cleaned" || work.Task.State != "completed" {
			t.Fatal("incorrect whole-task completion", work, e)
		}
		if len(cleanup) > 4 && cleanup[4] {
			if e = engine.ReleaseDrain(ctx, plan.ID, srel.PeerID, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			for _, rid := range []string{srid, trid} {
				if e = mdb.Nodes().RecordHeartbeat(ctx, rid, true, 1, map[string]any{"capabilities": []string{"storage-v2", store.MigrationCapability}, "storage": map[string]any{"physical_free_bytes": 20 * store.GiB}}, time.Now().Unix()); e != nil {
					t.Fatal(e)
				}
			}
			reverse := runReverseMigrationFixture(t, ctx, repo, mdb.Nodes(), master, mdb.Database(), trel.PeerID, srel.PeerID, filepath.Join(targetDir, "recordings"), filepath.Join(sourceDir, "recordings"))
			row, e := mdb.Recordings().Recording(ctx, id)
			if e != nil || row.State != "ready" || row.MemberID != srel.PeerID || row.ID != id || row.UserID != user.ID {
				t.Fatal("reverse recording identity", row, e)
			}
			token, e := master.RecordingCapability(ctx, *row, store.StorageMember{ID: srel.PeerID, RelationshipID: &srid}, "download")
			if e != nil {
				t.Fatal(e)
			}
			request := httptest.NewRequest("GET", "https://source.test/internal/v1/recordings/"+id, nil)
			request.Header.Set("X-Recording-Capability", token)
			response := httptest.NewRecorder()
			transport.routers["https://source.test"].ServeHTTP(response, request)
			if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), payload) {
				t.Fatal("reverse recording business bytes", response.Code)
			}
			footer := recording.Metadata(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
			if encrypted {
				if footer.EncryptedLyrics == nil || footer.EncryptedLyrics.Encryption != snapshot.EncryptedLyrics.Encryption {
					t.Fatal("reverse descriptor changed", footer)
				}
				meta := footer.EncryptedLyrics.Encryption
				cipherBytes, e := base64.StdEncoding.DecodeString(footer.EncryptedLyrics.Ciphertext)
				if e != nil {
					t.Fatal(e)
				}
				nonce, _ := meta.ChunkNonce(0)
				decoded, e := aead.Open(nil, nonce, cipherBytes, meta.ChunkAAD(0))
				if e != nil || !bytes.Equal(decoded, plaintext) {
					t.Fatal("reverse client decryption", e)
				}
			}
			if e = mdb.Database().QueryRow("SELECT used_bytes FROM karaoke_users WHERE user_id=?", user.ID).Scan(&personalUsed); e != nil || personalUsed != o.Bytes {
				t.Fatal("reverse personal quota", personalUsed, e)
			}
			for _, entry := range []struct {
				database *sql.DB
				member   string
				used     int64
			}{{mdb.Database(), srel.PeerID, o.Bytes}, {mdb.Database(), trel.PeerID, 0}, {sdb.Database(), srel.PeerID, o.Bytes}, {tdb.Database(), trel.PeerID, 0}} {
				var used, reserved int64
				if e = entry.database.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", entry.member).Scan(&used, &reserved); e != nil || used != entry.used || reserved != 0 {
					t.Fatal("reverse recording quota", used, reserved, e)
				}
			}
			t.Logf("fresh reverse recording task=%s encrypted=%v; original opaque bytes, logical ID, descriptor and personal quota retained", reverse, encrypted)
		}
		t.Logf("authenticated recording cleanup bytes=%d encrypted=%v; audit rollback/lost receipt and client read verified; fixture-only grace advance", len(payload), encrypted)
		return
	}
	task := strings.Repeat("c", 32)
	h := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: task, MasterID: mid.ID, SourceID: srel.PeerID, TargetID: trel.PeerID, SourceRelationship: srid, TargetRelationship: trid, PlanSHA: strings.Repeat("1", 64), ObjectCount: 1, Bytes: int64(len(payload))}
	l := store.MigrationLease{TaskID: task, RunnerID: strings.Repeat("d", 32), Epoch: 1, ExpiresAt: time.Now().Unix() + 60}
	binding := &store.RecordingProof{ID: id, UserID: user.ID, Filename: v.Filename, ContentType: v.ContentType, Bytes: h.Bytes, SHA256: sha, CreatedAt: time.Now().Unix() - 1}
	if encrypted {
		binding.EncryptedLyricsEncryption = &snapshot.EncryptedLyrics.Encryption
		binding.MetadataSHA256 = store.RecordingMetadataSHA256(snapshot)
	}
	o := store.MigrationObject{ID: id, ObjectID: id, Resource: "recording", Kind: "recording", Parent: user.ID, Path: srid + "/" + user.ID + "/" + id + ".bin", TargetPath: trid + "/" + user.ID + "/" + id + ".bin", Bytes: h.Bytes, ETag: sha, Version: strings.Repeat("2", 64), Recording: binding}
	obj := store.MigrationPeerObject{Object: o, Proof: store.MigrationDiskProof{ID: id, Version: o.Version, Bytes: h.Bytes, SHA256: sha}}
	call := func(rel store.Relationship, route string, value any) map[string]any {
		t.Helper()
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		var body map[string]any
		if e = controlJSON(raw, &body); e != nil {
			t.Fatal(e)
		}
		result, e := master.Call(ctx, rel, route, body)
		if e != nil {
			t.Fatal(e)
		}
		return result
	}
	for _, rel := range []store.Relationship{srel, trel} {
		call(rel, "/internal/v1/resource-migration/register", map[string]any{"header": h, "lease": l, "state": "queued"})
		call(rel, "/internal/v1/resource-migration/object", map[string]any{"lease": l, "object": obj})
	}
	req := migrationDataRequest{Lease: l, Spec: migrationdata.Spec{TaskID: task, MasterID: mid.ID, SourceID: srel.PeerID, TargetID: trel.PeerID, LogicalID: id, ObjectID: id, Resource: "recording", TargetPath: o.TargetPath, Bytes: o.Bytes, SHA256: sha, SourceVersion: o.Version, Recording: binding}}
	prefix := "/internal/v1/resource-migration/data/"
	call(trel, prefix+"begin", req)
	for offset := 0; offset < len(payload); offset += migrationdata.ChunkBytes {
		req.Offset = int64(offset)
		req.Length = min(migrationdata.ChunkBytes, len(payload)-offset)
		response := call(srel, prefix+"read", req)
		encoded, _ := response["data"].(string)
		data, e := base64.StdEncoding.DecodeString(encoded)
		if e != nil {
			t.Fatal(e)
		}
		req.Data = data
		req.SHA, _ = response["chunk_sha256"].(string)
		call(trel, prefix+"append", req)
		req.Data = nil
		req.SHA = ""
	}
	wait := func(phase string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if call(trel, prefix+"status", req)["peer_state"] == phase {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("missing durable recording phase", phase)
	}
	call(trel, prefix+"verify", req)
	wait("verified")
	call(trel, prefix+"publish", req)
	wait("published")
	call(trel, prefix+"publish", req)
	wait("published")
	row, e := tdb.Recordings().Recording(ctx, id)
	if e != nil || row == nil || row.UserID != user.ID || row.MemberID != trel.PeerID || row.Title != "原始录音" || len(row.Lyrics) != len(snapshot.Lyrics) {
		t.Fatal(row, e)
	}
	targetMember := store.StorageMember{ID: trel.PeerID, RelationshipID: &trid}
	token, e := master.RecordingCapability(ctx, *row, targetMember, "download")
	if e != nil {
		t.Fatal(e)
	}
	request := httptest.NewRequest("GET", "https://target.test/internal/v1/recordings/"+id, nil)
	request.Header.Set("X-Recording-Capability", token)
	response := httptest.NewRecorder()
	targetRouter.ServeHTTP(response, request)
	if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), payload) {
		t.Fatal("ordinary recording read mismatch", response.Code)
	}
	if encrypted {
		footer := recording.Metadata(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
		if footer == nil || footer.EncryptedLyrics == nil || footer.EncryptedLyrics.Encryption != snapshot.EncryptedLyrics.Encryption {
			t.Fatal("encrypted footer changed")
		}
		cipherBytes, e := base64.StdEncoding.DecodeString(footer.EncryptedLyrics.Ciphertext)
		if e != nil {
			t.Fatal(e)
		}
		meta := footer.EncryptedLyrics.Encryption
		nonce, _ := meta.ChunkNonce(0)
		decoded, e := aead.Open(nil, nonce, cipherBytes, meta.ChunkAAD(0))
		if e != nil || !bytes.Equal(decoded, plaintext) {
			t.Fatal("client decryption after migration failed", e)
		}
	}
	masterRow, e := mdb.Recordings().Recording(ctx, id)
	if e != nil || masterRow.MemberID != srel.PeerID || masterRow.Title != "原始录音" {
		t.Fatal("publication changed business owner", masterRow, e)
	}
	var used, reserved, personal int64
	mdb.Database().QueryRow("SELECT used_bytes FROM karaoke_users WHERE user_id=?", user.ID).Scan(&personal)
	tdb.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", trel.PeerID).Scan(&used, &reserved)
	if personal != o.Bytes || used != o.Bytes || reserved != 0 {
		t.Fatal("quota mismatch", personal, used, reserved)
	}
	var users int
	tdb.Database().QueryRow("SELECT COUNT(*) FROM karaoke_users WHERE user_id=?", user.ID).Scan(&users)
	if users != 0 {
		t.Fatal("copied account")
	}
	info, e := os.Stat(filepath.Join(targetDir, "recordings", o.TargetPath))
	if e != nil || info.Mode().Perm()&0040 == 0 {
		t.Fatal("Direct media group cannot read published recording", info, e)
	}
	t.Logf("recording bytes=%d logical ID preserved, Master quota unchanged, no account copied", len(payload))
}
