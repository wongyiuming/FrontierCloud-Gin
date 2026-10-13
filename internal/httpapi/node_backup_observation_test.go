package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedBackupObservationActualSQLAndColdBytes(t *testing.T) {
	for _, cold := range []bool{false, true} {
		t.Run(map[bool]string{false: "sql", true: "cold"}[cold], func(t *testing.T) {
			ctx := context.Background()
			transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
			_, mdb, _, _, master := clusterFixture(t, "https://master.test", transport, true)
			router, sdb, dir, _, source := clusterFixture(t, "https://source.test", transport, true)
			if cold {
				if e := sdb.ConfigureFileBackups(filepath.Join(dir, ".cold-backups")); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := master.Promote(ctx, "Master", "https://master.test", store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if _, e := source.Promote(ctx, "Follower", "https://source.test", 0, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			pair, e := source.CreatePair(ctx, store.NodeAudit{})
			if e != nil {
				t.Fatal(e)
			}
			rid, e := master.ImportPair(ctx, pair, store.NodeAudit{})
			if e != nil {
				t.Fatal(e)
			}
			rel, e := mdb.Nodes().Relationship(ctx, rid)
			if e != nil {
				t.Fatal(e)
			}
			identity, e := master.IdentityState(ctx)
			if e != nil {
				t.Fatal(e)
			}
			data := bytes.Repeat([]byte("opaque backup bytes\x00"), 25000)
			sum := sha256.Sum256(data)
			sha := hex.EncodeToString(sum[:])
			repo := sdb.Backups()
			if e = repo.BeginBackup(ctx, rid, 100, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			for index, offset := 0, 0; offset < len(data); index++ {
				end := min(len(data), offset+store.MaxBackupChunk)
				if e = repo.AppendBackup(ctx, rid, 100, index, data[offset:end]); e != nil {
					t.Fatal(e)
				}
				offset = end
			}
			manifest, e := repo.CommitBackup(ctx, rid, 100, sha, store.NodeAudit{})
			if e != nil {
				t.Fatal(e)
			}
			digest, e := store.MigrationDigest(manifest)
			if e != nil {
				t.Fatal(e)
			}
			request := map[string]any{"action": "start", "observation_id": strings.Repeat("1", 32), "binding": map[string]any{"member_id": rel.PeerID, "master_id": identity.ID, "relationship_id": rid, "scope": "data"}, "resource_kind": "backup", "object_id": "100", "metadata_sha256": digest, "expected_bytes": len(data)}
			route := "/internal/v1/backup-observation"
			if status := migrationUnsignedStatus(router, route); status != 401 {
				t.Fatal("unsigned", status)
			}
			request["path"] = "/secrets/node-vault.key"
			if _, e = master.Call(ctx, rel, route, request); e == nil {
				t.Fatal("arbitrary path")
			}
			delete(request, "path")
			request["object_id"] = "0100"
			if _, e = master.Call(ctx, rel, route, request); e == nil {
				t.Fatal("noncanonical generation")
			}
			request["object_id"] = "100"
			poll := func(start bool) resourceinventory.ContentJob {
				t.Helper()
				if start {
					request["action"] = "start"
					delete(request, "incarnation")
				}
				deadline := time.Now().Add(10 * time.Second)
				for {
					value, e := master.Call(ctx, rel, route, request)
					if e != nil {
						t.Fatal(e)
					}
					var job resourceinventory.ContentJob
					if e = decodeInventory(value, &job); e != nil {
						t.Fatal(e)
					}
					if job.State == "observed" || job.State == "failed" {
						return job
					}
					if time.Now().After(deadline) {
						t.Fatal("observation timeout", job)
					}
					request["action"] = "status"
					request["incarnation"] = job.Incarnation
					time.Sleep(5 * time.Millisecond)
				}
			}
			job := poll(true)
			if job.Observation == nil || job.Observation.SHA256 != sha || job.Observation.Bytes != int64(len(data)) || job.Observation.Path != "backup/100" {
				t.Fatal("wrong actual proof", job)
			}
			request["action"] = "cancel"
			request["incarnation"] = job.Incarnation
			value, e := master.Call(ctx, rel, route, request)
			if e != nil {
				t.Fatal(e)
			}
			var cancelled resourceinventory.ContentJob
			if e = decodeInventory(value, &cancelled); e != nil || cancelled.State != "cancelled" || cancelled.Observation != nil {
				t.Fatal(cancelled, e)
			}
			configuration, e := mdb.Pool().MemberConfiguration(ctx, rel.PeerID)
			if e != nil {
				t.Fatal(e)
			}
			configuration.Backup.Enabled = true
			if e = mdb.Pool().ConfigureMember(ctx, rel.PeerID, configuration, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if e = master.Tick(ctx, rel); e != nil {
				t.Fatal(e)
			}
			observation, e := master.ObserveBackup(ctx, rid, manifest)
			if e != nil || observation.SHA256 != sha || observation.Bytes != int64(len(data)) {
				t.Fatal("typed Master observation", observation, e)
			}
			if cold {
				name := "artifact." + identity.ID + ".100." + sha
				file, e := os.OpenFile(filepath.Join(dir, ".cold-backups", name), os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = file.WriteAt([]byte("!"), 0); e != nil {
					t.Fatal(e)
				}
				file.Close()
			} else {
				if _, e = sdb.Database().Exec("UPDATE cluster_business_backup_chunks SET payload=? WHERE master_id=? AND generation=100 AND chunk_index=0", bytes.Repeat([]byte("!"), store.MaxBackupChunk), identity.ID); e != nil {
					t.Fatal(e)
				}
			}
			request["observation_id"] = strings.Repeat("2", 32)
			job = poll(true)
			if job.State != "failed" || job.Observation != nil || job.ErrorCode == "" {
				t.Fatal("corrupt backup approved", job)
			}
			if _, e = master.ObserveBackup(ctx, rid, manifest); e == nil {
				t.Fatal("Master accepted corrupt backup")
			}
			// Observation never deletes a generation or clears independent retirement.
			ledger, e := sdb.Pool().(store.RetirementRepository).RetirementLedger(ctx, rid, rel.PeerID)
			if e != nil || ledger.DatabaseClear {
				t.Fatal("observation cleared retention", ledger, e)
			}
		})
	}
}
