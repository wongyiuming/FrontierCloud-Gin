package business_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func s3BackupDatabase(t *testing.T, object bool) (store.Store, *sql.DB, string, string) {
	t.Helper()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	ctx := context.Background()
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "private-node-fixture"}); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("UPDATE node_identity SET `role`='Master' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	member, id := strings.Repeat("1", 32), strings.Repeat("2", 64)
	if _, err := raw.Exec("INSERT INTO cluster_storage_members(member_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES (?,'S3','S3',1,?,128,0,0,'online',1,2)", member, store.GiB); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("INSERT INTO s3_members(member_id,name,endpoint,region,bucket,prefix,address_style,namespace_key,sealed_credentials,credential_revision,revision,probe_revision,probe_state,created_at,updated_at) VALUES (?,'S3 fixture','https://s3.us-east-1.amazonaws.com','us-east-1','backup-s3-fixture','managed','path',?,'sealed-secret-fixture',1,3,3,'ready',1,2)", member, "aws\nbackup-s3-fixture"); err != nil {
		t.Fatal(err)
	}
	if object {
		path := "music/remote/a.mp3"
		locator := sha256.Sum256([]byte(path))
		if _, err := raw.Exec("INSERT INTO global_media_objects(media_id,storage_member_id,object_id,media_path,path_locator,object_kind,size_bytes,etag,state,created_at,updated_at) VALUES(?,?,?,?,?,'audio',128,'opaque','active',1,2)", id, member, id, path, hex.EncodeToString(locator[:])); err != nil {
			t.Fatal(err)
		}
		proof, err := json.Marshal(store.S3ObjectProof{Key: "objects/" + id, SessionID: strings.Repeat("3", 32), ObjectID: id, MemberID: member, MediaID: id, Bytes: 128, ETag: "opaque", VersionID: "version1", CompositeSHA256: base64.StdEncoding.EncodeToString(make([]byte, 32)) + "-1"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = raw.Exec("INSERT INTO s3_objects(media_id,member_id,object_key,object_id,proof_json,state,revision,created_at,updated_at) VALUES(?,?,?, ?,?,'active',1,1,2)", id, member, "objects/"+id, id, string(proof)); err != nil {
			t.Fatal(err)
		}
	}
	return db, raw, member, id
}

func TestS3BusinessBackupStripsAuthorityPreservesObjectAndLeavesDatabaseUnchanged(t *testing.T) {
	db, raw, member, _ := s3BackupDatabase(t, true)
	var artifact bytes.Buffer
	encoder := json.NewEncoder(&artifact)
	const generation int64 = 1790000000000000123
	if err := encoder.Encode(map[string]any{"kind": "header", "version": 2, "generation": generation}); err != nil {
		t.Fatal(err)
	}
	var sawMember, sawObject, sawOwner bool
	err := db.Backups().ExportBusinessSnapshot(context.Background(), func(table string, row map[string]any) error {
		switch table {
		case "s3_members":
			sawMember = true
			if row["sealed_credentials"] != "" || row["probe_revision"] != int64(0) || row["probe_state"] != "unchecked" {
				t.Fatal("authority exported", row)
			}
		case "s3_objects":
			sawObject = true
			if !strings.Contains(row["proof_json"].(string), "version1") {
				t.Fatal("provider identity lost")
			}
		case "cluster_storage_members":
			if row["member_id"] == member {
				sawOwner = true
				if row["storage_enabled"] != int64(0) || row["writable"] != int64(0) || row["health"] != "offline" {
					t.Fatal("restored adapter remained enabled", row)
				}
			}
		case "s3_uploads", "s3_upload_parts", "s3_probe_journal":
			t.Fatal("runtime journal exported", table)
		}
		return encoder.Encode(map[string]any{"kind": "row", "table": table, "value": row})
	})
	if err != nil || !sawMember || !sawObject || !sawOwner {
		t.Fatal(err, sawMember, sawObject, sawOwner)
	}
	if err = encoder.Encode(map[string]any{"kind": "end"}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(artifact.Bytes(), []byte("sealed-secret-fixture")) {
		t.Fatal("sealed credential leaked")
	}
	hash := sha256.Sum256(artifact.Bytes())
	report, err := backup.Preflight(context.Background(), bytes.NewReader(artifact.Bytes()), backup.Expectation{Generation: generation, Checksum: hex.EncodeToString(hash[:]), Bytes: int64(artifact.Len())}, t.TempDir())
	if err != nil || !report.LogicalValid || report.RestoreReady {
		t.Fatal(report, err)
	}
	var sealed, probe string
	var revision, enabled, writable int
	if err = raw.QueryRow("SELECT m.sealed_credentials,m.probe_state,m.probe_revision,s.storage_enabled,s.writable FROM s3_members m JOIN cluster_storage_members s ON s.member_id=m.member_id WHERE m.member_id=?", member).Scan(&sealed, &probe, &revision, &enabled, &writable); err != nil || sealed != "sealed-secret-fixture" || probe != "ready" || revision != 3 || enabled != 1 || writable != 1 {
		t.Fatal("export mutated live authority", sealed, probe, revision, enabled, writable, err)
	}
}

func TestS3BackupAndMaintenanceDistinguishStableReadsFromUnsettledMutations(t *testing.T) {
	for _, mode := range []string{"upload", "unknown-aborted", "probe", "part-grant", "read-grant", "delete", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			db, raw, member, id := s3BackupDatabase(t, true)
			var err error
			switch mode {
			case "upload", "unknown-aborted":
				state, uncertain := "creating", 0
				if mode == "unknown-aborted" {
					state, uncertain = "aborted", 1
				}
				_, err = raw.Exec("INSERT INTO s3_uploads(upload_id,member_id,object_key,object_id,state,credential_revision,create_uncertain,absolute_expires_at,created_at,updated_at) VALUES(?,?,?,?,?,1,?,86401,1,2)", strings.Repeat("4", 32), member, "objects/pending", strings.Repeat("5", 64), state, uncertain)
			case "probe":
				_, err = raw.Exec("INSERT INTO s3_probe_journal(probe_id,member_id,revision,credential_revision,object_key,state,created_at,updated_at) VALUES(?,?,3,1,'probe/pending','creating',1,2)", strings.Repeat("6", 32), member)
			case "part-grant":
				_, err = raw.Exec("INSERT INTO s3_upload_parts(upload_id,part_number,size_bytes,checksum_sha256,grant_until,created_at,updated_at) VALUES(?,1,128,?,?,1,2)", strings.Repeat("4", 32), base64.StdEncoding.EncodeToString(make([]byte, 32)), time.Now().Unix()+300)
			case "read-grant":
				_, err = raw.Exec("UPDATE s3_objects SET grant_until=? WHERE media_id=?", time.Now().Unix()+300, id)
			case "delete":
				_, err = raw.Exec("UPDATE s3_objects SET state='deleting' WHERE media_id=?", id)
			case "cleanup":
				_, err = raw.Exec("UPDATE s3_members SET cleanup_only=1 WHERE member_id=?", member)
			}
			if err != nil {
				t.Fatal(err)
			}
			called := false
			if err = db.Backups().ExportBusinessSnapshot(context.Background(), func(string, map[string]any) error { called = true; return nil }); !errors.Is(err, store.ErrBackupBusy) || called {
				t.Fatal("unstable projection emitted", mode, err, called)
			}
			status, err := db.Maintenance().InspectMaintenance(context.Background())
			// Full state archives retain settled object read grants. A dangling part
			// remains incomplete authority and cannot certify logical idleness.
			expectedIdle := mode == "read-grant"
			if err != nil || status.LogicalIdle != expectedIdle {
				t.Fatal("state versus v2 boundary", mode, status, err)
			}
		})
	}
}

func TestS3IdentityResetRejectsOrphanIntentsAndPreservesSettledHistory(t *testing.T) {
	for _, mode := range []string{"member", "unknown-create", "probe", "grant", "settled"} {
		t.Run(mode, func(t *testing.T) {
			db, raw, member, _ := s3BackupDatabase(t, false)
			if mode != "member" {
				if _, err := raw.Exec("DELETE FROM s3_members WHERE member_id=?", member); err != nil {
					t.Fatal(err)
				}
				if _, err := raw.Exec("DELETE FROM cluster_storage_members WHERE member_id=?", member); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			switch mode {
			case "unknown-create":
				_, err = raw.Exec("INSERT INTO s3_uploads(upload_id,member_id,object_key,object_id,state,credential_revision,create_uncertain,absolute_expires_at,created_at,updated_at) VALUES(?,?,?,?,'aborted',1,1,86401,1,2)", strings.Repeat("4", 32), member, "objects/pending", strings.Repeat("5", 64))
			case "probe", "grant", "settled":
				state, grant := "creating", int64(0)
				if mode != "probe" {
					state = "settled"
				}
				if mode == "grant" {
					grant = time.Now().Unix() + 300
				}
				_, err = raw.Exec("INSERT INTO s3_probe_journal(probe_id,member_id,revision,credential_revision,object_key,state,grant_until,created_at,updated_at) VALUES(?,?,3,1,'probe/pending',?,?,1,2)", strings.Repeat("6", 32), member, state, grant)
			}
			if err != nil {
				t.Fatal(err)
			}
			next := store.NodeIdentity{ID: strings.Repeat("b", 32), Role: "Standalone", PrivateKey: "next-private-fixture"}
			_, err = db.Nodes().ResetIdentity(context.Background(), strings.Repeat("a", 32), "Master", next, store.NodeAudit{})
			if mode == "settled" {
				if err != nil {
					t.Fatal("settled history blocked identity rotation", err)
				}
			} else if !errors.Is(err, store.ErrNodeState) {
				t.Fatal("owned S3 state discarded", mode, err)
			}
		})
	}
}

func TestS3BusinessBackupRejectsOwnershipAndNativeCapabilityFictionBeforeEmission(t *testing.T) {
	for _, mode := range []string{"missing-adapter", "native-backup"} {
		t.Run(mode, func(t *testing.T) {
			db, raw, member, _ := s3BackupDatabase(t, true)
			var err error
			if mode == "missing-adapter" {
				_, err = raw.Exec("DELETE FROM s3_members WHERE member_id=?", member)
			} else {
				_, err = raw.Exec("INSERT INTO cluster_backup_members(member_id,enabled,generation,last_success,lag_seconds,checksum,state,updated_at) VALUES(?,1,0,0,0,'','ready',2)", member)
			}
			if err != nil {
				t.Fatal(err)
			}
			called := false
			err = db.Backups().ExportBusinessSnapshot(context.Background(), func(string, map[string]any) error { called = true; return nil })
			if !errors.Is(err, store.ErrBackupState) || called {
				t.Fatal("invalid adapter state emitted", mode, err, called)
			}
		})
	}
}

func TestS3BusinessBackupRejectsZeroGrantOrphanPartBeforeEmission(t *testing.T) {
	db, raw, _, _ := s3BackupDatabase(t, true)
	id := strings.Repeat("4", 32)
	if _, err := raw.Exec("INSERT INTO s3_upload_parts(upload_id,part_number,size_bytes,checksum_sha256,grant_until,created_at,updated_at) VALUES(?,1,128,?,0,1,2)", id, base64.StdEncoding.EncodeToString(make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	called := false
	err := db.Backups().ExportBusinessSnapshot(context.Background(), func(string, map[string]any) error { called = true; return nil })
	if !errors.Is(err, store.ErrBackupBusy) || called {
		t.Fatal("unknown part omitted as settled history", err, called)
	}
	status, err := db.Maintenance().InspectMaintenance(context.Background())
	if err != nil || status.LogicalIdle || status.Pending["s3_part_orphans"] != 1 {
		t.Fatal("orphan part certified logical idleness", status, err)
	}
	var count int
	if err := raw.QueryRow("SELECT COUNT(*) FROM s3_upload_parts WHERE upload_id=? AND grant_until=0", id).Scan(&count); err != nil || count != 1 {
		t.Fatal("backup inspection discarded unknown state", count, err)
	}
}
