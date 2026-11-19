package business_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestBusinessBackupExportRepeatableSnapshotDatesAndPrivateTableExclusion(t *testing.T) {
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	ctx := context.Background()
	identity, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "private-key-must-not-export"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("UPDATE node_identity SET `role`='Master' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	name := "music/" + t.Name() + "/track.mp3"
	ids, err := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: name, Kind: "audio"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		raw.Exec("DELETE FROM media_visibility WHERE relative_path=?", name)
		raw.Exec("DELETE FROM media_playback_stats WHERE media_id=?", ids[name])
		raw.Exec("DELETE FROM media_objects WHERE media_id=?", ids[name])
		raw.Exec("DELETE FROM admin_audit_log WHERE request_id=?", t.Name())
		raw.Exec("UPDATE node_identity SET `role`=?,endpoint=? WHERE singleton=1", identity.Role, identity.Endpoint)
	})
	if err := db.Media().SetHidden(ctx, []string{name}, true, store.AdminAudit{RequestID: t.Name()}); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("INSERT INTO media_playback_stats(media_id,media_path,play_score,preference,created_at,updated_at) SELECT media_id,media_path,1,0,created_at,updated_at FROM media_objects WHERE media_id=?", ids[name]); err != nil {
		t.Fatal(err)
	}
	var changed, scoreSeen, dateSeen bool
	var artifact bytes.Buffer
	encoder := json.NewEncoder(&artifact)
	const backupGeneration int64 = 1790000000000000123
	if err := encoder.Encode(map[string]any{"kind": "header", "version": 2, "generation": backupGeneration}); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	err = db.Backups().ExportBusinessSnapshot(ctx, func(table string, row map[string]any) error {
		if err := encoder.Encode(map[string]any{"kind": "row", "table": table, "value": row}); err != nil {
			return err
		}
		allowed[table] = true
		if strings.Contains(table, "identity") || strings.Contains(table, "relationship") || strings.Contains(table, "business_backup") || table == "media_delete_operations" || table == "cluster_upload_sessions" {
			t.Fatal("private/runtime table leaked", table)
		}
		if table == "media_visibility" && row["relative_path"] == name {
			date, ok := row["updated_at"].(map[string]string)
			if !ok || date["$datetime"] == "" {
				t.Fatal("database-dependent datetime", row)
			}
			dateSeen = true
			// Commit two related updates after the export snapshot exists. Later
			// tables must still see the same pre-update database generation.
			tx, err := raw.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			if _, err := tx.Exec("UPDATE media_visibility SET hidden=0 WHERE relative_path=?", name); err != nil {
				return err
			}
			if _, err := tx.Exec("UPDATE media_playback_stats SET play_score=2 WHERE media_id=?", ids[name]); err != nil {
				return err
			}
			changed = true
			return tx.Commit()
		}
		if table == "media_playback_stats" && row["media_id"] == ids[name] {
			raw, err := json.Marshal(row["play_score"])
			if err != nil || string(raw) != "1" {
				t.Fatal("mixed snapshot generations", row, err)
			}
			scoreSeen = true
		}
		return nil
	})
	if err != nil || !changed || !scoreSeen || !dateSeen || !allowed["ip_security_projection"] {
		t.Fatal("snapshot export", err, changed, scoreSeen, dateSeen, allowed)
	}
	if err := encoder.Encode(map[string]any{"kind": "end"}); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(artifact.Bytes())
	report, err := backup.Preflight(ctx, bytes.NewReader(artifact.Bytes()), backup.Expectation{Generation: backupGeneration, Checksum: hex.EncodeToString(hash[:]), Bytes: int64(artifact.Len())}, t.TempDir())
	if err != nil || !report.LogicalValid || report.RestoreReady {
		t.Fatal("real driver exported artifact preflight", report, err)
	}
	var score int
	if err := raw.QueryRow("SELECT play_score FROM media_playback_stats WHERE media_id=?", ids[name]).Scan(&score); err != nil || score != 2 {
		t.Fatal("concurrent writer did not commit", score, err)
	}
	operation := strings.Repeat("d", 32)
	if _, err := raw.Exec("INSERT INTO media_delete_operations(operation_id,state,manifest,created_at) SELECT ?,'rename_pending','[]',created_at FROM media_objects WHERE media_id=?", operation, ids[name]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Exec("DELETE FROM media_delete_operations WHERE operation_id=?", operation) })
	called := false
	if err := db.Backups().ExportBusinessSnapshot(ctx, func(string, map[string]any) error { called = true; return nil }); !errors.Is(err, store.ErrBackupBusy) || called {
		t.Fatal("omitted pending intent exported", err, called)
	}
	if _, err := raw.Exec("DELETE FROM media_delete_operations WHERE operation_id=?", operation); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("output failure")
	if err := db.Backups().ExportBusinessSnapshot(ctx, func(string, map[string]any) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal("writer failure ignored", err)
	}
	if _, err := raw.Exec("UPDATE node_identity SET `role`='Follower' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if err := db.Backups().ExportBusinessSnapshot(ctx, func(string, map[string]any) error { return nil }); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("Follower business snapshot exposed", err)
	}
}

func TestBusinessBackupRefusesPopulatedSealedTreeBeforeEmission(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	identity, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, err = raw.Exec("UPDATE node_identity SET `role`='Master' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("c", 64)
	t.Cleanup(func() {
		raw.Exec("DELETE FROM sealed_tree_blob_ids WHERE blob_index=?", id)
		raw.Exec("UPDATE node_identity SET `role`=?,endpoint=? WHERE singleton=1", identity.Role, identity.Endpoint)
	})
	if _, err = raw.Exec(`INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, id); err != nil {
		t.Fatal(err)
	}
	idle, err := db.Maintenance().InspectMaintenance(ctx)
	if err != nil || idle.LogicalIdle || idle.Pending["sealed_tree_unrecoverable"] != 1 {
		t.Fatal("offline capture was not fenced", err)
	}
	emitted := false
	err = db.Backups().ExportBusinessSnapshot(ctx, func(string, map[string]any) error { emitted = true; return nil })
	if !errors.Is(err, store.ErrBackupState) || emitted {
		t.Fatal("incomplete backup was emitted", err)
	}
	var count int
	if err = raw.QueryRow(`SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, id).Scan(&count); err != nil || count != 1 {
		t.Fatal("backup check changed tree data", err)
	}
}

func TestBusinessBackupRefusesLegacyReadIntentBeforeEmission(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, err := raw.Exec("UPDATE node_identity SET `role`='Master' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("c", 64)
	if _, err := raw.Exec("INSERT INTO legacy_read_control_intents(operation_index,challenge_tag,nonce,revision,sealed) VALUES(?,?,?,?,?)", id, strings.Repeat("d", 64), []byte("nonce"), 1, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	emitted := false
	err := db.Backups().ExportBusinessSnapshot(ctx, func(string, map[string]any) error { emitted = true; return nil })
	if !errors.Is(err, store.ErrBackupState) || emitted {
		t.Fatal("snapshot omitted protected legacy-read intent", err, emitted)
	}
	var count int
	if err = raw.QueryRow("SELECT COUNT(*) FROM legacy_read_control_intents WHERE operation_index=?", id).Scan(&count); err != nil || count != 1 {
		t.Fatal("backup rejection changed the intent", count, err)
	}
}

func TestBusinessBackupRefusesSelectedUploadIntentBeforeEmission(t *testing.T) {
	operationID, encryptionID := strings.Repeat("c", 64), strings.Repeat("1", 64)
	sealed := []byte("sealed")
	for _, fixture := range []struct {
		table, insert string
		args          []any
	}{
		{"selected_upload_intents", "(operation_index,upload_index,member_index,parent_index,blob_index,encryption_id,sealed) VALUES(?,?,?,?,?,?,?)", []any{operationID, strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("2", 64), strings.Repeat("f", 64), encryptionID, sealed}},
		{"selected_s3_uploads", "(operation_index,encryption_id,sealed) VALUES(?,?,?)", []any{operationID, encryptionID, sealed}},
		{"selected_s3_parts", "(operation_index,part_index,encryption_id,sealed) VALUES(?,?,?,?)", []any{operationID, strings.Repeat("d", 64), encryptionID, sealed}},
	} {
		t.Run(fixture.table, func(t *testing.T) {
			db := database(t)
			ctx := context.Background()
			if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "synthetic"}); err != nil {
				t.Fatal(err)
			}
			raw := db.(interface{ Database() *sql.DB }).Database()
			if _, err := raw.Exec("UPDATE node_identity SET `role`='Master' WHERE singleton=1"); err != nil {
				t.Fatal(err)
			}
			if _, err := raw.Exec("INSERT INTO "+fixture.table+fixture.insert, fixture.args...); err != nil {
				t.Fatal(err)
			}
			emitted := false
			err := db.Backups().ExportBusinessSnapshot(ctx, func(string, map[string]any) error { emitted = true; return nil })
			if !errors.Is(err, store.ErrBackupState) || emitted {
				t.Fatal("snapshot omitted protected selected upload state", err, emitted)
			}
			var count int
			if err = raw.QueryRow("SELECT COUNT(*) FROM "+fixture.table+" WHERE operation_index=?", operationID).Scan(&count); err != nil || count != 1 {
				t.Fatal("backup rejection changed selected upload state", count, err)
			}
		})
	}
}
