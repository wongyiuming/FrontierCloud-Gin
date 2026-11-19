package backup

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

const businessFixtureMaster = "11111111111111111111111111111111"

func businessStateTarget(t *testing.T) *sqlitestore.Store {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().Exec("INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','','fixture',1)", businessFixtureMaster); err != nil {
		t.Fatal(err)
	}
	return db
}

func businessStateFixture() []byte {
	records := preflightRecords()
	ban := preflightRow(records, "ip_auto_ban_events")
	ban["last_path"] = "/api/v1/media/music/private-title.mp3"
	ban["expires_at"] = "9999-12-31 23:59:59.000000"
	date := ban["banned_at"]
	row := func(table string, value map[string]any) map[string]any {
		return map[string]any{"kind": "row", "table": table, "value": value}
	}
	return encodedPreflight(append(records[:len(records)-1],
		row("ip_security_audit_log", map[string]any{"id": 2, "ip_address": "192.0.2.1", "action": "invalid_api", "detail": `{"path":"/api/v1/media/music/private-title.mp3"}`, "session_id_hash": nil, "request_id": nil, "trace_id": nil, "created_at": date}),
		row("ip_security_summary", map[string]any{"ip_address": "192.0.2.1", "attack_count": 12, "last_attack_at": date}),
		row("ip_permanent_whitelist", map[string]any{"ip_address": "192.0.2.2", "created_at": date, "created_by_session_hash": nil, "note": "known admin"}),
		row("webrtc_observation_events", map[string]any{"id": 6, "client_ip": "192.0.2.2", "webrtc_ip": nil, "outcome": "missing", "matches_verified": 0, "observed_at": date}),
		row("webrtc_observation_summary", map[string]any{"client_ip": "192.0.2.2", "webrtc_ip_key": "", "webrtc_ip": nil, "observation_count": 5, "matching_count": 0, "first_seen": date, "last_seen": date, "last_outcome": "missing"}),
		row("karaoke_registration_daily", map[string]any{"client_ip": "192.0.2.2", "day_key": "20261002", "failure_count": 1, "success_count": 2, "updated_at": 2}),
		row("karaoke_audit_log", map[string]any{"id": 4, "user_id": strings.Repeat("d", 32), "action": "recording", "result": "ok", "client_ip": "192.0.2.2", "webrtc_addresses": `[]`, "detail": `{"name":"private-title.mp3"}`, "request_id": nil, "trace_id": nil, "created_at": 2}),
		map[string]any{"kind": "end"},
	))
}

func TestImportBusinessStatePreservesPolicyHistoryAndRetry(t *testing.T) {
	ctx := context.Background()
	db := businessStateTarget(t)
	data := businessStateFixture()
	for _, repeat := range []bool{false, true} {
		report, err := ImportBusinessState(ctx, bytes.NewReader(data), expectedPreflight(data), db.Database(), businessFixtureMaster, func() error { return nil })
		if err != nil || report.AlreadyApplied != repeat || report.RestoreReady || report.ArchivedRecordings != 1 || report.ArchivedUsageBytes != 28 || len(report.ImportedRows) != 9 {
			t.Fatalf("unexpected import result: %+v, %v", report, err)
		}
		for table, count := range report.ImportedRows {
			if count != 1 {
				t.Fatalf("%s imported %d rows", table, count)
			}
		}
	}
	ban, err := db.Security().IPBlock(ctx, "192.0.2.1")
	if err != nil || ban == nil || ban.ID != 1 {
		t.Fatal("active ban did not reach live policy", err)
	}
	generation, published, err := db.Security().EdgeProjection(ctx)
	if err != nil || generation != 1 || published != 0 {
		t.Fatal("projection was not refreshed exactly once", generation, published, err)
	}
	var quota, usage, recordingRows, adminRows int
	var sanitizedIP, sanitizedKaraoke string
	var path *string
	err = db.Database().QueryRow(`SELECT
 (SELECT quota_bytes FROM karaoke_users), (SELECT used_bytes FROM karaoke_users),
 (SELECT COUNT(*) FROM karaoke_recordings), (SELECT COUNT(*) FROM admin_audit_log),
 (SELECT detail FROM ip_security_audit_log), (SELECT detail FROM karaoke_audit_log),
 (SELECT last_path FROM ip_auto_ban_events)`).Scan(&quota, &usage, &recordingRows, &adminRows, &sanitizedIP, &sanitizedKaraoke, &path)
	if err != nil || quota != 100 || usage != 0 || recordingRows != 0 || adminRows != 0 || sanitizedIP != "{}" || sanitizedKaraoke != "{}" || path != nil {
		t.Fatal("live projection contains old paths or unbacked recording state", err)
	}
}

func TestImportBusinessStateRejectsUnverifiedInputAndRollsBackOnFenceLoss(t *testing.T) {
	ctx := context.Background()
	db := businessStateTarget(t)
	data := businessStateFixture()
	expected := expectedPreflight(data)
	read := func() *bytes.Reader { return bytes.NewReader(data) }
	validFence := func() error { return nil }
	wrongChecksum := expected
	wrongChecksum.Checksum = strings.Repeat("0", 64)
	if _, err := ImportBusinessState(ctx, read(), wrongChecksum, db.Database(), businessFixtureMaster, validFence); !errors.Is(err, store.ErrBackupState) {
		t.Fatal("unverified input accepted", err)
	}
	if _, err := ImportBusinessState(ctx, read(), expected, db.Database(), strings.Repeat("2", 32), validFence); !errors.Is(err, ErrBusinessStateTarget) {
		t.Fatal("unexpected target accepted", err)
	}
	fenceLoss := errors.New("fixture fence loss")
	checks := 0
	if _, err := ImportBusinessState(ctx, read(), expected, db.Database(), businessFixtureMaster, func() error {
		checks++
		if checks == 2 {
			return fenceLoss
		}
		return nil
	}); !errors.Is(err, fenceLoss) {
		t.Fatal("lost fence accepted", err)
	}
	for _, spec := range businessStateTables {
		var count int
		if err := db.Database().QueryRow("SELECT COUNT(*) FROM " + spec.table).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial state was committed", spec.table, count, err)
		}
	}
	if _, err := ImportBusinessState(ctx, read(), expected, db.Database(), businessFixtureMaster, validFence); err != nil {
		t.Fatal("could not retry rolled back import", err)
	}
	if _, err := db.Database().Exec("UPDATE webrtc_observation_summary SET observation_count=7"); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportBusinessState(ctx, read(), expected, db.Database(), businessFixtureMaster, validFence); !errors.Is(err, ErrBusinessStateTarget) {
		t.Fatal("changed target accepted", err)
	}
	var count int
	if err := db.Database().QueryRow("SELECT observation_count FROM webrtc_observation_summary").Scan(&count); err != nil || count != 7 {
		t.Fatal("conflicting target was overwritten", count, err)
	}
}
