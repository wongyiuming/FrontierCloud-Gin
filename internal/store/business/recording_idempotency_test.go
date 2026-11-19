package business_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

// The table/column are synthetic and exist only in this isolated fixture.
// Production migration, key handling, lifecycle fencing and HTTP remain gated.
func TestRecordingRequestIdempotencySynthetic(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_MYSQL_HOST") != "" && os.Getenv("FRONTIERCLOUD_TEST_MYSQL_DATABASE_PREFIX") == "" {
		t.Skip("a disposable per-test MySQL database is required for DDL")
	}
	db := database(t)
	ctx := context.Background()
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, err := raw.Exec(`ALTER TABLE karaoke_recordings ADD COLUMN request_protected INTEGER NOT NULL DEFAULT 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`ALTER TABLE karaoke_recordings ADD COLUMN request_id CHAR(32) NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE UNIQUE INDEX uq_test_recording_request ON karaoke_recordings(user_id,request_id)`); err != nil {
		t.Fatal(err)
	}
	ddl := `CREATE TABLE recording_request_intents(user_id CHAR(32) NOT NULL,request_id CHAR(32) NOT NULL,request_mac CHAR(64) NOT NULL,recording_id CHAR(32) NOT NULL,owner_id CHAR(32) NOT NULL,record_mac CHAR(64) NOT NULL,binding_mac CHAR(64) NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(user_id,request_id),UNIQUE(recording_id))`
	if db.Backend() == "mysql" {
		ddl += " ENGINE=InnoDB"
	}
	if _, err := raw.Exec(ddl); err != nil {
		t.Fatal(err)
	}
	identity, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "fixture", CreatedAt: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://recording.test", Allocation: 5 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	user := store.KaraokeUser{ID: strings.Repeat("d", 32), Username: "request_fixture", NameKey: "request_fixture", PasswordHash: "fixture", Quota: 16 * 1024 * 1024}
	audit := store.KaraokeAudit{IP: "192.0.2.175"}
	if err := db.Karaoke().RegisterUser(ctx, user, audit.IP, "20261001", audit); err != nil {
		t.Fatal(err)
	}
	repo, ok := db.Recordings().(store.RecordingRequestRepository)
	if !ok {
		t.Fatal("recording request repository unavailable")
	}
	request := strings.Repeat("e", 32)
	key := bytes.Repeat([]byte{7}, 32)
	body := []byte(`{"title":"private fixture","size_bytes":1024,"content_type":"audio/webm"}`)
	const workers = 8
	ids := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() {
			v := store.Recording{ID: fmt.Sprintf("%032x", i+1), UserID: user.ID, Filename: "fixture.webm", ContentType: "audio/webm", Bytes: 1024, Title: "private fixture"}
			got, member, err := repo.ReserveRecordingRequest(ctx, request, body, key, v, 10*store.GiB, audit)
			if err != nil {
				errs <- err
				return
			}
			if member.ID != identity.ID {
				errs <- fmt.Errorf("wrong owner")
				return
			}
			ids <- got.ID
		})
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Error("concurrent reserve", err)
	}
	if t.Failed() {
		return
	}
	var original string
	count := 0
	for id := range ids {
		if original == "" {
			original = id
		}
		if id != original {
			t.Fatal("duplicate request created another reservation")
		}
		count++
	}
	if count != workers {
		t.Fatal("not all requests completed", count)
	}
	var used, reserved int64
	if err := raw.QueryRow("SELECT used_bytes FROM karaoke_users WHERE user_id=?", user.ID).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", identity.ID).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if used != 1024 || reserved != 1024 {
		t.Fatal("quota charged more than once", used, reserved)
	}
	lookup, err := repo.LookupRecordingRequest(ctx, user.ID, request, key)
	if err != nil || lookup.ID != original || lookup.State != "pending" {
		t.Fatal("recovery", lookup.ID, lookup.State, err)
	}
	other := business.New(raw, db.Backend())
	if recovered, err := other.LookupRecordingRequest(ctx, user.ID, request, key); err != nil || recovered.ID != original {
		t.Fatal("fresh repository did not recover intent", recovered.ID, err)
	}
	var requestMAC, recordMAC, bindingMAC string
	if err := raw.QueryRow("SELECT request_mac,record_mac,binding_mac FROM recording_request_intents WHERE user_id=? AND request_id=?", user.ID, request).Scan(&requestMAC, &recordMAC, &bindingMAC); err != nil {
		t.Fatal(err)
	}
	plainHash := sha256.Sum256(body)
	if requestMAC == hex.EncodeToString(plainHash[:]) || strings.Contains(requestMAC+recordMAC+bindingMAC, "private fixture") {
		t.Fatal("request stored without keyed protection")
	}
	changed := store.Recording{ID: strings.Repeat("f", 32), UserID: user.ID, Filename: "fixture.webm", ContentType: "audio/webm", Bytes: 1024, Title: "private fixture"}
	if _, _, err := repo.ReserveRecordingRequest(ctx, request, append(body, ' '), key, changed, 10*store.GiB, audit); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("changed request accepted", err)
	}
	if _, err := repo.LookupRecordingRequest(ctx, user.ID, request, bytes.Repeat([]byte{8}, 32)); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("wrong key accepted", err)
	}
	conflict := changed
	conflict.ID = original
	if _, _, err := repo.ReserveRecordingRequest(ctx, strings.Repeat("f", 32), body, key, conflict, 10*store.GiB, audit); err == nil {
		t.Fatal("duplicate recording identity accepted")
	}
	if err := raw.QueryRow("SELECT used_bytes FROM karaoke_users WHERE user_id=?", user.ID).Scan(&used); err != nil || used != 1024 {
		t.Fatal("failed transaction changed quota", used, err)
	}
	failingRequest := strings.Repeat("c", 32)
	failureDDL := `CREATE TRIGGER request_intent_fault BEFORE INSERT ON recording_request_intents WHEN NEW.request_id='` + failingRequest + `' BEGIN SELECT RAISE(ABORT,'injected intent failure'); END`
	dropFailure := `DROP TRIGGER request_intent_fault`
	if db.Backend() == "mysql" {
		failureDDL = `ALTER TABLE recording_request_intents ADD CONSTRAINT request_intent_fault CHECK (request_id <> '` + failingRequest + `')`
		dropFailure = `ALTER TABLE recording_request_intents DROP CHECK request_intent_fault`
	}
	if _, err := raw.Exec(failureDDL); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ReserveRecordingRequest(ctx, failingRequest, body, key, changed, 10*store.GiB, audit); err == nil {
		t.Fatal("injected intent failure committed")
	}
	if _, err := raw.Exec(dropFailure); err != nil {
		t.Fatal(err)
	}
	var leaked int
	if err := raw.QueryRow("SELECT COUNT(*) FROM karaoke_recordings WHERE recording_id=?", changed.ID).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("reservation escaped intent rollback", leaked, err)
	}
	if err := raw.QueryRow("SELECT used_bytes FROM karaoke_users WHERE user_id=?", user.ID).Scan(&used); err != nil || used != 1024 {
		t.Fatal("intent failure leaked quota", used, err)
	}
	if _, err := raw.Exec("UPDATE karaoke_recordings SET title=? WHERE recording_id=?", "tampered", original); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.LookupRecordingRequest(ctx, user.ID, request, key); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("modified pending recording accepted", err)
	}
	if _, err := raw.Exec("UPDATE karaoke_recordings SET title=? WHERE recording_id=?", "private fixture", original); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("UPDATE karaoke_recordings SET updated_at=? WHERE recording_id=?", time.Now().Unix()-7200, original); err != nil {
		t.Fatal(err)
	}
	if err := repo.StageExpiredLegacyRecordings(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if protected, err := db.Recordings().Recording(ctx, original); err != nil || protected == nil || protected.State != "pending" {
		t.Fatal("protected request expired", protected, err)
	}
	if _, err := raw.Exec("UPDATE karaoke_recordings SET request_protected=0 WHERE recording_id=?", original); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.LookupRecordingRequest(ctx, user.ID, request, key); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("missing marker accepted", err)
	}
	if err := repo.StageExpiredLegacyRecordings(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if protected, err := db.Recordings().Recording(ctx, original); err != nil || protected == nil || protected.State != "pending" {
		t.Fatal("ambiguous request expired", protected, err)
	}
	if _, err := raw.Exec("UPDATE karaoke_recordings SET request_protected=1 WHERE recording_id=?", original); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("UPDATE karaoke_recordings SET request_protected=0,request_id=NULL WHERE recording_id=?", original); err != nil {
		t.Fatal(err)
	}
	if err := repo.StageExpiredLegacyRecordings(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if protected, err := db.Recordings().Recording(ctx, original); err != nil || protected == nil || protected.State != "pending" {
		t.Fatal("surviving intent failed to protect ambiguous reservation", protected, err)
	}
	if _, err := raw.Exec("UPDATE karaoke_recordings SET request_protected=1,request_id=? WHERE recording_id=?", request, original); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("UPDATE karaoke_users SET used_bytes=0 WHERE user_id=?", user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.LookupRecordingRequest(ctx, user.ID, request, key); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("inconsistent user quota accepted", err)
	}
	if _, err := raw.Exec("UPDATE karaoke_users SET used_bytes=1024 WHERE user_id=?", user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("UPDATE cluster_storage_members SET reserved_bytes=0 WHERE member_id=?", identity.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.LookupRecordingRequest(ctx, user.ID, request, key); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("inconsistent owner quota accepted", err)
	}
	if _, err := raw.Exec("UPDATE cluster_storage_members SET reserved_bytes=1024 WHERE member_id=?", identity.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("UPDATE recording_request_intents SET binding_mac=? WHERE user_id=? AND request_id=?", strings.Repeat("0", 64), user.ID, request); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.LookupRecordingRequest(ctx, user.ID, request, key); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("modified intent accepted", err)
	}
	if _, err := raw.Exec("UPDATE recording_request_intents SET binding_mac=? WHERE user_id=? AND request_id=?", bindingMAC, user.ID, request); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("DELETE FROM recording_request_intents WHERE user_id=? AND request_id=?", user.ID, request); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ReserveRecordingRequest(ctx, request, body, key, changed, 10*store.GiB, audit); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("orphan reservation allowed duplicate", err)
	}
	if _, err := repo.LookupRecordingRequest(ctx, user.ID, request, key); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("orphan reservation misreported missing", err)
	}
	if _, err := raw.Exec(`INSERT INTO recording_request_intents(user_id,request_id,request_mac,recording_id,owner_id,record_mac,binding_mac,created_at) VALUES(?,?,?,?,?,?,?,?)`, user.ID, request, requestMAC, original, identity.ID, recordMAC, bindingMAC, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Recordings().StageRecordingDeletion(ctx, user.ID, original, true, audit); err != nil {
		t.Fatal(err)
	}
	if err := db.Recordings().CompleteRecordingDeletion(ctx, user.ID, original, audit); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ReserveRecordingRequest(ctx, request, body, key, changed, 10*store.GiB, audit); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("tombstone replay recreated reservation", err)
	}
	if err := raw.QueryRow("SELECT used_bytes FROM karaoke_users WHERE user_id=?", user.ID).Scan(&used); err != nil || used != 0 {
		t.Fatal("quota not released after confirmed deletion", used, err)
	}
	for _, id := range []string{strings.Repeat("a", 32), strings.Repeat("b", 32)} {
		if _, _, err := db.Recordings().ReserveRecording(ctx, store.Recording{ID: id, UserID: user.ID, Filename: "old.webm", ContentType: "audio/webm", Bytes: 10}, 10*store.GiB, audit); err != nil {
			t.Fatal("old NULL request id reservation", err)
		}
	}
	var legacyCount int
	if err := raw.QueryRow("SELECT COUNT(*) FROM karaoke_recordings WHERE user_id=? AND request_id IS NULL AND request_protected=0", user.ID).Scan(&legacyCount); err != nil || legacyCount != 2 {
		t.Fatal("legacy nullable uniqueness", legacyCount, err)
	}
	if _, err := raw.Exec("UPDATE karaoke_recordings SET updated_at=? WHERE user_id=? AND request_id IS NULL", time.Now().Unix()-7200, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.StageExpiredLegacyRecordings(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRow("SELECT COUNT(*) FROM karaoke_recordings WHERE user_id=? AND request_id IS NULL AND state='deleting'", user.ID).Scan(&legacyCount); err != nil || legacyCount != 2 {
		t.Fatal("legacy expiry changed", legacyCount, err)
	}
	readyRequest := strings.Repeat("1", 32)
	readyInput := store.Recording{ID: strings.Repeat("2", 32), UserID: user.ID, Filename: "ready.webm", ContentType: "audio/webm", Bytes: 1024, Title: "private fixture"}
	ready, _, err := repo.ReserveRecordingRequest(ctx, readyRequest, body, key, readyInput, 10*store.GiB, audit)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Recordings().FinalizeRecording(ctx, user.ID, ready.ID, store.RecordingReceipt{ID: ready.ID, Bytes: 1024, SHA256: strings.Repeat("3", 64)}, audit); err != nil {
		t.Fatal(err)
	}
	if recovered, err := repo.LookupRecordingRequest(ctx, user.ID, readyRequest, key); err != nil || recovered.State != "ready" || recovered.ID != ready.ID {
		t.Fatal("completed request recovery", recovered.ID, recovered.State, err)
	}
	if replay, _, err := repo.ReserveRecordingRequest(ctx, readyRequest, body, key, readyInput, 10*store.GiB, audit); err != nil || replay.State != "ready" || replay.ID != ready.ID {
		t.Fatal("completed request recreated", replay.ID, replay.State, err)
	}
}
