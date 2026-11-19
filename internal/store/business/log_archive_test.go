package business_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestLogActivationPreservesSecurityAndTransactionalAudits(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	sqlDB := db.(interface{ Database() *sql.DB }).Database()
	key, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	catalog, e := logarchive.SharedCatalog(sqlDB, key, strings.Repeat("a", 32))
	if e != nil {
		t.Fatal(e)
	}
	db.Pool().(interface{ ConfigureLogArchive(*logarchive.Catalog) }).ConfigureLogArchive(catalog)
	ip := "198.51.100.73"
	for range 2 {
		if _, e = db.Security().RecordInvalidAPI(ctx, ip, "GET", "/preactivation", "test-agent", 3, 3600, store.AdminAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = catalog.Configure(ctx, logarchive.Target{MemberID: strings.Repeat("b", 32), RelationshipID: strings.Repeat("c", 32), Origin: "https://log.test"}, 0); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, e = db.Security().RecordInvalidAPI(ctx, ip, "GET", "/new-private-marker", "test-agent", 3, 3600, store.AdminAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	ban, e := db.Security().IPBlock(ctx, ip)
	if e != nil || ban == nil {
		t.Fatal("activation reset the existing ban window", e)
	}
	var legacy int
	if e = sqlDB.QueryRow("SELECT COUNT(*) FROM ip_security_audit_log WHERE detail LIKE '%new-private-marker%'").Scan(&legacy); e != nil || legacy != 0 {
		t.Fatal("new security body entered plaintext audit", e)
	}
	if e = db.Admin().AppendAudit(ctx, store.AdminAudit{Action: "new_private_action", SourceSummary: "private-file-name-marker", Detail: "private-detail-marker", Result: "success"}); e != nil {
		t.Fatal(e)
	}
	if e = sqlDB.QueryRow("SELECT COUNT(*) FROM admin_audit_log WHERE action='new_private_action'").Scan(&legacy); e != nil || legacy != 0 {
		t.Fatal("new Admin body entered plaintext audit", e)
	}
	if e = db.Observations().RecordObservations(ctx, ip, []string{"192.0.2.1"}, "accepted"); e != nil {
		t.Fatal(e)
	}
	now := time.Now().Add(time.Millisecond)
	for _, kind := range []logarchive.Kind{logarchive.Security, logarchive.Audit, logarchive.WebRTC} {
		entries, _, e := catalog.Query(ctx, now.Add(-time.Hour), now, now, kind, false, "")
		if e != nil || len(entries) == 0 {
			t.Fatal("producer absent", kind, e)
		}
	}
	// Archive failure cannot leave a committed business mutation without audit.
	sqlDB.Exec("UPDATE log_budget SET used_bytes=134217728 WHERE id=1")
	if _, e = db.Security().SetIPPolicy(ctx, "198.51.100.99", "whitelist", "must-rollback", store.AdminAudit{}); e == nil {
		t.Fatal("audit admission failure ignored")
	}
	var whitelist int
	if e = sqlDB.QueryRow("SELECT COUNT(*) FROM ip_permanent_whitelist WHERE ip_address='198.51.100.99'").Scan(&whitelist); e != nil || whitelist != 0 {
		t.Fatal("business transaction escaped audit rollback", e)
	}
}
