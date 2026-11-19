package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	_ "modernc.org/sqlite"
)

func TestSelectedOpaqueReservationPinsPolicyAndRollsBackAtomically(t *testing.T) {
	ctx := context.Background()
	file := filepath.ToSlash(filepath.Join(t.TempDir(), "selected.db"))
	if !strings.HasPrefix(file, "/") {
		file = "/" + file
	}
	uri := &url.URL{Scheme: "file", Path: file}
	query := uri.Query()
	query.Set("_busy_timeout", "5000")
	query.Set("_journal_mode", "WAL")
	query.Set("_synchronous", "NORMAL")
	uri.RawQuery = query.Encode()
	backend, driver, dsn := "sqlite", "sqlite", uri.String()
	if host := os.Getenv("FRONTIERCLOUD_TEST_MYSQL_HOST"); host != "" {
		if host != "mysql-fixture" || !strings.HasPrefix(os.Getenv("FRONTIERCLOUD_TEST_MYSQL_DATABASE"), "fc_business_") {
			t.Fatal("isolated MySQL fixture host and database required")
		}
		password, err := os.ReadFile(os.Getenv("FRONTIERCLOUD_TEST_MYSQL_PASSWORD_FILE"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := mysqldriver.NewConfig()
		cfg.Net, cfg.Addr, cfg.DBName = "tcp", net.JoinHostPort(host, "3306"), os.Getenv("FRONTIERCLOUD_TEST_MYSQL_DATABASE")
		cfg.User, cfg.Passwd, cfg.ParseTime = os.Getenv("FRONTIERCLOUD_TEST_MYSQL_USER"), strings.TrimSpace(string(password)), true
		backend, driver, dsn = "mysql", "mysql", cfg.FormatDSN()
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	defer db.Close()
	if err = schema.Initialize(ctx, db, backend); err != nil {
		t.Fatal(err)
	}
	r := New(db, backend)
	master, owner, relID := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	if _, err = r.InitializeIdentity(ctx, store.NodeIdentity{ID: master, Role: "Standalone", PrivateKey: "sealed-fixture", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 5 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = r.ConfigurePublicOrigin("https://master.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.PublicIngress(ctx); err != nil {
		t.Fatal(err)
	}
	relation := store.Relationship{ID: relID, PeerID: owner, Endpoint: "https://owner-control.test", PublicKey: protocol.Encode(bytes.Repeat([]byte{4}, 32)), Credential: "sealed-fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: time.Now().Unix()}
	if err = r.PrepareRelationship(ctx, relation, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = r.ActivateRelationship(ctx, relID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	cfg := store.ResourceConfiguration{}
	cfg.Storage.Enabled, cfg.Storage.Allocation = true, 3*store.GiB
	if err = r.ConfigureMember(ctx, owner, cfg, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	summary := map[string]any{"native_resource_origin": "https://owner-resource.test", "storage": map[string]any{"physical_free_bytes": 10 * store.GiB}}
	if err = r.RecordHeartbeat(ctx, relID, true, 1, summary, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ConfirmNativeTransport(ctx, owner, "Direct", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = r.RecordNativeDirectApplication(ctx, relID, 1, "https://owner-resource.test"); err != nil {
		t.Fatal(err)
	}
	otherOwner, otherRel := strings.Repeat("6", 32), strings.Repeat("7", 32)
	other := relation
	other.ID, other.PeerID, other.Endpoint = otherRel, otherOwner, "https://other-control.test"
	other.PublicKey = protocol.Encode(bytes.Repeat([]byte{5}, 32))
	if err = r.PrepareRelationship(ctx, other, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = r.ActivateRelationship(ctx, otherRel, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = r.ConfigureMember(ctx, otherOwner, cfg, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	otherSummary := map[string]any{"native_resource_origin": "https://other-resource.test", "storage": map[string]any{"physical_free_bytes": 10 * store.GiB}}
	if err = r.RecordHeartbeat(ctx, otherRel, true, 1, otherSummary, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ConfirmNativeTransport(ctx, otherOwner, "Direct", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = r.RecordNativeDirectApplication(ctx, otherRel, 1, "https://other-resource.test"); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err = r.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	intent := OpaqueCapacityIntent{OperationID: strings.Repeat("a", 64), MasterID: master, MemberID: owner, BlobID: strings.Repeat("b", 64), Digest: strings.Repeat("c", 64), Bytes: store.GiB}
	upload, parent, binding, origin := strings.Repeat("4", 32), strings.Repeat("f", 64), strings.Repeat("5", 64), "https://owner-resource.test"
	reserve := func(v OpaqueCapacityIntent, session string, revision int64, endpoint string) (bool, error) {
		return r.reserveSelectedOpaqueCapacity(ctx, key, v, upload, parent, session, revision, endpoint, 10*store.GiB, strings.Repeat("c", 64))
	}
	trigger := `CREATE TRIGGER fail_selected_reserve BEFORE UPDATE OF reserved_bytes ON cluster_storage_members BEGIN SELECT RAISE(ABORT,'capacity-fault'); END`
	if backend == "mysql" {
		trigger = `CREATE TRIGGER fail_selected_reserve BEFORE UPDATE ON cluster_storage_members FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='capacity-fault'`
	}
	if _, err = db.Exec(trigger); err != nil {
		t.Fatal(err)
	}
	if _, err = reserve(intent, binding, 1, origin); err == nil {
		t.Fatal("injected capacity failure accepted")
	}
	for _, table := range []string{"selected_upload_intents", "selected_upload_parent_scopes", "sealed_tree_capacity_intents", "sealed_tree_capacity_ids"} {
		var n int
		if err = db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("failed transaction left durable state", table, n, err)
		}
	}
	if _, err = db.Exec(`DROP TRIGGER fail_selected_reserve`); err != nil {
		t.Fatal(err)
	}
	if already, err := reserve(intent, binding, 1, origin); err != nil || already {
		t.Fatal("selected reservation rejected", already, err)
	}
	if already, err := reserve(intent, binding, 1, origin); err != nil || !already {
		t.Fatal("identical retry charged twice", already, err)
	}
	// A caller that lost the response must look up the committed upload ID
	// under the writer fence, not blindly issue a new operation.
	if err = r.ingressWrite(ctx, func(q queryer) error {
		recovered, found, e := r.recoverSelectedOpaqueCapacityTx(ctx, q, key, upload)
		if e != nil || !found || recovered.Capacity.capacity() != intent || recovered.ParentID != parent || recovered.AdminBinding != binding {
			return errors.New("committed reservation did not recover")
		}
		_, found, e = r.recoverSelectedOpaqueCapacityTx(ctx, q, key, strings.Repeat("f", 32))
		if e != nil || found {
			return errors.New("missing upload recovered")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("selected operation was accepted as a generic import", err)
	}
	if _, _, err = r.BindOpaqueCapacityScope(ctx, key, intent.OperationID, strings.Repeat("d", 64), strings.Repeat("e", 64)); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("selected operation was rebound to a migration scope", err)
	}
	for name, v := range map[string]struct {
		intent   OpaqueCapacityIntent
		binding  string
		revision int64
		origin   string
	}{
		"owner":          {OpaqueCapacityIntent{OperationID: intent.OperationID, MasterID: master, MemberID: master, BlobID: intent.BlobID, Digest: intent.Digest, Bytes: intent.Bytes}, binding, 1, origin},
		"other-follower": {OpaqueCapacityIntent{OperationID: intent.OperationID, MasterID: master, MemberID: otherOwner, BlobID: intent.BlobID, Digest: intent.Digest, Bytes: intent.Bytes}, binding, 1, "https://other-resource.test"},
		"session":        {intent, strings.Repeat("6", 64), 1, origin},
		"revision":       {intent, binding, 2, origin},
		"origin":         {intent, binding, 1, "https://other.test"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := reserve(v.intent, v.binding, v.revision, v.origin); !errors.Is(err, store.ErrNodeState) {
				t.Fatal("changed owner/session/policy accepted", err)
			}
		})
	}
	var used, count int64
	if err = db.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&used); err != nil || used != intent.Bytes {
		t.Fatal("selected capacity changed on retry", used, err)
	}
	if err = db.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", otherOwner).Scan(&used); err != nil || used != 0 {
		t.Fatal("rejected owner change modified other follower", used, err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM selected_upload_intents").Scan(&count); err != nil || count != 1 {
		t.Fatal("selected intent count", count, err)
	}
	otherIntent := intent
	otherIntent.OperationID, otherIntent.BlobID, otherIntent.MemberID, otherIntent.Bytes = strings.Repeat("d", 64), strings.Repeat("e", 64), otherOwner, 1
	if _, err = r.reserveSelectedOpaqueCapacity(ctx, key, otherIntent, strings.Repeat("8", 32), parent, binding, 1, "https://other-resource.test", 10*store.GiB, strings.Repeat("c", 64)); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("same-folder pending owner split accepted", err)
	}
	otherIntent.MemberID = owner
	if already, err := r.reserveSelectedOpaqueCapacity(ctx, key, otherIntent, strings.Repeat("8", 32), parent, binding, 1, origin, 10*store.GiB, strings.Repeat("c", 64)); err != nil || already {
		t.Fatal("same-owner pending sibling rejected", err)
	}
	if err = db.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&used); err != nil || used != intent.Bytes+1 {
		t.Fatal("same-folder capacity mismatch", used, err)
	}
	var sealed []byte
	var storedParent string
	if err = db.QueryRow("SELECT parent_index,sealed FROM selected_upload_intents WHERE operation_index=?", opaqueCapacityIndex(key, intent.OperationID)).Scan(&storedParent, &sealed); err != nil || storedParent == parent || bytes.Contains(sealed, []byte(parent)) || bytes.Contains(sealed, []byte(origin)) || bytes.Contains(sealed, []byte(binding)) || bytes.Contains(sealed, []byte(owner)) {
		t.Fatal("selected intent leaked metadata", err)
	}
	// A verified per-parent scope allows a large number of siblings without
	// repeatedly decrypting the entire pending set under the global fence.
	for i := 0; i < 50; i++ {
		v := intent
		v.OperationID, v.BlobID, v.Bytes = fmt.Sprintf("%064x", i+100), fmt.Sprintf("%064x", i+1000), 1
		started := time.Now()
		if already, e := r.reserveSelectedOpaqueCapacity(ctx, key, v, fmt.Sprintf("%032x", i+100), parent, binding, 1, origin, 10*store.GiB, strings.Repeat("c", 64)); e != nil || already {
			t.Fatal("scope fixture reservation", i, already, e)
		}
		if i == 49 {
			t.Logf("reservation with 51 pending records elapsed: %s (end-to-end, not fence duration)", time.Since(started))
		}
	}
	if already, e := reserve(intent, binding, 1, origin); e != nil || !already {
		t.Fatal("scope retry was not idempotent", already, e)
	}
	for _, mode := range []string{"valid", "missing-child", "missing-scope", "bad-intent"} {
		t.Run("maintenance-audit-"+mode, func(t *testing.T) {
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			switch mode {
			case "missing-child":
				_, e = tx.ExecContext(ctx, "DELETE FROM selected_upload_intents WHERE operation_index=?", opaqueCapacityIndex(key, intent.OperationID))
			case "missing-scope":
				_, e = tx.ExecContext(ctx, "DELETE FROM selected_upload_parent_scopes WHERE parent_index=?", selectedParentIndex(key, parent))
			case "bad-intent":
				_, e = tx.ExecContext(ctx, "UPDATE selected_upload_intents SET sealed=? WHERE operation_index=?", []byte("corrupt"), opaqueCapacityIndex(key, intent.OperationID))
			}
			if e != nil {
				t.Fatal(e)
			}
			e = r.auditSelectedScopesMaintenanceOnly(ctx, tx, key)
			if mode == "valid" && e != nil || mode != "valid" && !errors.Is(e, store.ErrNodeState) {
				t.Fatal("unexpected audit result", mode, e)
			}
		})
	}
	var beforeCorruption int64
	if err = db.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&beforeCorruption); err != nil {
		t.Fatal(err)
	}
	var scopeCipher []byte
	parentIndex := selectedParentIndex(key, parent)
	if err = db.QueryRow("SELECT sealed FROM selected_upload_parent_scopes WHERE parent_index=?", parentIndex).Scan(&scopeCipher); err != nil {
		t.Fatal(err)
	}
	badScope := bytes.Clone(scopeCipher)
	badScope[len(badScope)-1] ^= 1
	if _, err = db.Exec("UPDATE selected_upload_parent_scopes SET sealed=? WHERE parent_index=?", badScope, parentIndex); err != nil {
		t.Fatal(err)
	}
	if _, err = reserve(intent, binding, 1, origin); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("tampered scope accepted", err)
	}
	if _, err = db.Exec("UPDATE selected_upload_parent_scopes SET sealed=? WHERE parent_index=?", scopeCipher, parentIndex); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&used); err != nil || used != beforeCorruption {
		t.Fatal("scope corruption changed reservation", used, beforeCorruption, err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	concurrentParent := strings.Repeat("c", 64)
	for _, item := range []struct{ member, operation, blob, id, endpoint string }{
		{owner, strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("1", 32), origin},
		{otherOwner, strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("2", 32), "https://other-resource.test"},
	} {
		wg.Add(1)
		go func(v struct{ member, operation, blob, id, endpoint string }) {
			defer wg.Done()
			<-start
			candidate := intent
			candidate.MemberID, candidate.OperationID, candidate.BlobID, candidate.Bytes = v.member, v.operation, v.blob, 1
			_, err := r.reserveSelectedOpaqueCapacity(ctx, key, candidate, v.id, concurrentParent, binding, 1, v.endpoint, 10*store.GiB, strings.Repeat("c", 64))
			results <- err
		}(item)
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded, conflicted := 0, 0
	for result := range results {
		if result == nil {
			succeeded++
		} else if errors.Is(result, store.ErrNodeState) {
			conflicted++
		} else {
			t.Fatal("unexpected concurrent reservation error", result)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("same-parent race split owners: success=%d conflict=%d", succeeded, conflicted)
	}
	if _, err = r.ConfirmNativeTransport(ctx, owner, "Relay", 1, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err = reserve(intent, binding, 1, origin); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("superseded policy accepted", err)
	}
}

func TestSelectedPendingBindingCoversEncryptionDescriptor(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	metadata, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := protocol.IngressMediaDescriptor(metadata.CiphertextSize, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	pending := sealedtree.SelectedPending{OperationID: strings.Repeat("1", 64), ObjectID: strings.Repeat("2", 64), ParentID: strings.Repeat("3", 64), Name: "fixture.mp3", Placement: sealedtree.Placement{ObjectID: strings.Repeat("2", 64), OwnerID: strings.Repeat("4", 32), BlobID: strings.Repeat("5", 64), ReadAlias: strings.Repeat("6", 64), Bytes: metadata.CiphertextSize, SHA256: strings.Repeat("7", 64), Encryption: &metadata}, Admission: sealedtree.SelectedUploadFact{UploadID: strings.Repeat("8", 32), AdminBinding: strings.Repeat("9", 64), Policy: "Direct", Revision: 1, Origin: "https://owner.test"}, Descriptor: descriptor}
	original, err := selectedPendingBinding(key, pending)
	if err != nil {
		t.Fatal(err)
	}
	selected := selectedOpaqueIntent{Capacity: selectedCapacityFrom(OpaqueCapacityIntent{OperationID: pending.OperationID, MasterID: strings.Repeat("a", 32), MemberID: pending.Placement.OwnerID, BlobID: pending.Placement.BlobID, Digest: pending.Placement.SHA256, Bytes: pending.Placement.Bytes}), UploadID: pending.Admission.UploadID, ParentID: pending.ParentID, AdminBinding: pending.Admission.AdminBinding, Policy: pending.Admission.Policy, Revision: pending.Admission.Revision, OriginBinding: selectedOriginBinding(key, pending.Admission.Origin), PendingBinding: original}
	if err = verifySelectedPendingBinding(key, selected, pending); err != nil {
		t.Fatal("valid pending binding rejected", err)
	}
	other, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	changed := pending
	changed.Placement.Encryption = &other
	if _, err = selectedPendingBinding(key, changed); err == nil {
		t.Fatal("descriptor mismatch accepted")
	}
	changed.Descriptor, err = protocol.IngressMediaDescriptor(other.CiphertextSize, &other)
	if err != nil {
		t.Fatal(err)
	}
	newBinding, err := selectedPendingBinding(key, changed)
	if err != nil || newBinding == original {
		t.Fatal("different encryption descriptor not bound", err)
	}
	if err = verifySelectedPendingBinding(key, selected, changed); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("changed descriptor recovered", err)
	}
}

func TestSelectedOpaqueIntentFitsEncryptedRecordAtDNSLengthLimit(t *testing.T) {
	name := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}, ".")
	if len(name) != 253 {
		t.Fatal("fixture is not a maximal DNS name")
	}
	v := selectedOpaqueIntent{Capacity: selectedCapacityFrom(OpaqueCapacityIntent{OperationID: strings.Repeat("1", 64), MasterID: strings.Repeat("2", 32), MemberID: strings.Repeat("3", 32), BlobID: strings.Repeat("4", 64), Digest: strings.Repeat("5", 64), Bytes: 10 * store.GiB}), UploadID: strings.Repeat("6", 32), ParentID: strings.Repeat("b", 64), AdminBinding: strings.Repeat("7", 64), Policy: "Direct", Revision: int64(^uint64(0) >> 1), OriginBinding: strings.Repeat("b", 64), PendingBinding: strings.Repeat("c", 64), MasterBinding: strings.Repeat("8", 64), RelationshipID: strings.Repeat("9", 32), RelationshipBinding: strings.Repeat("a", 64)}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	index := opaqueCapacityIndex(key, v.Capacity.OperationID)
	id, sealed, err := sealCapacityRecord(key, index, raw)
	if err != nil {
		t.Fatal("valid maximum DNS name cannot be recorded", len(raw), err)
	}
	opened, err := openCapacityRecord(key, index, id, sealed)
	if err != nil || !bytes.Equal(opened, raw) {
		t.Fatal("maximum-length record failed to authenticate", err)
	}
}
