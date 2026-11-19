package business_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestLegacyEnrollmentIntentPinsOwnerAndRecoversAtomically(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	master, owner, relationship := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	v, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	key, _ := v.Seal(protocol.Encode(bytes.Repeat([]byte{8}, 32)))
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: master, Role: "Standalone", PrivateKey: key, CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	identity, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	ownerSeed := protocol.Encode(bytes.Repeat([]byte{9}, 32))
	ownerPublic, _ := protocol.PublicKey(ownerSeed)
	rel := store.Relationship{ID: relationship, PeerID: owner, Endpoint: "https://owner.test", PublicKey: ownerPublic, Credential: "fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: time.Now().Unix()}
	if err = db.Nodes().PrepareRelationship(ctx, rel, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = db.Nodes().ActivateRelationship(ctx, relationship, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(*business.Repository)
	if _, found, e := repo.FindCurrentLegacyReadControl(ctx, identity, v, relationship); e != nil || found {
		t.Fatal("new pair has phantom head", e)
	}
	operation, challenge := strings.Repeat("a", 32), strings.Repeat("b", 64)
	expiry := time.Now().Unix() + 20
	headIndex, _, err := v.LegacyReadHeadIndexes(relationship)
	if err != nil {
		t.Fatal(err)
	}
	headFault := `CREATE TRIGGER fail_legacy_head BEFORE INSERT ON legacy_read_control_intents WHEN NEW.operation_index='` + headIndex + `' BEGIN SELECT RAISE(ABORT,'legacy-head-fault'); END`
	if db.Backend() == "mysql" {
		headFault = `CREATE TRIGGER fail_legacy_head BEFORE INSERT ON legacy_read_control_intents FOR EACH ROW BEGIN IF NEW.operation_index='` + headIndex + `' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='legacy-head-fault'; END IF; END`
	}
	if _, err = raw.Exec(headFault); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.BeginLegacyReadEnrollment(ctx, identity, v, relationship, operation, challenge, expiry); err == nil || !strings.Contains(err.Error(), "legacy-head-fault") {
		t.Fatal("head failure not observed", err)
	}
	if _, err = raw.Exec(`DROP TRIGGER fail_legacy_head`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = raw.QueryRow(`SELECT COUNT(*) FROM legacy_read_control_intents`).Scan(&count); err != nil || count != 0 {
		t.Fatal("intent/head partially committed", count, err)
	}
	var beginWG sync.WaitGroup
	beginErrors := make(chan error, 8)
	for range 8 {
		beginWG.Add(1)
		go func() {
			defer beginWG.Done()
			pending, e := repo.BeginLegacyReadEnrollment(ctx, identity, v, relationship, operation, challenge, expiry)
			if e != nil {
				beginErrors <- e
			} else if pending.State != "pending" {
				beginErrors <- errors.New("unexpected begin state")
			}
		}()
	}
	beginWG.Wait()
	close(beginErrors)
	for e := range beginErrors {
		t.Fatal("concurrent begin", e)
	}
	if _, err = repo.BeginLegacyReadEnrollment(ctx, identity, v, relationship, operation, challenge, expiry); err != nil {
		t.Fatal("begin retry", err)
	}
	if current, e := repo.CurrentLegacyReadControl(ctx, identity, v, relationship); e != nil || current.Enrollment.OperationID != operation || current.Drain != nil || current.Status != nil {
		t.Fatal("initial current head", e)
	}
	if _, err = repo.BeginLegacyReadEnrollment(ctx, identity, v, relationship, strings.Repeat("c", 32), challenge, expiry); err == nil {
		t.Fatal("challenge reused")
	}
	idx, _, err := v.LegacyReadIntentIndexes(operation, challenge)
	if err != nil {
		t.Fatal(err)
	}
	var storedIndex, tag string
	var nonce, sealed []byte
	if err = raw.QueryRow(`SELECT operation_index,challenge_tag,nonce,sealed FROM legacy_read_control_intents WHERE operation_index=?`, idx).Scan(&storedIndex, &tag, &nonce, &sealed); err != nil {
		t.Fatal(err)
	}
	if idx != storedIndex || strings.Contains(idx, operation) || strings.Contains(tag, challenge) || bytes.Contains(sealed, []byte(operation)) || bytes.Contains(sealed, []byte(challenge)) || len(nonce) != 12 {
		t.Fatal("intent leaked or nonce invalid")
	}
	receipt := protocol.LegacyReadEnrollmentReceipt{Kind: "legacy-media-enrollment-v1", Challenge: challenge, MasterID: master, OwnerID: owner, RelationshipID: relationship, RelationshipBinding: strings.Repeat("4", 64), OwnerBinding: strings.Repeat("5", 64), FenceBinding: strings.Repeat("6", 64), State: "active"}
	payload, _ := receipt.Payload()
	sig, _ := protocol.Sign(ownerSeed, payload)
	if _, err = repo.ConfirmLegacyReadEnrollment(ctx, identity, v, operation, receipt, sig+"x"); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("bad signature accepted", err)
	}
	bad := receipt
	bad.OwnerID = strings.Repeat("7", 32)
	badPayload, _ := bad.Payload()
	badSig, _ := protocol.Sign(ownerSeed, badPayload)
	if _, err = repo.ConfirmLegacyReadEnrollment(ctx, identity, v, operation, bad, badSig); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong owner accepted", err)
	}
	trigger := `CREATE TRIGGER fail_legacy_enrollment BEFORE UPDATE ON legacy_read_control_intents BEGIN SELECT RAISE(ABORT,'legacy-enrollment-fault'); END`
	if db.Backend() == "mysql" {
		trigger = `CREATE TRIGGER fail_legacy_enrollment BEFORE UPDATE ON legacy_read_control_intents FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='legacy-enrollment-fault'`
	}
	if _, err = raw.Exec(trigger); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ConfirmLegacyReadEnrollment(ctx, identity, v, operation, receipt, sig); err == nil || !strings.Contains(err.Error(), "legacy-enrollment-fault") {
		t.Fatal("fault not observed", err)
	}
	if _, err = raw.Exec(`DROP TRIGGER fail_legacy_enrollment`); err != nil {
		t.Fatal(err)
	}
	old, fresh, err := repo.RecoverLegacyReadEnrollment(ctx, identity, v, relationship, operation, challenge)
	if err != nil || fresh || old.State != "pending" {
		t.Fatal("rollback recovery", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			confirmed, e := repo.ConfirmLegacyReadEnrollment(ctx, identity, v, operation, receipt, sig)
			if e != nil {
				errs <- e
			} else if confirmed.State != "confirmed" {
				errs <- errors.New("unexpected confirmation state")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal("concurrent confirmation", e)
	}
	if _, err = repo.ConfirmLegacyReadEnrollment(ctx, identity, v, operation, receipt, sig); err != nil {
		t.Fatal("receipt retry", err)
	}
	drainOperation, drainChallenge := strings.Repeat("c", 32), strings.Repeat("d", 64)
	if _, err = repo.BeginLegacyReadDrain(ctx, identity, v, relationship, operation, challenge, drainOperation, challenge); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("drain reused enrollment challenge", err)
	}
	drain, err := repo.BeginLegacyReadDrain(ctx, identity, v, relationship, operation, challenge, drainOperation, drainChallenge)
	if err != nil || drain.State != "pending" {
		t.Fatal("begin drain", err)
	}
	if _, err = repo.BeginLegacyReadDrain(ctx, identity, v, relationship, operation, challenge, drainOperation, drainChallenge); err != nil {
		t.Fatal("drain begin retry", err)
	}
	drainReceipt := protocol.LegacyReadDrainReceipt{Kind: "legacy-media-drain-v1", OperationID: drainOperation, Challenge: drainChallenge, ExpiresAt: expiry, MasterID: master, OwnerID: owner, RelationshipID: relationship, RelationshipBinding: receipt.RelationshipBinding, OwnerBinding: receipt.OwnerBinding, FenceBinding: receipt.FenceBinding, State: "revoked"}
	drainPayload, _ := drainReceipt.Payload()
	drainSignature, _ := protocol.Sign(ownerSeed, drainPayload)
	if _, err = repo.ConfirmLegacyReadDrain(ctx, identity, v, drainOperation, drainReceipt, sig); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("enrollment signature reused as drain", err)
	}
	wrongOperation := drainReceipt
	wrongOperation.OperationID = strings.Repeat("f", 32)
	wrongPayload, _ := wrongOperation.Payload()
	wrongSignature, _ := protocol.Sign(ownerSeed, wrongPayload)
	if _, err = repo.ConfirmLegacyReadDrain(ctx, identity, v, drainOperation, wrongOperation, wrongSignature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("other operation signature accepted", err)
	}
	badDrain := drainReceipt
	badDrain.FenceBinding = strings.Repeat("7", 64)
	badDrainPayload, _ := badDrain.Payload()
	badDrainSignature, _ := protocol.Sign(ownerSeed, badDrainPayload)
	if _, err = repo.ConfirmLegacyReadDrain(ctx, identity, v, drainOperation, badDrain, badDrainSignature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong drain scope accepted", err)
	}
	// Model a lost Owner response. A second drain cannot replace the pending
	// original operation; recovery asks for a freshly signed status instead.
	if _, err = repo.BeginLegacyReadDrain(ctx, identity, v, relationship, operation, challenge, strings.Repeat("0", 32), strings.Repeat("0", 64)); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("second drain replaced current", err)
	}
	// Cross the actual persisted deadline; no trusted signature is rewritten.
	if wait := time.Until(time.Unix(expiry, 0)); wait > 0 {
		time.Sleep(wait + 20*time.Millisecond)
	}
	if lost, ok, e := repo.RecoverLegacyReadDrain(ctx, identity, v, relationship, drainOperation, drainChallenge); e != nil || ok || lost.State != "pending" {
		t.Fatal("lost response was assumed committed", e)
	}
	if _, fresh, err = repo.RecoverLegacyReadDrain(ctx, identity, v, relationship, drainOperation, drainChallenge); err != nil || fresh {
		t.Fatal("expired drain renewed authority", err)
	}
	statusRequest, statusChallenge := strings.Repeat("e", 32), strings.Repeat("f", 64)
	statusExpiry := time.Now().Unix() + 120
	status, err := repo.BeginLegacyReadStatus(ctx, identity, v, relationship, "status", drainOperation, drainChallenge, statusRequest, statusChallenge, statusExpiry)
	if err != nil {
		t.Fatal("reauthorize status", err)
	}
	if _, err = repo.BeginLegacyReadStatus(ctx, identity, v, relationship, "status", drainOperation, drainChallenge, statusRequest, statusChallenge, statusExpiry); err != nil {
		t.Fatal("same pending status retry", err)
	}
	if _, err = repo.BeginLegacyReadStatus(ctx, identity, v, relationship, "resume", drainOperation, drainChallenge, statusRequest, statusChallenge, statusExpiry); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("pending request changed action", err)
	}
	if _, err = repo.BeginLegacyReadStatus(ctx, identity, v, relationship, "invalid", drainOperation, drainChallenge, strings.Repeat("7", 32), strings.Repeat("2", 64), statusExpiry); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("invalid action accepted", err)
	}
	observed, _ := status.Request.Receipt("draining")
	observedPayload, _ := observed.Payload()
	observedSignature, _ := protocol.Sign(ownerSeed, observedPayload)
	if _, err = repo.ConfirmLegacyReadStatus(ctx, identity, v, observed, observedSignature); err != nil {
		t.Fatal("record draining", err)
	}
	if _, err = repo.BeginLegacyReadStatus(ctx, identity, v, relationship, "status", drainOperation, drainChallenge, strings.Repeat("7", 32), challenge, time.Now().Unix()+120); err == nil {
		t.Fatal("cross-kind challenge reused")
	}
	if _, fresh, err = repo.RecoverLegacyReadStatus(ctx, identity, v, relationship, statusRequest, statusChallenge); err != nil || fresh {
		t.Fatal("draining treated as drained", err)
	}
	statusRequest2, statusChallenge2 := strings.Repeat("8", 32), strings.Repeat("9", 64)
	statusExpiry2 := time.Now().Unix() + 6
	status2, err := repo.BeginLegacyReadStatus(ctx, identity, v, relationship, "resume", drainOperation, drainChallenge, statusRequest2, statusChallenge2, statusExpiry2)
	if err != nil {
		t.Fatal(err)
	}
	revoked, _ := status2.Request.Receipt("revoked")
	revokedPayload, _ := revoked.Payload()
	revokedSignature, _ := protocol.Sign(ownerSeed, revokedPayload)
	resumeDraining := revoked
	resumeDraining.State = "draining"
	resumeDrainingPayload := make(map[string]any, len(revokedPayload))
	for key, value := range revokedPayload {
		resumeDrainingPayload[key] = value
	}
	resumeDrainingPayload["state"] = "draining"
	resumeDrainingSignature, _ := protocol.Sign(ownerSeed, resumeDrainingPayload)
	if _, err = repo.ConfirmLegacyReadStatus(ctx, identity, v, resumeDraining, resumeDrainingSignature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("resume accepted a draining receipt", err)
	}
	wrongAction := revoked
	wrongAction.Action = "status"
	wrongActionPayload, _ := wrongAction.Payload()
	wrongActionSignature, _ := protocol.Sign(ownerSeed, wrongActionPayload)
	if _, err = repo.ConfirmLegacyReadStatus(ctx, identity, v, wrongAction, wrongActionSignature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("signed status substituted for resume", err)
	}
	wrongStatusOperation := revoked
	wrongStatusOperation.OriginalOperationID = strings.Repeat("3", 32)
	wrongStatusOperationPayload, _ := wrongStatusOperation.Payload()
	wrongStatusOperationSignature, _ := protocol.Sign(ownerSeed, wrongStatusOperationPayload)
	if _, err = repo.ConfirmLegacyReadStatus(ctx, identity, v, wrongStatusOperation, wrongStatusOperationSignature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("status changed original operation", err)
	}
	wrongDeadline := revoked
	wrongDeadline.OriginalExpiresAt++
	wrongDeadlinePayload, _ := wrongDeadline.Payload()
	wrongDeadlineSignature, _ := protocol.Sign(ownerSeed, wrongDeadlinePayload)
	if _, err = repo.ConfirmLegacyReadStatus(ctx, identity, v, wrongDeadline, wrongDeadlineSignature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("status changed original deadline", err)
	}
	if _, err = repo.ConfirmLegacyReadStatus(ctx, identity, v, revoked, drainSignature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("drain signature reused as status", err)
	}
	if _, err = raw.Exec(trigger); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ConfirmLegacyReadStatus(ctx, identity, v, revoked, revokedSignature); err == nil || !strings.Contains(err.Error(), "legacy-enrollment-fault") {
		t.Fatal("status fault not observed", err)
	}
	if _, err = raw.Exec(`DROP TRIGGER fail_legacy_enrollment`); err != nil {
		t.Fatal(err)
	}
	if _, fresh, err = repo.RecoverLegacyReadStatus(ctx, identity, v, relationship, statusRequest2, statusChallenge2); err != nil || fresh {
		t.Fatal("failed status committed", err)
	}
	if _, err = repo.ConfirmLegacyReadStatus(ctx, identity, v, revoked, revokedSignature); err != nil {
		t.Fatal("status retry", err)
	}
	if _, fresh, err = repo.RecoverLegacyReadStatus(ctx, identity, v, relationship, statusRequest2, statusChallenge2); err != nil || !fresh {
		t.Fatal("fresh signed revoked status", err)
	}
	if wait := time.Until(time.Unix(statusExpiry2, 0)); wait > 0 {
		time.Sleep(wait + 20*time.Millisecond)
	}
	if _, fresh, err = repo.RecoverLegacyReadStatus(ctx, identity, v, relationship, statusRequest2, statusChallenge2); err != nil || fresh {
		t.Fatal("expired status renewed authority", err)
	}
	statusRequest3, statusChallenge3 := strings.Repeat("b", 32), strings.Repeat("1", 64)
	status3, err := repo.BeginLegacyReadStatus(ctx, identity, v, relationship, "status", drainOperation, drainChallenge, statusRequest3, statusChallenge3, time.Now().Unix()+120)
	if err != nil {
		t.Fatal("fresh status reauthorization", err)
	}
	revoked3, _ := status3.Request.Receipt("revoked")
	revokedPayload3, _ := revoked3.Payload()
	revokedSignature3, _ := protocol.Sign(ownerSeed, revokedPayload3)
	if _, err = repo.ConfirmLegacyReadStatus(ctx, identity, v, revoked3, revokedSignature3); err != nil {
		t.Fatal("fresh status confirmation", err)
	}
	if _, err = repo.ConfirmLegacyReadDrain(ctx, identity, v, drainOperation, drainReceipt, drainSignature); err != nil {
		t.Fatal("late receipt history", err)
	}
	emitted := false
	if err = db.Backups().ExportBusinessSnapshot(ctx, func(string, map[string]any) error { emitted = true; return nil }); !errors.Is(err, store.ErrBackupState) || emitted {
		t.Fatal("logical backup omitted a pending enrollment intent", err)
	}
	if db.Backend() == "sqlite" {
		var path string
		if err = raw.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
			t.Fatal(err)
		}
		opened, e := sqlitestore.OpenExisting(ctx, path)
		if e != nil {
			t.Fatal(e)
		}
		defer opened.Close()
		if err = opened.Initialize(ctx); err == nil {
			t.Fatal("normal startup accepted nonempty unintegrated intent")
		}
		repo = opened.Nodes().(*business.Repository)
	}
	got, fresh, err := repo.RecoverLegacyReadEnrollment(ctx, identity, v, relationship, operation, challenge)
	if err != nil || fresh || got.Receipt == nil || *got.Receipt != receipt || got.Signature != sig {
		t.Fatal("reopen recovery", err)
	}
	drainRecovered, drainFresh, err := repo.RecoverLegacyReadDrain(ctx, identity, v, relationship, drainOperation, drainChallenge)
	if err != nil || drainFresh || drainRecovered.Receipt == nil || *drainRecovered.Receipt != drainReceipt || drainRecovered.Signature != drainSignature {
		t.Fatal("drain reopen recovery", err)
	}
	if recoveredStatus, ok, e := repo.RecoverLegacyReadStatus(ctx, identity, v, relationship, statusRequest3, statusChallenge3); e != nil || !ok || recoveredStatus.Receipt == nil || *recoveredStatus.Receipt != revoked3 {
		t.Fatal("fresh status reopen", e)
	}
	current, e := repo.CurrentLegacyReadControl(ctx, identity, v, relationship)
	if e != nil || current.Drain == nil || current.Status == nil || current.Drain.OperationID != drainOperation || current.Status.Request.RequestID != statusRequest3 {
		t.Fatal("current head reopen", e)
	}
	var headTag string
	var headNonce, headSealed []byte
	var headRevision int64
	if e = raw.QueryRow(`SELECT challenge_tag,nonce,revision,sealed FROM legacy_read_control_intents WHERE operation_index=?`, headIndex).Scan(&headTag, &headNonce, &headRevision, &headSealed); e != nil {
		t.Fatal(e)
	}
	if _, e = raw.Exec(`UPDATE legacy_read_control_intents SET sealed=? WHERE operation_index=?`, []byte("tampered head"), headIndex); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.CurrentLegacyReadControl(ctx, identity, v, relationship); !errors.Is(e, store.ErrNodeState) {
		t.Fatal("tampered head accepted", e)
	}
	if _, e = raw.Exec(`UPDATE legacy_read_control_intents SET sealed=? WHERE operation_index=?`, headSealed, headIndex); e != nil {
		t.Fatal(e)
	}
	if _, e = raw.Exec(`DELETE FROM legacy_read_control_intents WHERE operation_index=?`, headIndex); e != nil {
		t.Fatal(e)
	}
	if _, _, e = repo.FindCurrentLegacyReadControl(ctx, identity, v, relationship); !errors.Is(e, store.ErrNodeState) {
		t.Fatal("missing head treated as first setup", e)
	}
	if _, e = raw.Exec(`INSERT INTO legacy_read_control_intents(operation_index,challenge_tag,nonce,revision,sealed) VALUES(?,?,?,?,?)`, headIndex, headTag, headNonce, headRevision, headSealed); e != nil {
		t.Fatal(e)
	}
	anchorIndex, _, e := v.LegacyReadAnchorIndexes(relationship)
	if e != nil {
		t.Fatal(e)
	}
	var anchorTag string
	var anchorNonce, anchorSealed []byte
	var anchorRevision int64
	if e = raw.QueryRow(`SELECT challenge_tag,nonce,revision,sealed FROM legacy_read_control_intents WHERE operation_index=?`, anchorIndex).Scan(&anchorTag, &anchorNonce, &anchorRevision, &anchorSealed); e != nil {
		t.Fatal(e)
	}
	if _, e = raw.Exec(`DELETE FROM legacy_read_control_intents WHERE operation_index=?`, anchorIndex); e != nil {
		t.Fatal(e)
	}
	if _, _, e = repo.FindCurrentLegacyReadControl(ctx, identity, v, relationship); !errors.Is(e, store.ErrNodeState) {
		t.Fatal("missing anchor treated as first setup", e)
	}
	if _, e = raw.Exec(`INSERT INTO legacy_read_control_intents(operation_index,challenge_tag,nonce,revision,sealed) VALUES(?,?,?,?,?)`, anchorIndex, anchorTag, anchorNonce, anchorRevision, anchorSealed); e != nil {
		t.Fatal(e)
	}
	if _, err = raw.Exec(`UPDATE node_relationships SET peer_endpoint=? WHERE relationship_id=?`, "https://replaced.test", relationship); err != nil {
		t.Fatal(err)
	}
	if _, _, err = repo.RecoverLegacyReadEnrollment(ctx, identity, v, relationship, operation, challenge); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("repaired relationship accepted", err)
	}
	if _, _, err = repo.RecoverLegacyReadStatus(ctx, identity, v, relationship, statusRequest3, statusChallenge3); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("repaired status relationship accepted", err)
	}
	if _, err = raw.Exec(`UPDATE node_relationships SET peer_endpoint=? WHERE relationship_id=?`, rel.Endpoint, relationship); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`UPDATE legacy_read_control_intents SET sealed=? WHERE operation_index=?`, []byte("tampered"), idx); err != nil {
		t.Fatal(err)
	}
	if _, _, err = repo.RecoverLegacyReadEnrollment(ctx, identity, v, relationship, operation, challenge); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("tamper accepted", err)
	}
}
