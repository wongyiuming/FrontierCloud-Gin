package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	_ "modernc.org/sqlite"
)

func TestSelectedS3IntentJournalAuthenticatesBindingsAndRecovers(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file::memory:?cache=private")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE sealed_tree_capacity_ids(encryption_id CHAR(64) NOT NULL PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	statements, err := migrations.SelectedS3Statements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range statements {
		if _, err = db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	r := New(db, "sqlite")
	key := bytes.Repeat([]byte{7}, 32)
	meta, err := mediacrypto.NewMetadata(100)
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.Repeat("a", 64)
	initial := selectedS3Intent{OperationID: strings.Repeat("b", 64), UploadID: strings.Repeat("c", 32), MemberID: strings.Repeat("d", 32), ObjectID: strings.Repeat("e", 64), BlobID: blob, Key: "objects/aa/aa/" + blob + ".blob", Owner: strings.Repeat("f", 64), LocationBinding: strings.Repeat("1", 64), CredentialRevision: 1, CreatedAt: 1, Bytes: meta.CiphertextSize, Digest: strings.Repeat("2", 64), Encryption: meta, Phase: "reserved", State: "pending", Revision: 1}
	initial.PartCommitment, err = selectedS3Commitment(initial.Bytes, []string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	denied := errors.New("reservation guard denied")
	guard := func(context.Context, queryer, selectedS3Intent, bool) error { return nil }
	if err = r.write(ctx, func(q queryer) error {
		return r.writeSelectedS3IntentTx(ctx, q, key, initial, func(context.Context, queryer, selectedS3Intent, bool) error { return denied })
	}); !errors.Is(err, denied) {
		t.Fatal("guard failure", err)
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM selected_s3_uploads`).Scan(&count); err != nil || count != 0 {
		t.Fatal("guard persisted intent", count, err)
	}
	if err = r.write(ctx, func(q queryer) error { return r.writeSelectedS3IntentTx(ctx, q, key, initial, guard) }); err != nil {
		t.Fatal(err)
	}
	if err = r.write(ctx, func(q queryer) error {
		return r.precommitSelectedS3PartsTx(ctx, q, key, initial, []string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))})
	}); err == nil {
		t.Fatal("different part list matched commitment")
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM selected_s3_parts`).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected precommit persisted parts", count, err)
	}
	if err = r.write(ctx, func(q queryer) error {
		return r.precommitSelectedS3PartsTx(ctx, q, key, initial, []string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))})
	}); err != nil {
		t.Fatal("precommit", err)
	}
	creating := initial
	creating.Phase, creating.Revision = "creating", 2
	if err = r.write(ctx, func(q queryer) error { return r.writeSelectedS3IntentTx(ctx, q, key, creating, guard) }); err != nil {
		t.Fatal(err)
	}
	active := creating
	active.Phase, active.Revision, active.ProviderUploadID = "uploading", 3, strings.Repeat("P", 2048)
	if err = r.write(ctx, func(q queryer) error { return r.writeSelectedS3IntentTx(ctx, q, key, active, guard) }); err != nil {
		t.Fatal(err)
	}
	if err = r.write(ctx, func(q queryer) error {
		got, found, err := r.readSelectedS3IntentTx(ctx, q, key, active.OperationID)
		if err != nil || !found || got != active {
			t.Fatalf("reopened intent: %+v %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	part := selectedS3Part{OperationID: active.OperationID, Number: 1, Bytes: active.Bytes, SHA256: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)), GrantUntil: 500, Revision: 2}
	partGuard := func(context.Context, queryer, selectedS3Part, bool) error { return nil }
	substituted := part
	substituted.SHA256 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if err = r.write(ctx, func(q queryer) error {
		_, err := r.writeSelectedS3PartTx(ctx, q, key, active, substituted, partGuard)
		return err
	}); err == nil {
		t.Fatal("grant changed precommitted bytes")
	}
	if err = r.write(ctx, func(q queryer) error {
		_, err := r.writeSelectedS3PartTx(ctx, q, key, active, part, partGuard)
		return err
	}); err != nil {
		t.Fatal("part grant", err)
	}
	if err = r.write(ctx, func(q queryer) error {
		already, err := r.writeSelectedS3PartTx(ctx, q, key, active, part, partGuard)
		if !already {
			return errors.New("identical replay was not idempotent")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	confirmed := part
	confirmed.Revision, confirmed.Confirmed, confirmed.ETag = 3, true, `"provider-part"`
	if err = r.write(ctx, func(q queryer) error {
		_, err := r.writeSelectedS3PartTx(ctx, q, key, active, confirmed, func(context.Context, queryer, selectedS3Part, bool) error { return denied })
		return err
	}); !errors.Is(err, denied) {
		t.Fatal("provider observation guard", err)
	}
	if err = r.write(ctx, func(q queryer) error {
		_, err := r.writeSelectedS3PartTx(ctx, q, key, active, confirmed, partGuard)
		return err
	}); err != nil {
		t.Fatal("confirm", err)
	}
	changedPart := confirmed
	changedPart.Revision, changedPart.SHA256 = 4, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if err = r.write(ctx, func(q queryer) error {
		_, err := r.writeSelectedS3PartTx(ctx, q, key, active, changedPart, partGuard)
		return err
	}); err == nil {
		t.Fatal("confirmed part changed")
	}
	completing := active
	completing.Revision, completing.Phase = 4, "completing"
	if err = r.write(ctx, func(q queryer) error { return r.writeSelectedS3IntentTx(ctx, q, key, completing, guard) }); err != nil {
		t.Fatal(err)
	}
	if err = r.write(ctx, func(q queryer) error {
		parts, err := r.completeSelectedS3PartsTx(ctx, q, key, completing)
		if err != nil || len(parts) != 1 || parts[0].SHA256 != part.SHA256 {
			t.Fatalf("durable part replay: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bad := active
	bad.Revision, bad.Phase, bad.MemberID = 4, "completing", strings.Repeat("9", 32)
	if err = r.write(ctx, func(q queryer) error { return r.writeSelectedS3IntentTx(ctx, q, key, bad, guard) }); err == nil {
		t.Fatal("member switch accepted")
	}
	var sealed []byte
	var id string
	if err = db.QueryRow(`SELECT encryption_id,sealed FROM selected_s3_uploads`).Scan(&id, &sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(active.ProviderUploadID)) || bytes.Contains(sealed, []byte(active.Key)) {
		t.Fatal("provider metadata leaked")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err = db.Exec(`UPDATE selected_s3_uploads SET sealed=?`, sealed); err != nil {
		t.Fatal(err)
	}
	if err = r.write(ctx, func(q queryer) error {
		_, _, err := r.readSelectedS3IntentTx(ctx, q, key, active.OperationID)
		return err
	}); err == nil {
		t.Fatal("tampered record accepted")
	}
}
