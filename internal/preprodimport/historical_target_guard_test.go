package preprodimport

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	_ "modernc.org/sqlite"
)

func TestHistoricalTargetGuardAuthenticatesIdentityPinAndSQLite(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "target.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,endpoint TEXT,private_key TEXT,created_at INTEGER)`, `CREATE TABLE sealed_tree_source_pin(singleton INTEGER PRIMARY KEY,sealed BLOB)`} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{13}, 32)
	encoded := protocol.Encode(seed)
	sealedKey, err := v.Seal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := protocol.PublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	public, err := protocol.Decode(pub)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := receiverFromMasterSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	identity := store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Master", Endpoint: "https://example.invalid", PrivateKey: sealedKey, CreatedAt: 1}
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "source-node-v1", SourceNode: strings.Repeat("b", 32), SourceKeyID: strings.Repeat("c", 64), SourcePublic: bytes.Repeat([]byte{3}, 32), TargetNode: identity.ID, TargetMasterPublic: public, TargetX25519: receiver.PublicKey().Bytes(), Generation: strings.Repeat("d", 64)}
	raw, err := json.Marshal(pin)
	if err != nil {
		t.Fatal(err)
	}
	sealedPin, err := v.Seal(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(1,?,?,?,?,?)`, identity.ID, identity.Role, identity.Endpoint, identity.PrivateKey, identity.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO sealed_tree_source_pin VALUES(1,?)`, sealedPin); err != nil {
		t.Fatal(err)
	}
	checks := 0
	guard := historicalTargetGuard{path: path, identity: identity, pin: pin, scopeDigest: strings.Repeat("e", 64), vault: v, check: func() error { checks++; return nil }}
	validate := func(g historicalTargetGuard) error {
		t.Helper()
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		return g.validate(ctx, tx)
	}
	if err = validate(guard); err != nil || checks != 2 {
		t.Fatalf("valid target rejected: %v checks=%d", err, checks)
	}
	wrong := guard
	wrong.path = filepath.Join(t.TempDir(), "different.sqlite")
	if validate(wrong) == nil {
		t.Fatal("different target database accepted")
	}
	wrong = guard
	wrong.identity.Endpoint = "https://other.invalid"
	if validate(wrong) == nil {
		t.Fatal("different target identity accepted")
	}
	wrong = guard
	wrong.pin.TargetX25519 = bytes.Repeat([]byte{4}, 32)
	if validate(wrong) == nil {
		t.Fatal("different target receiver accepted")
	}
	wrong = guard
	wrong.pin.SourceKeyID = strings.Repeat("e", 64)
	if validate(wrong) == nil {
		t.Fatal("different source pin accepted")
	}
	wrong = guard
	wrong.check = func() error { return errors.New("maintenance lost") }
	if validate(wrong) == nil {
		t.Fatal("lost maintenance fence accepted")
	}
	if _, err = db.Exec(`UPDATE node_identity SET role='Storage'`); err != nil {
		t.Fatal(err)
	}
	if validate(guard) == nil {
		t.Fatal("changed actual target role accepted")
	}
}
