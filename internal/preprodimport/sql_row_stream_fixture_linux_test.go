//go:build linux && ledger_fixture

package preprodimport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureSQLSource(t *testing.T, omitUnique bool) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "synthetic-source.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { db.Close() })
	for _, statement := range []string{`PRAGMA journal_mode=WAL`, `CREATE TABLE frontiercloud_schema(singleton INTEGER PRIMARY KEY,generation INTEGER NOT NULL)`, `INSERT INTO frontiercloud_schema VALUES(1,7)`} {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, spec := range fixtureRowSpecs {
		cols := make([]string, len(spec.columns))
		for i, name := range spec.columns {
			typ := "TEXT"
			if spec.name == "crypto_key_id" && name == "singleton" {
				typ = "INTEGER"
			}
			cols[i] = name + " " + typ
		}
		key := spec.key
		if spec.name == "encryption" {
			key = "object_kind,object_id"
		}
		if !(omitUnique && spec.name == "objects") {
			cols = append(cols, "PRIMARY KEY ("+key+")")
		}
		if spec.name == "encryption" {
			cols = append(cols, "UNIQUE (file_id)")
		}
		if _, err = db.Exec("CREATE TABLE " + spec.table + " (" + strings.Join(cols, ",") + ")"); err != nil {
			t.Fatal(err)
		}
		tx, e := db.Begin()
		if e != nil {
			t.Fatal(e)
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(spec.columns)), ",")
		stmt, e := tx.Prepare("INSERT INTO " + spec.table + " (" + strings.Join(spec.columns, ",") + ") VALUES (" + placeholders + ")")
		if e != nil {
			t.Fatal(e)
		}
		count := 137
		if spec.name == "crypto_key_id" {
			count = 1
		}
		for row := 0; row < count; row++ {
			values := make([]any, len(spec.columns))
			for i, col := range spec.columns {
				values[i] = fmt.Sprintf("synthetic-%s-%04d", col, row)
				if col == spec.key {
					values[i] = fmt.Sprintf("%04d", row)
				}
				if col == "object_kind" {
					values[i] = "media"
				}
				if col == "media_path" {
					values[i] = fmt.Sprintf("music/秘密/track-%04d.mp3", row)
				}
				if spec.name == "members" && col == "relationship_id" {
					values[i] = nil
				}
				if spec.name == "encryption" && col == "descriptor_json" {
					values[i] = nil
				}
				if spec.name == "encryption" && col == "file_id" {
					values[i] = fmt.Sprintf("%032x", row+1)
				}
				if spec.name == "crypto_key_id" && col == "singleton" {
					values[i] = 1
				}
				if spec.name == "crypto_key_id" && col == "key_id" {
					values[i] = strings.Repeat("6", 64)
				}
			}
			if _, e = stmt.Exec(values...); e != nil {
				t.Fatal(e)
			}
		}
		if e = stmt.Close(); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
	}
	return db
}

func fixtureSQLScope() fixtureStreamScope {
	return fixtureStreamScope{Source: strings.Repeat("1", 32), Target: strings.Repeat("2", 32), Challenge: strings.Repeat("3", 64), SchemaGeneration: 7, PageSize: 17}
}
func fixtureSQLDestination(t *testing.T) *os.File {
	t.Helper()
	f, e := os.OpenFile(filepath.Join(t.TempDir(), "encrypted.snapshot"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestFixtureSignedSQLRowStreamConsistentAndEncrypted(t *testing.T) {
	db := fixtureSQLSource(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	dst := fixtureSQLDestination(t)
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	scope := fixtureSQLScope()
	checks := 0
	check := func() error { checks++; return nil }
	// WAL permits a second writer after measurement; the same read transaction
	// must still export exactly its original snapshot in both passes. This does
	// not claim real writer freeze or source connection identity.
	after := func() error {
		_, e := db.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('new','media','music/new.mp3','new','1','1')`)
		return e
	}
	signed, desc, err := fixtureCaptureSQLRows(ctx, tx, dst, private, scope, check, after)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(desc.key[:])
	if checks < 2 || len(signed.Manifest.Sections) != 9 || signed.Manifest.Sections[0].Rows != 137 {
		t.Fatal("snapshot coverage", checks, signed.Manifest.Sections)
	}
	var liveCount int
	if err = db.QueryRow(`SELECT COUNT(*) FROM media_objects`).Scan(&liveCount); err != nil || liveCount != 138 {
		t.Fatal("fixture writer", liveCount, err)
	}
	if err = fixtureVerifySignedStream(ctx, signed, pub, scope, desc, dst); err != nil {
		t.Fatal("valid signed stream", err)
	}
	ciphertext, err := os.ReadFile(dst.Name())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("music/秘密")) {
		t.Fatal("source path written in plaintext")
	}
	reader, err := openEncryptedSnapshotFixture(dst, desc)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	hash := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(io.NewSectionReader(reader, 0, desc.size), hash))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	sections, rows := 0, 0
	for scanner.Scan() {
		var frame map[string]json.RawMessage
		if err = json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			t.Fatal(err)
		}
		if _, ok := frame["section"]; ok {
			sections++
		}
		if _, ok := frame["row"]; ok {
			rows++
		}
	}
	if err = scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if sections != 9 || rows != 137*8+1 || hex.EncodeToString(hash.Sum(nil)) != signed.Manifest.PlainSHA256 {
		t.Fatal("stream completeness", sections, rows)
	}
	wrong := scope
	wrong.Challenge = strings.Repeat("4", 64)
	if fixtureVerifySignedStream(ctx, signed, pub, wrong, desc, dst) == nil {
		t.Fatal("wrong target scope accepted")
	}
	altered := signed
	altered.Manifest.Sections = append([]fixtureSectionSummary(nil), signed.Manifest.Sections...)
	altered.Manifest.Sections[0].Rows++
	if fixtureVerifySignedStream(ctx, altered, pub, scope, desc, dst) == nil {
		t.Fatal("modified section count accepted")
	}
	wrongKey := desc
	wrongKey.key[0] ^= 1
	if fixtureVerifySignedStream(ctx, signed, pub, scope, wrongKey, dst) == nil {
		t.Fatal("wrong plaintext key accepted")
	}
	var byteAt [1]byte
	if _, err = dst.ReadAt(byteAt[:], 5); err != nil {
		t.Fatal(err)
	}
	byteAt[0] ^= 1
	if _, err = dst.WriteAt(byteAt[:], 5); err != nil {
		t.Fatal(err)
	}
	if fixtureVerifySignedStream(ctx, signed, pub, scope, desc, dst) == nil {
		t.Fatal("modified ciphertext accepted")
	}
}

func TestFixtureSQLRowStreamRejectsMissingUniqueAndFreezeLoss(t *testing.T) {
	for _, tc := range []struct {
		name      string
		nonunique bool
		fail      string
	}{
		{"missing page key uniqueness", true, ""}, {"schema generation mismatch", false, "schema"},
		{"freeze lost after first pass", false, "freeze"}, {"cancel after first pass", false, "cancel"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := fixtureSQLSource(t, tc.nonunique)
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			dst := fixtureSQLDestination(t)
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(private)
			scope := fixtureSQLScope()
			if tc.fail == "schema" {
				scope.SchemaGeneration++
			}
			frozen := true
			check := func() error {
				if !frozen {
					return errors.New("freeze lost")
				}
				return nil
			}
			after := func() error {
				if tc.fail == "freeze" {
					frozen = false
				}
				if tc.fail == "cancel" {
					cancel()
				}
				return nil
			}
			signed, desc, err := fixtureCaptureSQLRows(ctx, tx, dst, private, scope, check, after)
			if err == nil || desc != (encryptedSnapshotFixtureDescriptor{}) || len(signed.Signature) != 0 {
				t.Fatal("unsafe capture returned authorization", err)
			}
		})
	}
}

func TestFixtureSQLRowStreamPartialOutputCannotAuthorizeRecovery(t *testing.T) {
	db := fixtureSQLSource(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	dst := fixtureSQLDestination(t)
	secondPass := false
	checks := 0
	check := func() error {
		if secondPass {
			checks++
			if checks > 1100 {
				return errors.New("synthetic freeze loss")
			}
		}
		return nil
	}
	after := func() error { secondPass = true; return nil }
	signed, desc, err := fixtureCaptureSQLRows(ctx, tx, dst, private, fixtureSQLScope(), check, after)
	if err == nil || desc != (encryptedSnapshotFixtureDescriptor{}) || len(signed.Signature) != 0 {
		t.Fatal("partial capture returned authorization", err)
	}
	info, err := dst.Stat()
	if err != nil || info.Size() <= 0 {
		t.Fatal("fixture did not reach partial ciphertext", info, err)
	}
	partial, err := os.ReadFile(dst.Name())
	if err != nil || bytes.Contains(partial, []byte("music/秘密")) {
		t.Fatal("partial output exposed plaintext", err)
	}
	// Recovery starts a new encrypted artifact with a fresh key/nonce. It must
	// never append or grant authority to the incomplete previous artifact.
	newDst := fixtureSQLDestination(t)
	pub := private.Public().(ed25519.PublicKey)
	signed, desc, err = fixtureCaptureSQLRows(ctx, tx, newDst, private, fixtureSQLScope(), func() error { return nil }, nil)
	if err != nil {
		t.Fatal("fresh retry", err)
	}
	defer clear(desc.key[:])
	if fixtureVerifySignedStream(ctx, signed, pub, fixtureSQLScope(), desc, newDst) != nil {
		t.Fatal("fresh retry failed validation")
	}
	if fixtureVerifySignedStream(ctx, signed, pub, fixtureSQLScope(), desc, dst) == nil {
		t.Fatal("partial artifact accepted as complete retry")
	}
}

func TestFixtureSQLRowStreamVerifierRejectsBadFramingAndOrdering(t *testing.T) {
	db := fixtureSQLSource(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var out bytes.Buffer
	snapshot, err := fixtureWalkSQLRows(ctx, tx, &out, 17, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	original := out.Bytes()
	if err = fixtureVerifyStreamFrames(ctx, bytes.NewReader(original), int64(len(original)), snapshot.sections); err != nil {
		t.Fatal("valid framing", err)
	}
	for name, change := range map[string]func([]byte) []byte{
		"wrong section": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"section":"objects"`), []byte(`"section":"changed"`), 1)
		},
		"unknown field": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`{"row":[`), []byte(`{"extra":true,"row":[`), 1)
		},
		"wrong row count": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"end":"objects","rows":137`), []byte(`"end":"objects","rows":136`), 1)
		},
		"missing final newline": func(raw []byte) []byte { return raw[:len(raw)-1] },
		"swapped first two rows": func(raw []byte) []byte {
			lines := bytes.Split(raw, []byte{'\n'})
			lines[1], lines[2] = lines[2], lines[1]
			return bytes.Join(lines, []byte{'\n'})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := change(append([]byte(nil), original...))
			if bytes.Equal(candidate, original) {
				t.Fatal("fixture mutation did not apply")
			}
			if fixtureVerifyStreamFrames(ctx, bytes.NewReader(candidate), int64(len(candidate)), snapshot.sections) == nil {
				t.Fatal("bad stream accepted")
			}
		})
	}
}
