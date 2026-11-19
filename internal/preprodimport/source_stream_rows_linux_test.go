//go:build linux && ledger_fixture

package preprodimport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestSourceRowsV2MatchesCompleteFixtureAndRejectsNonUnique(t *testing.T) {
	for _, missingKey := range []bool{false, true} {
		db := fixtureSQLSource(t, missingKey)
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		var actual, expected bytes.Buffer
		got, err := scanSourceRowsV2(ctx, tx, &actual, 17, func() error { return ctx.Err() })
		if missingKey {
			if err == nil {
				t.Fatal("missing unique pagination key accepted")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			want, e := fixtureWalkSQLRows(ctx, tx, &expected, 17, func() error { return ctx.Err() })
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.HasPrefix(actual.Bytes(), expected.Bytes()) || int64(expected.Len()) != want.size || got.Bytes <= want.size || len(got.Sections) != len(want.sections)+1 {
				t.Fatal("production row stream diverged from independently verified fixture")
			}
			for i, section := range got.Sections[:len(want.sections)] {
				if !reflect.DeepEqual([]any{section.Name, section.Rows, section.SHA256}, []any{want.sections[i].Name, want.sections[i].Rows, want.sections[i].SHA256}) {
					t.Fatal("production section differs", section.Name)
				}
			}
			reserved := got.Sections[len(want.sections)]
			if reserved.Name != "encryption_ids" || reserved.Rows != 137 {
				t.Fatal("missing complete reserved encryption IDs", reserved)
			}
		}
		_ = tx.Rollback()
		cancel()
	}
}

// Integrates production intent, Vault-backed signing, same-transaction row
// walker and the isolated authenticated encryption fixture. This is not a
// target-decryptable wire protocol or an import authorization.
func TestSourceRowsV2UnderRealVaultCaptureCoordinator(t *testing.T) {
	db := fixtureSQLSource(t, false)
	var sequence int
	var name, path string
	if err := db.QueryRow(`SELECT seq,name,file FROM pragma_database_list WHERE name='main'`).Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	data := filepath.Dir(path)
	if err := os.Chmod(data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.Encode(bytes.Repeat([]byte{8}, 32))
	sealed, err := v.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	public, err := protocol.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,private_key TEXT)`); err != nil {
		t.Fatal(err)
	}
	source, target := strings.Repeat("2", 32), strings.Repeat("3", 32)
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master',?)`, source, sealed); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	now := time.Now().UTC()
	intent := sourceCaptureIntent{Version: 1, Purpose: "frontiercloud:source-capture-intent:v1", CaptureID: strings.Repeat("1", 32), SourceNode: source, TargetNode: target, Challenge: strings.Repeat("4", 64), ScopeDigest: strings.Repeat("5", 64), SourceKeyID: strings.Repeat("6", 64), Receiver: strings.Repeat("7", 64), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(time.Minute).Unix()}
	dst := fixtureSQLDestination(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	err = coordinateSourceCapture(ctx, gate, root, data, path, v, intent, public, func(ctx context.Context, reader maintenance.SQLiteSnapshotReader, sign func(string) (string, error), check func() error) error {
		first, e := scanSourceRowsV2(ctx, reader, io.Discard, 17, check)
		if e != nil {
			return e
		}
		pr, pw := io.Pipe()
		type result struct {
			value sourceRowsDigest
			err   error
		}
		done := make(chan result, 1)
		go func() {
			r, e := scanSourceRowsV2(ctx, reader, pw, 17, check)
			_ = pw.CloseWithError(e)
			done <- result{r, e}
		}()
		desc, e := captureEncryptedSnapshotFixture(ctx, dst, pr, first.Bytes)
		if e != nil {
			_ = pr.CloseWithError(e)
		} else {
			_ = pr.Close()
		}
		second := <-done
		if e != nil {
			return e
		}
		if second.err != nil {
			return second.err
		}
		defer clear(desc.key[:])
		if !reflect.DeepEqual(first, second.value) || desc.plainSHA != first.SHA256 {
			return invalid("source rows changed")
		}
		if e = dst.Sync(); e != nil {
			return e
		}
		cipherHash := sha256.New()
		if _, e = io.Copy(cipherHash, io.NewSectionReader(dst, 0, desc.size+int64((desc.size-1)/fixtureEncryptedChunkSize+1)*16)); e != nil {
			return e
		}
		manifest, e := json.Marshal(struct {
			Version  int                   `json:"version"`
			Sections []sourceSectionDigest `json:"sections"`
			Plain    string                `json:"plain_sha256"`
			Cipher   string                `json:"cipher_sha256"`
		}{2, first.Sections, hex.EncodeToString(first.SHA256[:]), hex.EncodeToString(cipherHash.Sum(nil))})
		if e != nil {
			return e
		}
		defer clear(manifest)
		manifestHash := sha256.Sum256(manifest)
		digest := hex.EncodeToString(manifestHash[:])
		signature, e := sign(digest)
		if e != nil {
			return e
		}
		payload := map[string]any{"kind": "frontiercloud-preprod-source-stream-v2", "capture_id": intent.CaptureID, "source_node": source, "target_node": target, "challenge": intent.Challenge, "scope_sha256": intent.ScopeDigest, "sha256": digest, "expires_unix": intent.ExpiresUnix}
		if e = protocol.Verify(public, payload, signature); e != nil {
			return e
		}
		decrypted, e := openEncryptedSnapshotFixture(dst, desc)
		if e != nil {
			return e
		}
		defer decrypted.Close()
		plainHash := sha256.New()
		if _, e = io.Copy(plainHash, io.NewSectionReader(decrypted, 0, desc.size)); e != nil {
			return e
		}
		if !bytes.Equal(plainHash.Sum(nil), first.SHA256[:]) {
			return invalid("source rows decryption")
		}
		return check()
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := readSourceCaptureIntent(root, v)
	if err != nil || got != intent {
		t.Fatal("capture intent missing", err)
	}
}
