//go:build linux

package preprodimport

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestSourceCaptureCoordinatorRealVaultIdentityAndDurableIntent(t *testing.T) {
	data, secrets := filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	created, err := vault.Open(secrets)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.OpenExisting(secrets)
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.Encode(bytes.Repeat([]byte{8}, 32))
	encryptedKey, err := created.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	public, err := protocol.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, "source.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,private_key TEXT)`); err != nil {
		t.Fatal(err)
	}
	source, target := strings.Repeat("2", 32), strings.Repeat("3", 32)
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master',?)`, source, encryptedKey); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE media_crypto_keys(singleton INTEGER PRIMARY KEY,key_id TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO media_crypto_keys VALUES(1,?)`, strings.Repeat("6", 64)); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	called := false
	err = coordinateSourceCapture(ctx, gate, root, data, path, v, intent, "wrong-public-key", func(context.Context, maintenance.SQLiteSnapshotReader, func(string) (string, error), func() error) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatal("wrong pinned source key accepted")
	}
	if _, err = root.Lstat(filepath.Join(sourceCaptureIntentDir, sourceCaptureIntentName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong key reserved intent", err)
	}
	digest := strings.Repeat("a", 64)
	err = coordinateSourceCapture(ctx, gate, root, data, path, v, intent, public, func(ctx context.Context, reader maintenance.SQLiteSnapshotReader, sign func(string) (string, error), check func() error) error {
		called = true
		if _, err := db.ExecContext(ctx, `INSERT INTO node_identity VALUES(2,'other','Master','other')`); err == nil {
			return errors.New("independent writer escaped capture lock")
		}
		signature, err := sign(digest)
		if err != nil {
			return err
		}
		if _, err = sign(digest); err == nil {
			return errors.New("one intent signed twice")
		}
		payload := map[string]any{"kind": "frontiercloud-preprod-source-stream-v2", "capture_id": intent.CaptureID, "source_node": source, "target_node": target, "challenge": intent.Challenge, "scope_sha256": intent.ScopeDigest, "sha256": digest, "expires_unix": intent.ExpiresUnix}
		if err = protocol.Verify(public, payload, signature); err != nil {
			return err
		}
		return check()
	})
	if err != nil || !called {
		t.Fatal("source coordinator", err)
	}
	got, err := readSourceCaptureIntent(root, v)
	if err != nil || got != intent {
		t.Fatal("missing durable intent", err)
	}
	if err = coordinateSourceCapture(ctx, gate, root, data, path, v, intent, public, func(context.Context, maintenance.SQLiteSnapshotReader, func(string) (string, error), func() error) error {
		return nil
	}); err == nil {
		t.Fatal("active intent allowed replay")
	}
	if enabled, err := gate.Enabled(); err != nil || !enabled {
		t.Fatal("maintenance marker lost", err)
	}
}

func TestSourceCaptureCoordinatorCrashLeavesDurableIntent(t *testing.T) {
	if data := os.Getenv("FC_CAPTURE_CRASH_DATA"); data != "" {
		secrets, public := os.Getenv("FC_CAPTURE_CRASH_SECRETS"), os.Getenv("FC_CAPTURE_CRASH_PUBLIC")
		issued, err := strconv.ParseInt(os.Getenv("FC_CAPTURE_CRASH_ISSUED"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		v, err := vault.OpenExisting(secrets)
		if err != nil {
			t.Fatal(err)
		}
		gate, err := maintenance.Open(data)
		if err != nil {
			t.Fatal(err)
		}
		defer gate.Close()
		root, err := os.OpenRoot(data)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		intent := sourceCaptureIntent{Version: 1, Purpose: "frontiercloud:source-capture-intent:v1", CaptureID: strings.Repeat("1", 32), SourceNode: strings.Repeat("2", 32), TargetNode: strings.Repeat("3", 32), Challenge: strings.Repeat("4", 64), ScopeDigest: strings.Repeat("5", 64), SourceKeyID: strings.Repeat("6", 64), Receiver: strings.Repeat("7", 64), IssuedUnix: issued, ExpiresUnix: issued + 120}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		err = coordinateSourceCapture(ctx, gate, root, data, filepath.Join(data, "source.sqlite"), v, intent, public, func(ctx context.Context, reader maintenance.SQLiteSnapshotReader, sign func(string) (string, error), check func() error) error {
			if _, err := sign(strings.Repeat("a", 64)); err != nil {
				return err
			}
			fmt.Println("intent-synced")
			for {
				time.Sleep(time.Hour)
			}
		})
		t.Fatal("capture should have been killed", err)
	}
	data, secrets := filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(secrets)
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.Encode(bytes.Repeat([]byte{8}, 32))
	key, err := v.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	public, err := protocol.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, "source.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{`PRAGMA journal_mode=WAL`, `CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,private_key TEXT)`} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master',?)`, strings.Repeat("2", 32), key); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE media_crypto_keys(singleton INTEGER PRIMARY KEY,key_id TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO media_crypto_keys VALUES(1,?)`, strings.Repeat("6", 64)); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
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
	issued := time.Now().Unix()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSourceCaptureCoordinatorCrashLeavesDurableIntent$", "-test.count=1")
	cmd.Env = append(os.Environ(), "FC_CAPTURE_CRASH_DATA="+data, "FC_CAPTURE_CRASH_SECRETS="+secrets, "FC_CAPTURE_CRASH_PUBLIC="+public, "FC_CAPTURE_CRASH_ISSUED="+strconv.FormatInt(issued, 10))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			line <- scanner.Text()
		} else {
			line <- ""
		}
	}()
	select {
	case value := <-line:
		if value != "intent-synced" {
			t.Fatalf("capture did not reach durable intent: %q", value)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("capture did not reach durable intent")
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	root, err := os.OpenRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	intent, err := readSourceCaptureIntent(root, v)
	if err != nil || intent.IssuedUnix != issued {
		t.Fatal("crash lost durable intent", err)
	}
	if enabled, err := gate.Enabled(); err != nil || !enabled {
		t.Fatal("crash lost maintenance marker", err)
	}
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(2,'after','Master','x')`); err != nil {
		t.Fatal("crash retained SQLite lock", err)
	}
}
