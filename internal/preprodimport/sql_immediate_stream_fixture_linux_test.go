//go:build linux && ledger_fixture

package preprodimport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A child process provides an independent SQLite connection and OS process.
// It does not simulate a hostile process modifying the database files directly.
func TestFixtureImmediateStreamAgainstSeparateProcess(t *testing.T) {
	if path := os.Getenv("FC_TEST_WRITER_DATABASE"); path != "" {
		u := url.URL{Scheme: "file", Path: path, RawQuery: url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(100)"}}.Encode()}
		db, err := sql.Open("sqlite", u.String())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		_, err = db.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('child','media','music/child.mp3','child','1','1')`)
		if os.Getenv("FC_TEST_WRITER_EXPECT_BUSY") == "1" {
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "locked") {
				t.Fatalf("writer was not blocked: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		return
	}
	db := fixtureSQLSource(t, false)
	var sequence int
	var name, path string
	if err := db.QueryRow(`SELECT seq,name,file FROM pragma_database_list WHERE name='main'`).Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	child := func(expectBusy bool) error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFixtureImmediateStreamAgainstSeparateProcess$", "-test.count=1")
		cmd.Env = append(os.Environ(), "FC_TEST_WRITER_DATABASE="+path)
		if expectBusy {
			cmd.Env = append(cmd.Env, "FC_TEST_WRITER_EXPECT_BUSY=1")
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("child: %s", out)
		}
		return err
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: url.Values{"mode": {"rw"}, "_txlock": {"immediate"}, "_pragma": {"busy_timeout(100)"}}.Encode()}
	source, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	source.SetMaxOpenConns(1)
	defer source.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	tx, err := source.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	dst := fixtureSQLDestination(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	signed, desc, err := fixtureCaptureSQLRows(ctx, tx, dst, key, fixtureSQLScope(), func() error { return ctx.Err() }, func() error { return child(true) })
	if err != nil {
		t.Fatal(err)
	}
	defer clear(desc.key[:])
	if err = fixtureVerifySignedStream(ctx, signed, pub, fixtureSQLScope(), desc, dst); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = child(false); err != nil {
		t.Fatal("writer remained blocked after rollback", err)
	}
}

func TestFixtureImmediateLockReleasedOnProcessDeath(t *testing.T) {
	if path := os.Getenv("FC_TEST_HOLDER_DATABASE"); path != "" {
		u := url.URL{Scheme: "file", Path: path, RawQuery: url.Values{"mode": {"rw"}, "_txlock": {"immediate"}}.Encode()}
		db, err := sql.Open("sqlite", u.String())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		fmt.Println("locked")
		for {
			time.Sleep(time.Hour)
		}
	}
	db := fixtureSQLSource(t, false)
	var sequence int
	var name, path string
	if err := db.QueryRow(`SELECT seq,name,file FROM pragma_database_list WHERE name='main'`).Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFixtureImmediateLockReleasedOnProcessDeath$", "-test.count=1")
	cmd.Env = append(os.Environ(), "FC_TEST_HOLDER_DATABASE="+path)
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		if scanner.Scan() {
			line <- scanner.Text()
		} else {
			line <- ""
		}
	}()
	select {
	case got := <-line:
		if got != "locked" {
			t.Fatalf("holder failed: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("holder did not acquire lock")
	}
	busy := func() error {
		_, err := db.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('after-death','media','music/after.mp3','after','1','1')`)
		return err
	}
	if err = busy(); err == nil || !strings.Contains(strings.ToLower(err.Error()), "locked") {
		t.Fatalf("live holder did not block writer: %v", err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if err = busy(); err != nil {
		t.Fatal("writer remained blocked after holder death", err)
	}
}

func TestFixtureImmediateStreamCancellationAndLostTransaction(t *testing.T) {
	for _, mode := range []string{"deadline-30s", "transaction-lost"} {
		t.Run(mode, func(t *testing.T) {
			db := fixtureSQLSource(t, false)
			var sequence int
			var name, path string
			if err := db.QueryRow(`SELECT seq,name,file FROM pragma_database_list WHERE name='main'`).Scan(&sequence, &name, &path); err != nil {
				t.Fatal(err)
			}
			u := url.URL{Scheme: "file", Path: path, RawQuery: url.Values{"mode": {"rw"}, "_txlock": {"immediate"}, "_pragma": {"busy_timeout(100)"}}.Encode()}
			source, err := sql.Open("sqlite", u.String())
			if err != nil {
				t.Fatal(err)
			}
			source.SetMaxOpenConns(1)
			defer source.Close()
			duration := 29*time.Second + 900*time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			tx, err := source.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			signed, desc, err := fixtureCaptureSQLRows(ctx, tx, fixtureSQLDestination(t), key, fixtureSQLScope(), func() error { return ctx.Err() }, func() error {
				if mode == "deadline-30s" {
					<-ctx.Done()
					return nil
				}
				return tx.Rollback()
			})
			if err == nil || len(signed.Signature) != 0 || desc.size != 0 {
				t.Fatal("lost transaction or deadline produced signed snapshot", err)
			}
			// Cancellation of BeginTx's context triggers database/sql rollback.
			until := time.Now().Add(3 * time.Second)
			for {
				_, err = db.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('after','media','music/after.mp3','after','1','1')`)
				if err == nil || time.Now().After(until) {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if err != nil {
				t.Fatal("writer remained blocked after failed capture", err)
			}
		})
	}
}
