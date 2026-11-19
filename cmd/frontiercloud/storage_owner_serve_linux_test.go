//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/bootstrap"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

// This exercises the real serve process and OS lifecycle in an isolated network.
// It proves a TCP listener, not production certificate issuance or an HTTPS read.
func TestStorageOwnerPreparedServeRestart(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_PREPARED_STORAGE_SERVER") == "1" {
		if err := serve(); err != nil {
			t.Fatal(err)
		}
		return
	}
	ctx := context.Background()
	dir := t.TempDir()
	data, secrets := filepath.Join(dir, "data"), filepath.Join(dir, "secrets")
	for _, p := range []string{filepath.Join(data, "media", "music"), filepath.Join(data, "media", "vido"), filepath.Join(data, "media", "lyrics"), filepath.Join(data, "recordings"), secrets} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := bootstrap.InitializeSecrets(secrets); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	l.Close()
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, udpPort, _ := net.SplitHostPort(u.LocalAddr().String())
	u.Close()
	endpoint := "https://storage.test:" + port
	static, err := filepath.Abs("../../static")
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"DEPLOYMENT_MODE": "only_stroge", "DB_TYPE": "sqlite", "SQLITE_PATH": filepath.Join(data, "node.sqlite"),
		"DATA_ROOT": data, "SECRETS_DIR": secrets, "STATIC_ROOT": static,
		"TLS_ENABLED": "true", "SERVER_NAME": "storage.test", "NGINX_MEDIA_ACCEL": "false",
		"STORAGE_TRANSPORT": "relay", "STORAGE_PORT": port, "STORAGE_ENDPOINT": endpoint,
		"HTTP_ADDR": address, "WEBRTC_STUN_PORT": udpPort,
		"FRONTIERCLOUD_TEST_PREPARED_STORAGE_SERVER": "1",
	} {
		t.Setenv(key, value)
	}
	c, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err = deployment.Bind(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	db, err := sqlitestore.Open(c.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := node.Initialize(ctx, db.Nodes(), secrets)
	if err != nil {
		t.Fatal(err)
	}
	if err = id.RecordNativeRuntime(ctx, data); err != nil {
		t.Fatal(err)
	}
	volume, err := media.New(filepath.Join(data, "media"), db.Media(), id)
	if err != nil {
		t.Fatal(err)
	}
	recordings, err := os.OpenRoot(filepath.Join(data, "recordings"))
	if err != nil {
		t.Fatal(err)
	}
	control := node.NewService(db.Nodes(), id, nil)
	control.ConfigureVolumes(db.Pool(), volume, recordings)
	volume.ConfigureCluster(db.Nodes(), db.Pool(), control)
	if err = control.InitializeStorage(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	stableID := id.ID
	if err = volume.Close(); err != nil {
		t.Fatal(err)
	}
	if err = recordings.Close(); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = prepareEmptyStorageOwner(ctx, c, gate, stableID); err != nil {
		t.Fatal(err)
	}
	if err = gate.Resume(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	gate.Close()
	for attempt := 0; attempt < 2; attempt++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStorageOwnerPreparedServeRestart$", "-test.count=1")
		log, err := os.CreateTemp(dir, "serve-"+strconv.Itoa(attempt)+"-*.log")
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		if err = cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		listening := false
		limit := time.Now().Add(20 * time.Second)
		for time.Now().Before(limit) {
			select {
			case err = <-done:
				log.Close()
				raw, _ := os.ReadFile(log.Name())
				t.Fatalf("serve exited before listening: %v\n%s", err, raw)
			default:
			}
			started, _ := os.ReadFile(log.Name())
			if bytes.Contains(started, []byte("FrontierCloud Go runtime started")) {
				conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
				if e == nil {
					conn.Close()
					listening = true
					break
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		if !listening {
			_ = cmd.Process.Kill()
			<-done
			log.Close()
			raw, _ := os.ReadFile(log.Name())
			t.Fatalf("serve did not listen\n%s", raw)
		}
		if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
			_ = cmd.Process.Kill()
			<-done
			log.Close()
			t.Fatal(err)
		}
		select {
		case err = <-done:
			log.Close()
			if err != nil {
				raw, _ := os.ReadFile(log.Name())
				t.Fatalf("serve SIGTERM: %v\n%s", err, raw)
			}
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			log.Close()
			t.Fatal("serve did not stop after SIGTERM")
		}
		check, err := sqlitestore.OpenReadOnly(ctx, c.SQLitePath)
		if err != nil {
			t.Fatal(err)
		}
		row, err := check.Nodes().ReadIdentity(ctx)
		check.Close()
		if err != nil || row.ID != stableID || row.Role != "Follower" || row.Endpoint != endpoint {
			t.Fatal(fmt.Errorf("identity changed after restart %d: %w", attempt+1, err))
		}
	}
}
