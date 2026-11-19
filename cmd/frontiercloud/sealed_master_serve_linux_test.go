//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/bootstrap"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

// Exercise serve and the local encrypted catalog through the real HTTP
// listener. Loopback models the trusted edge; there is no external CA or Redis.
func TestSealedMasterServesLocalCatalog(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_SEALED_MASTER_SERVER") == "1" {
		if err := serve(); err != nil {
			t.Fatal(err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
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
	// The real image runs as its application UID. The isolated test may run
	// as root, so give the private mount the UID of the tested process.
	if err := os.Chown(secrets, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	static, err := filepath.Abs("../../static")
	if err != nil {
		t.Fatal(err)
	}
	redisURL := os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://127.0.0.1:1/0"
	}
	for key, value := range map[string]string{
		"DEPLOYMENT_MODE": config.DeploymentBusiness, "DB_TYPE": "sqlite", "SQLITE_PATH": filepath.Join(data, "node.sqlite"),
		"DATA_ROOT": data, "SECRETS_DIR": secrets, "STATIC_ROOT": static, "HTTP_ADDR": address,
		"TLS_ENABLED": "true", "SERVER_NAME": "master.test", "PUBLIC_ORIGIN": "https://master.test", "ADMIN_ORIGIN": "https://master.test",
		"REDIS_URL": redisURL, "NGINX_MEDIA_ACCEL": "false", "LOG_LEVEL": "INFO",
		"TRUSTED_PROXY_NETWORKS": "127.0.0.0/8", "PUBLIC_INGRESS_TRUSTED_PROXY_NETWORKS": "127.0.0.0/8",
		"FRONTIERCLOUD_TEST_SEALED_MASTER_SERVER": "1",
	} {
		t.Setenv(key, value)
	}
	c, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := deployment.Bind(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	db, err := sqlitestore.Open(c.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Initialize(ctx); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := os.Chmod(c.SQLitePath, 0600); err != nil {
		db.Close()
		t.Fatal(err)
	}
	identity, err := node.Initialize(ctx, db.Nodes(), secrets)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := identity.RecordNativeRuntime(ctx, data); err != nil {
		db.Close()
		t.Fatal(err)
	}
	_, promoteErr := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: c.PublicOrigin, Allocation: store.GiB, PhysicalFree: 2 * store.GiB}, store.NodeAudit{})
	closeErr := db.Close()
	if promoteErr != nil || closeErr != nil {
		t.Fatal(promoteErr, closeErr)
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := sealedTreePrepareCommand([]string{identity.ID}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := gate.Resume(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	log, err := os.CreateTemp(dir, "master-serve-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSealedMasterServesLocalCatalog$", "-test.count=1")
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var exitErr error
	go func() { exitErr = cmd.Wait(); close(done) }()
	defer func() { _ = cmd.Process.Kill(); <-done }()
	deadline := time.Now().Add(15 * time.Second)
	for {
		raw, _ := os.ReadFile(log.Name())
		if bytes.Contains(raw, []byte("FrontierCloud Go runtime started")) {
			if !bytes.Contains(raw, []byte("sealed S3 control installed; provider probes remain required")) {
				t.Fatalf("fresh Master did not install authenticated S3 control\n%s", raw)
			}
			break
		}
		select {
		case <-done:
			t.Fatalf("Master exited before listening: %v\n%s", exitErr, raw)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("Master did not listen\n%s", raw)
		}
		time.Sleep(25 * time.Millisecond)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/api/v1/media/catalog/categories?media_type=music", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "master.test"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "192.0.2.42")
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !json.Valid(body) {
		t.Fatalf("local encrypted catalog: %d %s %v", response.StatusCode, body, err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if exitErr != nil {
			t.Fatal(exitErr)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("Master did not stop after SIGTERM")
	}
	// The bootstrap listener and authenticated Owner/tree state must also be
	// reusable by the same binary after a clean process exit.
	secondLog, err := os.CreateTemp(dir, "master-restart-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer secondLog.Close()
	second := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSealedMasterServesLocalCatalog$", "-test.count=1")
	second.Stdout, second.Stderr = secondLog, secondLog
	if err = second.Start(); err != nil {
		t.Fatal(err)
	}
	secondDone := make(chan struct{})
	var secondErr error
	go func() { secondErr = second.Wait(); close(secondDone) }()
	defer func() { _ = second.Process.Kill(); <-secondDone }()
	restartDeadline := time.Now().Add(15 * time.Second)
	for {
		raw, _ := os.ReadFile(secondLog.Name())
		if bytes.Contains(raw, []byte("FrontierCloud Go runtime started")) {
			if !bytes.Contains(raw, []byte("sealed S3 control installed; provider probes remain required")) {
				t.Fatalf("restarted Master did not reopen S3 control\n%s", raw)
			}
			break
		}
		select {
		case <-secondDone:
			t.Fatalf("Master restart failed: %v\n%s", secondErr, raw)
		default:
		}
		if time.Now().After(restartDeadline) {
			t.Fatalf("Master restart did not listen\n%s", raw)
		}
		time.Sleep(25 * time.Millisecond)
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/api/v1/media/catalog/categories?media_type=music", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "master.test"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "192.0.2.42")
	response, err = (&http.Client{Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !json.Valid(body) {
		t.Fatalf("restarted catalog: %d %s %v", response.StatusCode, body, err)
	}
	if err = second.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondDone:
		if secondErr != nil {
			t.Fatal(secondErr)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("restarted Master did not stop")
	}
	// A missing control or failed authenticated journal audit must not expose
	// S3 or disable the native catalog.
	checkS3Unavailable := func(reason string) {
		t.Helper()
		log, e := os.CreateTemp(dir, "master-s3-unavailable-*.log")
		if e != nil {
			t.Fatal(e)
		}
		defer log.Close()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSealedMasterServesLocalCatalog$", "-test.count=1")
		cmd.Stdout, cmd.Stderr = log, log
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		done := make(chan struct{})
		var exitErr error
		go func() { exitErr = cmd.Wait(); close(done) }()
		defer func() { _ = cmd.Process.Kill(); <-done }()
		deadline := time.Now().Add(15 * time.Second)
		for {
			raw, _ := os.ReadFile(log.Name())
			if bytes.Contains(raw, []byte("FrontierCloud Go runtime started")) {
				if !bytes.Contains(raw, []byte("sealed S3 unavailable")) || !bytes.Contains(raw, []byte(reason)) || bytes.Contains(raw, []byte("sealed S3 control installed")) {
					t.Fatalf("S3 %s did not fail closed\n%s", reason, raw)
				}
				break
			}
			select {
			case <-done:
				t.Fatalf("Master with S3 %s exited: %v\n%s", reason, exitErr, raw)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("Master with S3 %s did not listen\n%s", reason, raw)
			}
			time.Sleep(25 * time.Millisecond)
		}
		r, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/api/v1/media/catalog/categories?media_type=music", nil)
		if e != nil {
			t.Fatal(e)
		}
		r.Host = "master.test"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Real-IP", "192.0.2.42")
		response, e := (&http.Client{Timeout: 3 * time.Second}).Do(r)
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if e != nil || response.StatusCode != http.StatusOK || !json.Valid(body) {
			t.Fatalf("native catalog with S3 %s: %d %s %v", reason, response.StatusCode, body, e)
		}
		if e = cmd.Process.Signal(syscall.SIGTERM); e != nil {
			t.Fatal(e)
		}
		select {
		case <-done:
			if exitErr != nil {
				t.Fatal(exitErr)
			}
		case <-time.After(12 * time.Second):
			t.Fatal("Master with S3 unavailable did not stop")
		}
	}
	controlDir := filepath.Join(data, ".selected-s3-control")
	savedControl := controlDir + ".fixture-saved"
	if err = os.Rename(controlDir, savedControl); err != nil {
		t.Fatal(err)
	}
	checkS3Unavailable("control_unavailable")
	if err = os.Rename(savedControl, controlDir); err != nil {
		t.Fatal(err)
	}
	// An unauthenticated persistent journal is never treated as empty, even
	// though the same database continues serving native encrypted media.
	journalDB, err := sqlitestore.OpenExisting(ctx, c.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	badIndex := strings.Repeat("f", 64)
	_, insertErr := journalDB.Database().ExecContext(ctx, `INSERT INTO selected_upload_intents(operation_index,upload_index,member_index,parent_index,blob_index,encryption_id,sealed) VALUES(?,?,?,?,?,?,?)`, badIndex, badIndex, badIndex, badIndex, badIndex, badIndex, []byte{1})
	if err = errors.Join(insertErr, journalDB.Close()); err != nil {
		t.Fatal(err)
	}
	checkS3Unavailable("audit_failed")
	journalDB, err = sqlitestore.OpenExisting(ctx, c.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	_, deleteErr := journalDB.Database().ExecContext(ctx, `DELETE FROM selected_upload_intents WHERE operation_index=?`, badIndex)
	if err = errors.Join(deleteErr, journalDB.Close()); err != nil {
		t.Fatal(err)
	}
	// A persisted peer without its paired relationship is never rewritten to
	// Master or admitted by the bootstrap path. This is a synthetic database.
	brokenDB, err := sqlitestore.OpenExisting(ctx, c.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	peerID := strings.Repeat("a", 32)
	if peerID == identity.ID {
		peerID = strings.Repeat("b", 32)
	}
	if _, err = brokenDB.Database().ExecContext(ctx, `UPDATE public_ingress_config SET node_id=?,public_origin=?,peer_binding=? WHERE singleton=1`, peerID, "https://candidate.test", strings.Repeat("c", 64)); err != nil {
		brokenDB.Close()
		t.Fatal(err)
	}
	if err = brokenDB.Close(); err != nil {
		t.Fatal(err)
	}
	// The existing Master TLS name can remain the management origin while
	// a different, persisted peer TLS origin is unavailable.
	t.Setenv("ADMIN_ORIGIN", "https://master.test")
	thirdLog, err := os.CreateTemp(dir, "master-recovery-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer thirdLog.Close()
	third := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSealedMasterServesLocalCatalog$", "-test.count=1")
	third.Stdout, third.Stderr = thirdLog, thirdLog
	if err = third.Start(); err != nil {
		t.Fatal(err)
	}
	thirdDone := make(chan struct{})
	var thirdErr error
	go func() { thirdErr = third.Wait(); close(thirdDone) }()
	defer func() { _ = third.Process.Kill(); <-thirdDone }()
	recoveryDeadline := time.Now().Add(15 * time.Second)
	for {
		raw, _ := os.ReadFile(thirdLog.Name())
		if bytes.Contains(raw, []byte("FrontierCloud ingress recovery only")) {
			break
		}
		select {
		case <-thirdDone:
			t.Fatalf("recovery runtime exited: %v\n%s", thirdErr, raw)
		default:
		}
		if time.Now().After(recoveryDeadline) {
			t.Fatalf("recovery runtime did not listen\n%s", raw)
		}
		time.Sleep(25 * time.Millisecond)
	}
	recoveryRequest := func(host, path string) *http.Response {
		r, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		r.Host = host
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Real-IP", "192.0.2.42")
		response, e := (&http.Client{Timeout: 3 * time.Second}).Do(r)
		if e != nil {
			t.Fatal(e)
		}
		return response
	}
	response = recoveryRequest("master.test", "/api/v1/media/catalog/categories?media_type=music")
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("unavailable peer exposed public catalog", response.StatusCode)
	}
	response = recoveryRequest("candidate.test", "/api/v1/media/admin/ingress-recovery")
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("unavailable peer origin exposed Master recovery", response.StatusCode)
	}
	response = recoveryRequest("master.test", "/api/v1/media/admin/ingress-recovery")
	page, e := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if e != nil || response.StatusCode != http.StatusOK || !bytes.Contains(page, []byte("入口恢复")) {
		t.Fatal("recovery page", response.StatusCode, e)
	}
	response = recoveryRequest("master.test", "/api/v1/media/admin/ingress-recovery/state")
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("unauthenticated recovery state", response.StatusCode)
	}
	restored := os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL") != ""
	if restored {
		key, e := os.ReadFile(filepath.Join(secrets, "admin_key"))
		if e != nil {
			t.Fatal(e)
		}
		request := func(method, path, body, contentType string, cookies []*http.Cookie, csrf string) *http.Response {
			r, err := http.NewRequestWithContext(ctx, method, "http://"+address+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "master.test"
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Real-IP", "192.0.2.42")
			r.Header.Set("Origin", "https://master.test")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			if contentType != "" {
				r.Header.Set("Content-Type", contentType)
			}
			if csrf != "" {
				r.Header.Set("X-CSRF-Token", csrf)
			}
			for _, cookie := range cookies {
				r.AddCookie(cookie)
			}
			result, err := (&http.Client{Timeout: 12 * time.Second}).Do(r)
			if err != nil {
				t.Fatal(err)
			}
			return result
		}
		login := request("POST", "/api/v1/media/admin/elevate", url.Values{"token": {strings.TrimSpace(string(key))}}.Encode(), "application/x-www-form-urlencoded", nil, "")
		cookies := login.Cookies()
		login.Body.Close()
		if login.StatusCode != http.StatusOK {
			t.Fatal("real Admin login", login.StatusCode)
		}
		csrf := ""
		for _, cookie := range cookies {
			if cookie.Name == c.CSRFCookieName() {
				csrf = cookie.Value
			}
		}
		if csrf == "" {
			t.Fatal("missing CSRF cookie")
		}
		state := request("GET", "/api/v1/media/admin/ingress-recovery/state", "", "", cookies, "")
		var observed struct {
			MasterID string              `json:"master_id"`
			Ingress  store.PublicIngress `json:"ingress"`
		}
		e = json.NewDecoder(io.LimitReader(state.Body, 4096)).Decode(&observed)
		state.Body.Close()
		if e != nil || state.StatusCode != http.StatusOK || observed.MasterID != identity.ID || observed.Ingress.NodeID != peerID {
			t.Fatal("recovery state", state.StatusCode, e)
		}
		body := func(id string, generation int64) string {
			b, e := json.Marshal(map[string]any{"member_id": id, "generation": generation})
			if e != nil {
				t.Fatal(e)
			}
			return string(b)
		}
		for _, tc := range []struct {
			id         string
			generation int64
			csrf       string
			want       int
		}{
			{identity.ID, observed.Ingress.Generation, "", http.StatusForbidden},
			{peerID, observed.Ingress.Generation, csrf, http.StatusConflict},
			{identity.ID, observed.Ingress.Generation + 1, csrf, http.StatusConflict},
		} {
			r := request("POST", "/api/v1/media/admin/ingress-recovery/restore", body(tc.id, tc.generation), "application/json", cookies, tc.csrf)
			r.Body.Close()
			if r.StatusCode != tc.want {
				t.Fatal("recovery negative response", r.StatusCode, tc.want)
			}
		}
		r := request("POST", "/api/v1/media/admin/ingress-recovery/restore", body(identity.ID, observed.Ingress.Generation), "application/json", cookies, csrf)
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatal("recovery restore", r.StatusCode)
		}
		response = recoveryRequest("master.test", "/api/v1/media/catalog/categories?media_type=music")
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatal("catalog after recovery", response.StatusCode)
		}
		status := request("GET", "/api/v1/media/admin/status", "", "", cookies, "")
		var deletionStatus struct {
			Protocol  string `json:"media_delete_protocol"`
			Available bool   `json:"media_delete_available"`
		}
		e = json.NewDecoder(io.LimitReader(status.Body, 8192)).Decode(&deletionStatus)
		status.Body.Close()
		if e != nil || status.StatusCode != http.StatusOK || deletionStatus.Protocol != "sealed-v1" || !deletionStatus.Available {
			t.Fatal("normal Master startup did not install sealed deletion", status.StatusCode, e)
		}
	}
	if err = third.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-thirdDone:
		if thirdErr != nil {
			t.Fatal(thirdErr)
		}
	case <-time.After(12 * time.Second):
		_ = third.Process.Kill()
		<-thirdDone
		t.Fatal("recovery runtime did not stop")
	}
	brokenDB, err = sqlitestore.OpenExisting(ctx, c.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	var preservedID, preservedOrigin string
	err = brokenDB.Database().QueryRowContext(ctx, `SELECT node_id,public_origin FROM public_ingress_config WHERE singleton=1`).Scan(&preservedID, &preservedOrigin)
	brokenDB.Close()
	wantID, wantOrigin := peerID, "https://candidate.test"
	if restored {
		wantID, wantOrigin = identity.ID, "https://master.test"
	}
	if err != nil || preservedID != wantID || preservedOrigin != wantOrigin {
		t.Fatal("failed startup changed selected ingress", err)
	}
	if restored {
		// The restored selection must survive a new OS process; no in-memory
		// recovery state may be required for normal Local serving.
		log, err := os.CreateTemp(dir, "master-restored-*.log")
		if err != nil {
			t.Fatal(err)
		}
		defer log.Close()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSealedMasterServesLocalCatalog$", "-test.count=1")
		cmd.Stdout, cmd.Stderr = log, log
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		var exitErr error
		go func() { exitErr = cmd.Wait(); close(done) }()
		defer func() { _ = cmd.Process.Kill(); <-done }()
		deadline := time.Now().Add(15 * time.Second)
		for {
			raw, _ := os.ReadFile(log.Name())
			if bytes.Contains(raw, []byte("FrontierCloud Go runtime started")) {
				break
			}
			select {
			case <-done:
				t.Fatalf("restored Master exited: %v\n%s", exitErr, raw)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("restored Master did not start\n%s", raw)
			}
			time.Sleep(25 * time.Millisecond)
		}
		response = recoveryRequest("master.test", "/api/v1/media/catalog/categories?media_type=music")
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatal("catalog after restored restart", response.StatusCode)
		}
		if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
			if exitErr != nil {
				t.Fatal(exitErr)
			}
		case <-time.After(12 * time.Second):
			t.Fatal("restored Master did not stop")
		}
	}
}
