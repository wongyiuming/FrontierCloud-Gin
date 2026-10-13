package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failResultWriter struct {
	successful int
	writes     int
}

func (w *failResultWriter) Write(data []byte) (int, error) {
	w.writes++
	if w.writes > w.successful {
		return 0, errors.New("private destination failure")
	}
	return len(data), nil
}

type shortResultWriter struct{}

func (shortResultWriter) Write(data []byte) (int, error) { return len(data) / 2, nil }

func TestNodeResultShortWriteReturnsNonzero(t *testing.T) {
	output := &resultWriter{writer: shortResultWriter{}}
	if _, e := output.Write([]byte("task revision 2")); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal(e)
	}
	code := 0
	var diagnostic bytes.Buffer
	output.finish(&code, &diagnostic)
	if code != 2 || diagnostic.Len() == 0 {
		t.Fatal("short report delivery acknowledged", code)
	}
}

func TestMigrationControlOutputFailureIsNonzeroAfterRemoteMutation(t *testing.T) {
	master, source, target, id := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32), strings.Repeat("4", 32)
	mutations := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := strings.TrimPrefix(r.URL.Path, "/api/v1/media/admin")
		switch route {
		case "/elevate":
			http.SetCookie(w, &http.Cookie{Name: "fixture_session", Value: "session", Path: "/", Secure: true})
			http.SetCookie(w, &http.Cookie{Name: "fixture_csrf", Value: "csrf", Path: "/", Secure: true})
			io.WriteString(w, `{"status":"ok"}`)
		case "/status":
			io.WriteString(w, `{"session":true,"csrf_cookie_name":"fixture_csrf"}`)
		case "/nodes":
			json.NewEncoder(w).Encode(map[string]string{"role": "Master", "node_id": master})
		case "/nodes/migrations/" + id + "/control", "/nodes/migrations/" + id + "/release-drain":
			if r.Method != "POST" || r.Header.Get("X-CSRF-Token") != "csrf" {
				t.Error("authenticated control contract changed")
				w.WriteHeader(403)
				return
			}
			mutations++
			json.NewEncoder(w).Encode(store.MigrationTask{ID: id, MasterID: master, SourceID: source, TargetID: target, PlanSHA: strings.Repeat("5", 64), Revision: 2, State: "completed"})
		case "/logout":
			io.WriteString(w, `{"status":"ok"}`)
		default:
			t.Error("unexpected route", route)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"pause", "resume", "cancel", "retry", "release-drain"} {
		for _, structured := range []bool{false, true} {
			for _, successful := range []int{0, 1} {
				if structured && successful == 1 {
					continue
				}
				args := []string{"node", "migrate", action, id, "--master", server.URL, "--ca-file", ca, "--credential-stdin", "--task-revision", "1", "--confirm-source-id", source, "--confirm-target-id", target}
				output := &failResultWriter{successful: successful}
				var diagnostic bytes.Buffer
				before := mutations
				code := migrationCommand(context.Background(), args, structured, strings.NewReader("isolated-fixture-credential\n"), output, &diagnostic)
				if code != 2 || mutations != before+1 || diagnostic.Len() == 0 || strings.Contains(diagnostic.String(), "private destination") {
					t.Fatal("remote result loss reported success", action, structured, successful, code, mutations-before, diagnostic.String())
				}
			}
		}
	}
}
