package certificate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Explicit development-only volume acceptance; never executed in hosted CI.
func TestCertificateContainerSharedVolumes(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_CERTIFICATE_VOLUMES") != "1" {
		t.Skip("requires isolated certificate Compose volumes")
	}
	if os.Geteuid() != 0 || os.Getegid() != 10001 {
		t.Fatal("fixture requires exact certificate container identity")
	}
	dir, public := "/var/lib/frontiercloud-certificate", "/run/frontiercloud-http01"
	cert, key := testPair(t, "storage.fixture.test", 90)
	server := httptest.NewServer(http.FileServer(http.Dir(public)))
	defer server.Close()
	issuer := func(ctx context.Context, present func(string, string) (func(), error)) ([]byte, []byte, error) {
		closeFn, e := present("container_fixture_token", "container_public_proof")
		if e != nil {
			return nil, nil, e
		}
		defer closeFn()
		request, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/container_fixture_token", nil)
		response, e := server.Client().Do(request)
		if e != nil {
			return nil, nil, e
		}
		defer response.Body.Close()
		b, e := io.ReadAll(response.Body)
		if e != nil || string(b) != "container_public_proof" {
			return nil, nil, errors.New("public proof unavailable")
		}
		return cert, key, nil
	}
	a, e := OpenContainer(context.Background(), "storage.fixture.test", dir, port(t), issuer)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	if e = a.UseHTTP01Directory(public); e != nil {
		t.Fatal(e)
	}
	if _, e = accountKey(dir); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Start(); e != nil {
		t.Fatal(e)
	}
	if v := waitJob(t, a); v.Job.State != "success" || v.State != "valid" || v.Validation != "shared_http01" {
		t.Fatal(v)
	}
	if _, e = a.SetAutoRenew(true); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(public, "container_fixture_token")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("public proof retained")
	}
	p, e := manifest(dir)
	if e != nil {
		t.Fatal(e)
	}
	for path, mode := range map[string]os.FileMode{"account.key": 0600, "state.json": 0600, "current.json": 0640, p.Generation: 0750, filepath.Join(p.Generation, "privkey.pem"): 0640} {
		info, e := os.Stat(filepath.Join(dir, path))
		if e != nil || info.Mode().Perm() != mode {
			t.Fatal(path, e)
		}
	}
	t.Log("real container volume issuance, cleanup, private account, group TLS and durable policy passed")
}

func TestCertificateContainerLocalExpiredRenewal(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_CERTIFICATE_VOLUMES") != "1" {
		t.Skip("requires isolated certificate Compose volumes and runtime CLI")
	}
	cert, key := testPair(t, "storage.fixture.test", 90)
	issued := make(chan struct{}, 1)
	a, e := OpenContainer(context.Background(), "storage.fixture.test", "/var/lib/frontiercloud-certificate", port(t), func(context.Context, func(string, string) (func(), error)) ([]byte, []byte, error) {
		issued <- struct{}{}
		return cert, key, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.SetAutoRenew(false); e != nil {
		t.Fatal(e)
	}
	if e = a.publish(cert, key); e != nil {
		t.Fatal(e)
	}
	// Seed an expired fixture generation; production recovery never edits TLS state.
	pair, e := manifest(a.directory)
	if e != nil {
		t.Fatal(e)
	}
	expiredCert, expiredKey := testPair(t, a.host, -1)
	for name, data := range map[string][]byte{"fullchain.pem": expiredCert, "privkey.pem": expiredKey} {
		if e = os.WriteFile(filepath.Join(a.directory, pair.Generation, name), data, 0640); e != nil {
			t.Fatal(e)
		}
	}
	a.state.Job.StartedAt = time.Now().Add(-2 * time.Hour).Unix()
	if e = a.save(); e != nil {
		t.Fatal(e)
	}
	if a.Status().State != "expired" {
		t.Fatal("fixture is not expired")
	}
	if _, e = NewTLS(a.host, a.directory, "/unused/bootstrap.pem", "/unused/bootstrap.key"); e == nil {
		t.Fatal("expired managed TLS did not fail closed")
	}
	done := make(chan error, 1)
	go func() { done <- a.Serve("/run/frontiercloud-certificate/control.sock") }()
	defer func() {
		a.Close()
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	client := UnixClient{Socket: "/run/frontiercloud-certificate/control.sock", Hostname: a.host}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for {
		if _, e = client.Control(ctx, Request{Action: "status"}); e == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(e)
		}
		time.Sleep(time.Millisecond)
	}
	command := exec.CommandContext(ctx, "/app/frontiercloud", "certificate-renew")
	command.Env = append(os.Environ(), "SERVER_NAME="+a.host)
	output, e := command.Output()
	if e != nil {
		t.Fatal("container local renewal failed", e)
	}
	var view View
	if json.Unmarshal(output, &view) != nil || view.Hostname != a.host {
		t.Fatal("local renewal response mismatch")
	}
	select {
	case <-issued:
	case <-ctx.Done():
		t.Fatal("local command queried status instead of submitting renewal")
	}
	if view = waitJob(t, a); view.Job.State != "success" || view.State != "valid" {
		t.Fatal(view)
	}
	if _, e = NewTLS(a.host, a.directory, "/unused/bootstrap.pem", "/unused/bootstrap.key"); e != nil {
		t.Fatal("recovered managed TLS remains unavailable", e)
	}
	if _, e = a.SetAutoRenew(true); e != nil {
		t.Fatal(e)
	}
	t.Log("expired managed certificate recovered through actual container CLI and private socket without HTTPS or volume edits")
}

func TestCertificateContainerTemporaryPort80(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_CERTIFICATE_PORT80") != "1" {
		t.Skip("requires explicit isolated development host-network fixture")
	}
	if os.Geteuid() != 0 || os.Getegid() != 10001 {
		t.Fatal("unexpected container identity")
	}
	for _, outcome := range []string{"success", "failed", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			entered, proceed := make(chan struct{}), make(chan struct{})
			cert, key := testPair(t, "storage.fixture.test", 90)
			state := t.TempDir()
			if e := os.Chmod(state, 0750); e != nil {
				t.Fatal(e)
			}
			a, e := OpenContainer(context.Background(), "storage.fixture.test", state, ":80", func(ctx context.Context, present func(string, string) (func(), error)) ([]byte, []byte, error) {
				closeFn, e := present("container_temporary_token", "temporary_proof")
				if e != nil {
					return nil, nil, e
				}
				defer closeFn()
				close(entered)
				select {
				case <-proceed:
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
				if outcome == "failed" {
					return nil, nil, errors.New("fixture CA refused")
				}
				return cert, key, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			other, e := net.Listen("tcp", ":80")
			if e != nil {
				t.Fatal("development port 80 is occupied", e)
			}
			if _, e = a.present(context.Background(), "collision", "proof"); !errors.Is(e, errPortBusy) {
				other.Close()
				t.Fatal("did not preserve existing port owner", e)
			}
			other.Close()
			if _, e = a.Start(); e != nil {
				t.Fatal(e)
			}
			select {
			case <-entered:
			case <-a.ctx.Done():
				t.Fatal("fixture cancelled")
			case <-time.After(3 * time.Second):
				t.Fatal("temporary challenge did not start")
			}
			request, _ := http.NewRequest("GET", "http://127.0.0.1/.well-known/acme-challenge/container_temporary_token", nil)
			request.Host = "storage.fixture.test"
			client := &http.Client{Timeout: time.Second}
			response, e := client.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(response.Body)
			response.Body.Close()
			if e != nil || string(b) != "temporary_proof" || !a.Status().Job.Port80Active {
				t.Fatal("temporary proof absent", e)
			}
			if outcome == "cancelled" {
				a.Close()
			} else {
				close(proceed)
				waitJob(t, a)
			}
			released, e := net.Listen("tcp", ":80")
			if e != nil {
				t.Fatal("temporary host port remained owned", e)
			}
			released.Close()
		})
	}
}
